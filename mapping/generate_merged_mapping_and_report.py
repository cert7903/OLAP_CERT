"""
generate_merged_mapping_and_report.py
-------------------------------------
MITRE ATT&CK ↔ CAPEC 매핑 (STIX + Semantic + User CSV 병합)
"""

import os
import json
import zipfile
import tempfile
import requests
import pandas as pd
from tqdm import tqdm
from sentence_transformers import SentenceTransformer, util

CTI_URL = "https://github.com/mitre/cti/archive/refs/heads/master.zip"
LOCAL_CTI_DIR = os.path.join(tempfile.gettempdir(), "mitre_cti_data")
OUTPUT_FILE = "mapping/merged_mapping_report.csv"
USER_CSV = "mapping/user_scenario_mapping.csv"  # 사용자 시나리오 매핑 테이블
SEMANTIC_MAPPING_CSV = "mapping/full_attack_capec_mapping_semantic.csv"


# ---------------------------------------------------------------------
# 1️⃣ 다운로드 및 로드
# ---------------------------------------------------------------------
def download_cti_repo():
    os.makedirs(LOCAL_CTI_DIR, exist_ok=True)
    zip_path = os.path.join(LOCAL_CTI_DIR, "cti_master.zip")

    if not os.path.exists(zip_path):
        print("[+] Downloading CTI master zip...")
        r = requests.get(CTI_URL)
        r.raise_for_status()
        with open(zip_path, "wb") as f:
            f.write(r.content)

    extract_dir = os.path.join(LOCAL_CTI_DIR, "cti_master")
    if not os.path.exists(extract_dir):
        print(f"[+] Extracting to {extract_dir} ...")
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(LOCAL_CTI_DIR)

    return extract_dir


# ---------------------------------------------------------------------
# 2️⃣ MITRE ATT&CK 데이터 파싱
# ---------------------------------------------------------------------
def parse_attack_techniques(cti_root):
    attack_dir = os.path.join(cti_root, "cti-master", "enterprise-attack")
    all_json_files = []
    for root, _, files in os.walk(attack_dir):
        for f in files:
            if f.endswith(".json"):
                all_json_files.append(os.path.join(root, f))

    techniques = {}
    print(f"[+] Scanning {len(all_json_files)} ATT&CK JSON files...")
    for file in tqdm(all_json_files):
        try:
            data = json.load(open(file, encoding="utf-8"))
        except Exception:
            continue
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                tid = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tid = ref.get("external_id")
                        break
                if tid:
                    techniques[tid] = {
                        "id": tid,
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                    }
    print(f"[+] Parsed {len(techniques)} ATT&CK techniques.")
    return techniques


# ---------------------------------------------------------------------
# 3️⃣ CAPEC 데이터 로드
# ---------------------------------------------------------------------
def load_capec_data():
    print("[+] Fetching CAPEC JSON ...")
    CAPEC_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/attack-pattern/attack-pattern--a.json"
    try:
        r = requests.get(CAPEC_URL)
        r.raise_for_status()
        capec_data = json.loads(r.text)
    except Exception as e:
        print(f"[!] Could not fetch CAPEC JSON: {e}")
        capec_data = {"objects": []}
    return capec_data


def parse_capec_objects(capec_data):
    capecs = {}
    for obj in capec_data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            cid = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "capec":
                    cid = ref.get("external_id")
                    break
            if cid:
                capecs[cid] = {
                    "id": cid,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                }
    print(f"[+] Parsed {len(capecs)} CAPEC entries.")
    return capecs


# ---------------------------------------------------------------------
# 4️⃣ Semantic Matching (SBERT)
# ---------------------------------------------------------------------
def compute_semantic_similarity(attack_dict, capec_dict, threshold=0.6):
    print("[+] Using Sentence-BERT for embeddings (fast & accurate).")
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

    attack_texts = [f"{v['name']} {v['description']}" for v in attack_dict.values()]
    capec_texts = [f"{v['name']} {v['description']}" for v in capec_dict.values()]

    attack_emb = model.encode(attack_texts, convert_to_tensor=True, show_progress_bar=True)
    capec_emb = model.encode(capec_texts, convert_to_tensor=True, show_progress_bar=True)

    sim_matrix = util.cos_sim(attack_emb, capec_emb)

    results = []
    for i, a in enumerate(attack_dict.values()):
        best_idx = int(sim_matrix[i].argmax())
        best_sim = float(sim_matrix[i][best_idx])
        if best_sim >= threshold:
            c = list(capec_dict.values())[best_idx]
            results.append(
                {
                    "ATTACK_ID": a["id"],
                    "ATTACK_NAME": a["name"],
                    "CAPEC_ID": c["id"],
                    "CAPEC_NAME": c["name"],
                    "SIMILARITY": round(best_sim, 4),
                }
            )
    print(f"[+] Found {len(results)} semantic mappings (similarity ≥ {threshold}).")
    return pd.DataFrame(results)


# ---------------------------------------------------------------------
# 5️⃣ 사용자 정의 시나리오 CSV 로드 (UTF-8/CP949 자동 감지)
# ---------------------------------------------------------------------
def load_user_mapping(path):
    print(f"[+] Loading user scenario mapping from {path}")
    try:
        df = pd.read_csv(path, dtype=str).fillna("")
    except UnicodeDecodeError:
        print("[!] UTF-8 디코딩 실패 — CP949 인코딩으로 재시도합니다.")
        df = pd.read_csv(path, dtype=str, encoding="cp949").fillna("")
    print(f"[+] Loaded {len(df)} rows from user mapping CSV.")
    return df


# ---------------------------------------------------------------------
# 6️⃣ 병합 처리
# ---------------------------------------------------------------------
def merge_mappings(user_df, semantic_df):
    merged_rows = []
    for _, row in user_df.iterrows():
        tid = str(row.get("MITRE ATT&CK TID", "")).strip()
        scenario = row.get("시나리오명", "")
        desc = row.get("비고(설명)", "")
        대응방안 = row.get("대응방안", "")
        src = semantic_df[semantic_df["ATTACK_ID"] == tid]
        if not src.empty:
            best = src.iloc[0]
            merged_rows.append(
                {
                    "시나리오명": scenario,
                    "ATTACK_ID": tid,
                    "ATTACK_NAME": best["ATTACK_NAME"],
                    "CAPEC_ID": best["CAPEC_ID"],
                    "CAPEC_NAME": best["CAPEC_NAME"],
                    "SIMILARITY": best["SIMILARITY"],
                    "비고(설명)": desc,
                    "대응방안": 대응방안,
                }
            )
        else:
            merged_rows.append(
                {
                    "시나리오명": scenario,
                    "ATTACK_ID": tid,
                    "ATTACK_NAME": "",
                    "CAPEC_ID": "",
                    "CAPEC_NAME": "",
                    "SIMILARITY": "",
                    "비고(설명)": desc,
                    "대응방안": 대응방안,
                }
            )
    return pd.DataFrame(merged_rows)


# ---------------------------------------------------------------------
# 7️⃣ 실행 진입점
# ---------------------------------------------------------------------
def main():
    cti_root = download_cti_repo()
    attacks = parse_attack_techniques(cti_root)
    capec_json = load_capec_data()
    capecs = parse_capec_objects(capec_json)

    if os.path.exists(SEMANTIC_MAPPING_CSV):
        print(f"[+] Loading existing semantic mapping from {SEMANTIC_MAPPING_CSV}")
        semantic_df = pd.read_csv(SEMANTIC_MAPPING_CSV)
    else:
        semantic_df = compute_semantic_similarity(attacks, capecs, threshold=0.6)
        os.makedirs("mapping", exist_ok=True)
        semantic_df.to_csv(SEMANTIC_MAPPING_CSV, index=False, encoding="utf-8-sig")

    user_df = load_user_mapping(USER_CSV)
    merged_df = merge_mappings(user_df, semantic_df)

    os.makedirs("mapping", exist_ok=True)
    merged_df.to_csv(OUTPUT_FILE, index=False, encoding="utf-8-sig")
    print(f"[+] Final merged mapping saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
