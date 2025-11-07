#!/usr/bin/env python3
"""
generate_full_attack_capec_mapping.py
-------------------------------------
Semantic-based ATT&CK <-> CAPEC mapping using Sentence-BERT embeddings.

Output:
  mapping/full_attack_capec_mapping_semantic.csv
Columns:
  ATTACK_ID, ATTACK_NAME, CAPEC_ID, CAPEC_NAME, SIMILARITY
"""

import os
import re
import json
import zipfile
import tempfile
import requests
from pathlib import Path
import pandas as pd
from sentence_transformers import SentenceTransformer, util

# ===== 설정 =====
CTI_ZIP_URL = "https://github.com/mitre/cti/archive/refs/heads/master.zip"
MODEL_NAME = "all-MiniLM-L6-v2"
SIM_THRESHOLD = 0.65
OUT_DIR = Path("mapping")
OUT_FILE = OUT_DIR / "full_attack_capec_mapping_semantic.csv"

# ===== 유틸 =====
def strip_html(text):
    return re.sub(r"<.*?>", "", str(text or "")).replace("\n", " ").strip()

def download_cti_repo(tmpdir: Path) -> Path:
    print("[+] Downloading MITRE CTI repository ...")
    zip_path = tmpdir / "cti_master.zip"
    with requests.get(CTI_ZIP_URL, stream=True, timeout=60) as r:
        r.raise_for_status()
        with open(zip_path, "wb") as f:
            for chunk in r.iter_content(8192):
                f.write(chunk)
    print("[+] Extracting CTI repo ...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(tmpdir)
    for p in tmpdir.iterdir():
        if p.is_dir() and "cti-" in p.name:
            return p
    return tmpdir

def load_json(path: Path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

# ===== 데이터 수집 =====
def collect_attack(repo_root: Path):
    attack_dir = repo_root / "enterprise-attack" / "attack-pattern"
    attacks = []
    print("[+] Collecting ATT&CK attack patterns ...")
    for p in attack_dir.rglob("*.json"):
        j = load_json(p)
        if not j: continue
        for obj in j.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id")
                    attacks.append({
                        "id": tid,
                        "name": obj.get("name", ""),
                        "desc": strip_html(obj.get("description", ""))
                    })
    print(f"[+] ATT&CK count: {len(attacks)}")
    return attacks

def collect_capec(repo_root: Path):
    capec_dir = repo_root / "capec" / "2.1" / "attack-pattern"
    capecs = []
    print("[+] Collecting CAPEC patterns ...")
    for p in capec_dir.rglob("*.json"):
        j = load_json(p)
        if not j: continue
        for obj in j.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            for ref in obj.get("external_references", []):
                if "capec" in ref.get("source_name", "").lower():
                    cid = ref.get("external_id")
                    capecs.append({
                        "id": cid,
                        "name": obj.get("name", ""),
                        "desc": strip_html(obj.get("description", ""))
                    })
    print(f"[+] CAPEC count: {len(capecs)}")
    return capecs

# ===== 메인 =====
def main():
    OUT_DIR.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mitre_cti_") as tmp:
        repo = download_cti_repo(Path(tmp))
        attacks = collect_attack(repo)
        capecs = collect_capec(repo)

    print("[+] Loading SBERT model ...")
    model = SentenceTransformer(MODEL_NAME)

    print("[+] Encoding ATT&CK & CAPEC descriptions ...")
    attack_emb = model.encode([a["desc"] for a in attacks], convert_to_tensor=True, show_progress_bar=True)
    capec_emb = model.encode([c["desc"] for c in capecs], convert_to_tensor=True, show_progress_bar=True)

    print("[+] Calculating semantic similarities ...")
    sim_matrix = util.cos_sim(attack_emb, capec_emb)

    results = []
    for i, attack in enumerate(attacks):
        sims = sim_matrix[i].cpu().tolist()
        best_idx = int(max(range(len(sims)), key=lambda j: sims[j]))
        best_sim = sims[best_idx]
        if best_sim >= SIM_THRESHOLD:
            capec = capecs[best_idx]
            results.append({
                "ATTACK_ID": attack["id"],
                "ATTACK_NAME": attack["name"],
                "CAPEC_ID": capec["id"],
                "CAPEC_NAME": capec["name"],
                "SIMILARITY": round(best_sim, 4)
            })

    df = pd.DataFrame(results)
    df.sort_values(by="SIMILARITY", ascending=False, inplace=True)
    df.to_csv(OUT_FILE, index=False, encoding="utf-8-sig")

    print(f"[+] Done! {len(df)} semantic mappings saved to {OUT_FILE}")

if __name__ == "__main__":
    main()
