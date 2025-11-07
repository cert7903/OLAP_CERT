#!/usr/bin/env python3
"""
generate_merged_mapping_and_report.py

- Merge user's mapping table (mapping/user_mapping.csv) with full ATT&CK<->CAPEC mapping
  (generated from MITRE CTI repository, semantic matching).
- Produce combined CSV and a textual analysis report.

Outputs:
 - mapping/full_attack_capec_mapping_semantic.csv   (generated or reused)
 - mapping/combined_attack_capec_mapping.csv       (final merged output)
 - mapping/merge_report.txt                        (analysis)
"""

import os, re, sys, json, zipfile, tempfile, requests
from pathlib import Path
from typing import Dict, Any, List, Tuple
import pandas as pd
import numpy as np

# optional imports
try:
    from sentence_transformers import SentenceTransformer, util
    USE_SBERT = True
except Exception:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    USE_SBERT = False

# ================== Configuration ==================
CTI_ZIP_URL = "https://github.com/mitre/cti/archive/refs/heads/master.zip"
WORK_DIR = Path("mapping")
WORK_DIR.mkdir(exist_ok=True)
USER_CSV = WORK_DIR / "user_mapping.csv"   # <-- 사용자 매핑 파일 (CSV)
EXPLICIT_CSV = WORK_DIR / "full_attack_capec_mapping.csv"           # optional explicit
SEMANTIC_CSV = WORK_DIR / "full_attack_capec_mapping_semantic.csv"  # generated semantic
COMBINED_CSV = WORK_DIR / "combined_attack_capec_mapping.csv"
REPORT_FILE = WORK_DIR / "merge_report.txt"

# Parameters
SEMANTIC_SIM_THRESHOLD = 0.65
SEMANTIC_TOPK = 3
SBERT_MODEL = "all-MiniLM-L6-v2"
FILTER_CTI_DIRS = ["enterprise-attack", "capec"]  # speed-up: only scan these

# ================== Utilities ==================
def strip_html(s: str) -> str:
    if not s: return ""
    s = re.sub(r"<[^>]+>", " ", str(s))
    s = re.sub(r"\s+", " ", s).strip()
    return s

def download_and_extract_cti(tmpdir: Path) -> Path:
    print("[+] Downloading CTI master zip...")
    r = requests.get(CTI_ZIP_URL, stream=True, timeout=60)
    r.raise_for_status()
    zip_path = tmpdir / "cti_master.zip"
    with open(zip_path, "wb") as fh:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                fh.write(chunk)
    extract_dir = tmpdir / "cti_master"
    extract_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_dir)
    # return repo root
    for p in extract_dir.iterdir():
        if p.is_dir():
            return p
    return extract_dir

def load_json_safe(path: Path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        try:
            with open(path, "rb") as fh:
                return json.loads(fh.read().decode("utf-8", errors="ignore"))
        except Exception:
            return None

# ================== CTI parsing (ATT&CK & CAPEC from repo) ==================
def iter_json_files(repo_root: Path, filter_dirs: List[str] = None):
    for root, dirs, files in os.walk(repo_root):
        # optional directory filtering (only process relevant dirs)
        rel = os.path.relpath(root, repo_root)
        if filter_dirs:
            if rel == ".":
                pass
            else:
                if not any(rel.startswith(fd) for fd in filter_dirs):
                    continue
        for f in files:
            if f.lower().endswith(".json"):
                yield Path(root) / f

def collect_patterns_and_tactics(repo_root: Path):
    """
    Returns:
      attacks: dict ATTACK_ID -> {name, desc, uuid}
      capecs: dict CAPEC_ID -> {name, desc, uuid}
      technique_to_tactics: dict ATTACK_ID -> [tactic1, tactic2, ...]
    """
    attacks = {}
    capecs = {}
    tech_to_tactics = {}

    for jf in iter_json_files(repo_root, filter_dirs=FILTER_CTI_DIRS):
        j = load_json_safe(jf)
        if not j:
            continue
        objs = j.get("objects") if isinstance(j, dict) else None
        if objs is None:
            continue
        for obj in objs:
            if not isinstance(obj, dict):
                continue
            typ = obj.get("type")
            if typ != "attack-pattern":
                continue
            # find external refs
            external_refs = obj.get("external_references", []) or []
            ext_id = ""
            src_hint = ""
            for ref in external_refs:
                s = (ref.get("source_name") or "").lower()
                if "mitre-attack" in s and ref.get("external_id"):
                    ext_id = str(ref.get("external_id")).strip().upper()
                    src_hint = "mitre-attack"
                    break
                if "capec" in s and ref.get("external_id"):
                    ext_id = str(ref.get("external_id")).strip().upper()
                    src_hint = "capec"
                    # DO NOT break: prefer mitre-attack if present later
            name = obj.get("name","") or ""
            desc = strip_html(obj.get("description","") or "")
            uid = obj.get("id","")
            # store by ext_id if present, else by uid for capec repo patterns
            if ext_id and ext_id.upper().startswith("T"):
                attacks[ext_id] = {"attack_id": ext_id, "attack_name": name, "attack_desc": desc, "uuid": uid}
                # gather tactics (kill_chain_phases)
                phases = obj.get("kill_chain_phases", []) or []
                tactics = [p.get("phase_name") for p in phases if p.get("phase_name")]
                # also check x_mitre_tactic-like fields
                for k,v in obj.items():
                    if isinstance(k,str) and k.startswith("x_mitre") and "tactic" in k and v:
                        if isinstance(v, list):
                            tactics += [str(x) for x in v]
                        else:
                            tactics.append(str(v))
                tech_to_tactics[ext_id] = sorted(list(set(tactics)))
            elif ext_id and ext_id.upper().startswith("CAPEC"):
                capecs[ext_id] = {"capec_id": ext_id, "capec_name": name, "capec_desc": desc, "uuid": uid}
            else:
                # sometimes capec objects are present without external refs in this file; detect by folder path or name heuristics
                # We'll ignore these here.
                pass

    return attacks, capecs, tech_to_tactics

# ================== Semantic mapping (SBERT or TF-IDF fallback) ==================
def semantic_match(attacks: Dict[str,Any], capecs: Dict[str,Any], threshold=SEMANTIC_SIM_THRESHOLD, topk=SEMANTIC_TOPK):
    attack_list = list(attacks.values())
    capec_list = list(capecs.values())
    results = []

    attack_texts = [(a["attack_id"], (a["attack_name"] or "") + " " + (a["attack_desc"] or "")) for a in attack_list]
    capec_texts = [(c["capec_id"], (c["capec_name"] or "") + " " + (c["capec_desc"] or "")) for c in capec_list]

    if USE_SBERT:
        print("[+] Using SBERT for semantic matching.")
        model = SentenceTransformer(SBERT_MODEL)
        atk_emb = model.encode([t for _,t in attack_texts], convert_to_tensor=True, show_progress_bar=True)
        cap_emb = model.encode([t for _,t in capec_texts], convert_to_tensor=True, show_progress_bar=True)
        sims = util.cos_sim(atk_emb, cap_emb).cpu().numpy()
        for i,(aid,atext) in enumerate(attack_texts):
            # top-k capecs
            idxs = np.argsort(-sims[i])[:topk]
            for j in idxs:
                score = float(sims[i][j])
                if score >= threshold:
                    cid = capec_texts[j][0]
                    # lookup names
                    results.append({
                        "ATTACK_ID": aid,
                        "ATTACK_NAME": attacks.get(aid,{}).get("attack_name",""),
                        "CAPEC_ID": cid,
                        "CAPEC_NAME": capecs.get(cid,{}).get("capec_name",""),
                        "SIMILARITY": round(score,4),
                        "MATCH_METHOD": "sbert"
                    })
    else:
        print("[+] Using TF-IDF fallback for semantic matching.")
        corpus_attack = [t for _,t in attack_texts]
        corpus_capec = [t for _,t in capec_texts]
        vectorizer = TfidfVectorizer(max_df=0.9, min_df=1, ngram_range=(1,2))
        combined = corpus_attack + corpus_capec
        X = vectorizer.fit_transform(combined)
        A = X[:len(corpus_attack)]
        C = X[len(corpus_attack):]
        sims = cosine_similarity(A, C)
        for i,(aid,atext) in enumerate(attack_texts):
            row = sims[i]
            idxs = np.argsort(-row)[:topk]
            for j in idxs:
                score = float(row[j])
                if score >= threshold:
                    cid = capec_texts[j][0]
                    results.append({
                        "ATTACK_ID": aid,
                        "ATTACK_NAME": attacks.get(aid,{}).get("attack_name",""),
                        "CAPEC_ID": cid,
                        "CAPEC_NAME": capecs.get(cid,{}).get("capec_name",""),
                        "SIMILARITY": round(score,4),
                        "MATCH_METHOD": "tfidf"
                    })
    return pd.DataFrame(results)

# ================== User mapping loader & normalization ==================
def load_user_mapping(path: Path) -> pd.DataFrame:
    if not path.exists():
        print(f"[!] User mapping file not found at {path}. Please place your CSV there.")
        return pd.DataFrame(columns=["방화벽","시나리오명","MITRE ATT&CK TID","비고(설명)","대응방안"])
    df = pd.read_csv(path, dtype=str).fillna("")
    # normalize header names (make sure MITRE ATT&CK TID column exists)
    # allow user to have e.g., 'MITRE ATT&CK TID' or 'MITRE ATT&CK TID ' etc.
    cols = {c.strip():c for c in df.columns}
    # standardize to known column names
    rename_map = {}
    for k in cols:
        lk = k.lower()
        if "mitre" in lk and "tid" in lk:
            rename_map[cols[k]] = "MITRE ATT&CK TID"
        elif "시나리오" in lk or "scenario" in lk:
            rename_map[cols[k]] = "시나리오명"
        elif "비고" in lk or "설명" in lk:
            rename_map[cols[k]] = "비고(설명)"
        elif "대응" in lk or "대응방안" in lk:
            rename_map[cols[k]] = "대응방안"
    if rename_map:
        df = df.rename(columns=rename_map)
    # ensure columns exist
    for col in ["MITRE ATT&CK TID","시나리오명","비고(설명)","대응방안"]:
        if col not in df.columns:
            df[col] = ""
    return df

# ================== Merge logic ==================
def expand_user_tid_to_tids(user_tid: str, attacks: Dict[str,Any], tech_to_tactics: Dict[str,List[str]]):
    """
    If user_tid starts with 'T' -> return [TID]
    If startswith 'TA' or contains 'Exfiltration' (tactic), attempt to expand to techniques under that tactic.
    """
    if not user_tid or str(user_tid).strip()=="":
        return []
    s = str(user_tid).strip()
    # If contains comma, split
    if "," in s:
        parts = [x.strip() for x in s.split(",") if x.strip()]
    else:
        parts = [s]
    result = []
    for p in parts:
        # extract token like 'T1048' or 'TA0010' or textual 'Exfiltration'
        m = re.search(r"(T\d{3,7})", p.upper())
        if m:
            tid = m.group(1)
            if tid in attacks:
                result.append(tid)
                continue
        # check TAxxx style (tactic)
        m2 = re.search(r"(TA\d{3,7})", p.upper())
        if m2:
            # find all techniques that include this tactic code in their kill_chain_phases? 
            # Our tech_to_tactics maps technique->phase names (e.g., 'exfiltration'). 
            # So we try matching by known tactic names if TA code given, fallback to empty.
            ta = m2.group(1)
            # TA ids not directly in tech_to_tactics; try to match by typical mapping:
            # We map common TA codes to phase names (heuristic)
            ta_map = {
                "TA0010": "exfiltration",
                "TA0001": "initial-access",
                "TA0033": "collection",
                "TA0043": "reconnaissance",
                # add more if needed
            }
            phase = ta_map.get(ta, "")
            if phase:
                for tid, tactics in tech_to_tactics.items():
                    if any(phase.lower() in (t or "").lower() for t in tactics):
                        result.append(tid)
                continue
        # else treat p as textual tactic name -> find matching techniques by tactic name or match by substring in name
        text = p.lower()
        # match tactic phrase in tech_to_tactics values
        matched = False
        for tid, tactics in tech_to_tactics.items():
            for t in tactics:
                if t and text in t.lower():
                    result.append(tid)
                    matched = True
                    break
            if matched: break
        if matched:
            continue
        # as fallback, try to match by technique name substring
        for tid, info in attacks.items():
            if text in (info.get("attack_name","") or "").lower():
                result.append(tid)
        # end fallback
    # deduplicate
    return sorted(list(set(result)))

def merge_user_and_auto(user_df: pd.DataFrame, auto_df: pd.DataFrame, attacks: Dict[str,Any], capecs: Dict[str,Any], tech_to_tactics: Dict[str,List[str]]):
    """
    auto_df: semantic/exlicit mapping dataframe with columns ATTACK_ID, CAPEC_ID, SIMILARITY, MATCH_METHOD (if semantic)
    user_df: original user mapping with MITRE ATT&CK TID (free text)
    returns combined dataframe and analysis dict
    """
    # prepare auto map keyed by ATTACK_ID -> list of CAPECs (from auto mapping)
    auto_map = {}
    for _, row in auto_df.iterrows():
        aid = str(row.get("ATTACK_ID","")).strip()
        cid = str(row.get("CAPEC_ID","")).strip().upper()
        sim = row.get("SIMILARITY","") if "SIMILARITY" in row else ""
        method = row.get("MATCH_METHOD","semantic") if "MATCH_METHOD" in row else "auto"
        if aid=="" or cid=="":
            continue
        auto_map.setdefault(aid, []).append({"CAPEC_ID":cid,"SIMILARITY":sim,"MATCH_METHOD":method})

    combined_rows = []
    conflicts = []
    user_only = []
    auto_only = []

    # process user rows
    for idx, u in user_df.iterrows():
        user_tid_field = str(u.get("MITRE ATT&CK TID","")).strip()
        user_scenario = str(u.get("시나리오명","")).strip()
        user_note = str(u.get("비고(설명)","")).strip()
        user_remedy = str(u.get("대응방안","")).strip()
        # expand to TIDs
        tids = expand_user_tid_to_tids(user_tid_field, attacks, tech_to_tactics)
        if not tids:
            # try fuzzy match by substring of scenario to attack names
            found = []
            text = user_scenario.lower()
            for tid, info in attacks.items():
                if text and text in (info.get("attack_name","") or "").lower():
                    found.append(tid)
            tids = found

        if not tids:
            # user mapping cannot be resolved to TIDs
            user_only.append({"user_index": idx, "user_tid_field": user_tid_field, "scenario": user_scenario})
            # still include row with empty ATTACK_ID
            combined_rows.append({
                "ATTACK_ID": "",
                "ATTACK_NAME": "",
                "CAPEC_ID": "",
                "CAPEC_NAME": "",
                "SOURCE": "user_only",
                "NOTE": "",
                "USER_SCENARIO": user_scenario,
                "USER_NOTE": user_note,
                "USER_REMEDY": user_remedy,
                "SIMILARITY": "",
                "MATCH_METHOD": ""
            })
            continue

        # for each resolved TID, combine
        for tid in tids:
            auto_entries = auto_map.get(tid, [])
            if not auto_entries:
                # no auto match -> user only mapped technique
                combined_rows.append({
                    "ATTACK_ID": tid,
                    "ATTACK_NAME": attacks.get(tid,{}).get("attack_name",""),
                    "CAPEC_ID": "",
                    "CAPEC_NAME": "",
                    "SOURCE": "user_only",
                    "NOTE": "",
                    "USER_SCENARIO": user_scenario,
                    "USER_NOTE": user_note,
                    "USER_REMEDY": user_remedy,
                    "SIMILARITY": "",
                    "MATCH_METHOD": ""
                })
            else:
                # if user row included a CAPEC in the scenario? (not likely) - otherwise we attach auto entries
                for a in auto_entries:
                    combined_rows.append({
                        "ATTACK_ID": tid,
                        "ATTACK_NAME": attacks.get(tid,{}).get("attack_name",""),
                        "CAPEC_ID": a["CAPEC_ID"],
                        "CAPEC_NAME": capecs.get(a["CAPEC_ID"],{}).get("capec_name",""),
                        "SOURCE": "auto_semantic",
                        "NOTE": "",
                        "USER_SCENARIO": user_scenario,
                        "USER_NOTE": user_note,
                        "USER_REMEDY": user_remedy,
                        "SIMILARITY": a.get("SIMILARITY",""),
                        "MATCH_METHOD": a.get("MATCH_METHOD","")
                    })

    # auto-only entries (that weren't referenced by user)
    user_refed = set([r["ATTACK_ID"] for r in combined_rows if r.get("ATTACK_ID")])
    for aid, entries in auto_map.items():
        if aid not in user_refed:
            for a in entries:
                combined_rows.append({
                    "ATTACK_ID": aid,
                    "ATTACK_NAME": attacks.get(aid,{}).get("attack_name",""),
                    "CAPEC_ID": a["CAPEC_ID"],
                    "CAPEC_NAME": capecs.get(a["CAPEC_ID"],{}).get("capec_name",""),
                    "SOURCE": "auto_only",
                    "NOTE": "",
                    "USER_SCENARIO": "",
                    "USER_NOTE": "",
                    "USER_REMEDY": "",
                    "SIMILARITY": a.get("SIMILARITY",""),
                    "MATCH_METHOD": a.get("MATCH_METHOD","")
                })

    df_comb = pd.DataFrame(combined_rows, columns=[
        "ATTACK_ID","ATTACK_NAME","CAPEC_ID","CAPEC_NAME","SOURCE","NOTE",
        "USER_SCENARIO","USER_NOTE","USER_REMEDY","SIMILARITY","MATCH_METHOD"
    ])

    # detect conflicts: same ATTACK_ID mapped to >1 distinct CAPEC_ID by auto+user or auto entries
    conflict_list = []
    grouped = df_comb.groupby("ATTACK_ID")
    for aid, group in grouped:
        cids = sorted(group["CAPEC_ID"].unique())
        cids = [c for c in cids if c and str(c).strip()!=""]
        if len(cids) > 1:
            conflict_list.append({"ATTACK_ID":aid, "ATTACK_NAME": group.iloc[0]["ATTACK_NAME"], "CAPEC_IDS":cids})

    analysis = {
        "total_user_rows": len(user_df),
        "resolved_user_TIDs": len(user_df) - len(user_only),
        "user_only_count": len(user_only),
        "auto_only_count": sum(1 for v in auto_map.values() for _ in v if True) - sum(1 for _ in df_comb[df_comb["SOURCE"]!="auto_only"].index),
        "conflicts": conflict_list,
        "user_unresolved": user_only
    }

    return df_comb, analysis

# ================== Main flow ==================
def main():
    # 1) collect CTI and build attacks & capecs
    tmp = Path(tempfile.mkdtemp(prefix="mitre_cti_"))
    try:
        repo = download_and_extract_cti(tmp)
        attacks, capecs, tech_to_tactics = collect_patterns_and_tactics(repo)
    except Exception as e:
        print(f"[!] Failed to download/parse CTI repo: {e}")
        return
    finally:
        # leave tmp for debugging or cleanup; clean up at end
        pass

    # 2) if semantic csv exists, load it; else compute semantic matches
    if SEMANTIC_CSV.exists():
        print(f"[+] Loading existing semantic mapping from {SEMANTIC_CSV}")
        auto_df = pd.read_csv(SEMANTIC_CSV, dtype=str).fillna("")
        # ensure columns name consistency
        if "ATTACK_ID" not in auto_df.columns and "attack_id" in auto_df.columns:
            auto_df = auto_df.rename(columns=str.upper)
    else:
        # build semantic mapping
        print("[+] Building semantic mapping (this may take several minutes)...")
        auto_df = semantic_match(attacks, capecs, threshold=SEMANTIC_SIM_THRESHOLD, topk=SEMANTIC_TOPK)
        # expected columns: ATTACK_ID, ATTACK_NAME, CAPEC_ID, CAPEC_NAME, SIMILARITY, MATCH_METHOD
        auto_df.to_csv(SEMANTIC_CSV, index=False, encoding="utf-8-sig")
        print(f"[+] Semantic mapping saved to {SEMANTIC_CSV}")

    # 3) load user mapping
    user_df = load_user_mapping(USER_CSV)

    # 4) merge
    combined_df, analysis = merge_user_and_auto(user_df, auto_df, attacks, capecs, tech_to_tactics)

    # 5) write combined CSV and report
    combined_df.to_csv(COMBINED_CSV, index=False, encoding="utf-8-sig")
    with open(REPORT_FILE, "w", encoding="utf-8") as fh:
        fh.write("Merge Analysis Report\n")
        fh.write("=====================\n\n")
        fh.write(f"Total user rows: {analysis['total_user_rows']}\n")
        fh.write(f"User rows resolved to TIDs: {analysis['resolved_user_TIDs']}\n")
        fh.write(f"User-only (unresolved) rows: {len(analysis['user_unresolved'])}\n\n")
        fh.write("Conflicts (ATTACK_ID mapped to multiple CAPECs):\n")
        for c in analysis['conflicts']:
            fh.write(f" - {c['ATTACK_ID']} ({c['ATTACK_NAME']}): {', '.join(c['CAPEC_IDS'])}\n")
        fh.write("\nUnresolved user rows (index, MITRE field, scenario):\n")
        for u in analysis['user_unresolved']:
            fh.write(f" - {u['user_index']}: '{u['user_tid_field']}' / '{u['scenario']}'\n")
    print(f"[+] Combined CSV written to {COMBINED_CSV}")
    print(f"[+] Report written to {REPORT_FILE}")

    # 6) cleanup temp repo folder
    try:
        import shutil
        shutil.rmtree(tmp)
    except Exception:
        pass

if __name__ == "__main__":
    main()
