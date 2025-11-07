#!/usr/bin/env python3
"""
generate_full_attack_capec_mapping.py (semantic-augmented)

- Downloads MITRE CTI master zip and CAPEC JSON (if needed).
- Extracts attack-pattern and relationship objects.
- Builds explicit mappings from relationships and external_references.
- Builds ATT&CK technique descriptions and CAPEC descriptions (from CTI or CAPEC JSON).
- Computes semantic similarity between ATT&CK descriptions and CAPEC descriptions:
    - Uses sentence-transformers (SBERT) if available.
    - Falls back to TF-IDF + cosine similarity otherwise.
- Outputs:
    - mapping/full_attack_capec_mapping.csv                (explicit mappings)
    - mapping/full_attack_capec_mapping_semantic.csv      (explicit + semantic mappings with scores)
- Requires: requests, pandas, scikit-learn (for fallback), optionally sentence-transformers
"""

from pathlib import Path
import requests
import zipfile
import tempfile
import json
import os
import pandas as pd
import sys
import re
import math
from typing import Dict, Any, List, Tuple, Set
from itertools import islice

# Attempt imports for embedding; fallback will use sklearn TF-IDF
USE_SBERT = False
try:
    from sentence_transformers import SentenceTransformer, util
    USE_SBERT = True
except Exception:
    USE_SBERT = False

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

CTI_ZIP_URL = "https://github.com/mitre/cti/archive/refs/heads/master.zip"
CAPEC_JSON_URL = "https://capec.mitre.org/data/json/attackPatterns.json"
OUTPUT_DIR = Path("mapping")
OUTPUT_EXPLICIT = OUTPUT_DIR / "full_attack_capec_mapping.csv"
OUTPUT_SEMANTIC = OUTPUT_DIR / "full_attack_capec_mapping_semantic.csv"
TMP_PREFIX = "mitre_cti_"

# Semantic thresholds (adjustable)
SBERT_THRESHOLD = 0.70
TFIDF_THRESHOLD = 0.40
MAX_SEMANTIC_PER_ATTACK = 5  # top-k CAPEC per ATTACK by similarity


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
    print(f"[+] Extracting to {extract_dir} ...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_dir)
    top_entries = [p for p in extract_dir.iterdir() if p.is_dir()]
    if top_entries:
        return top_entries[0]
    return extract_dir


def iter_json_files(repo_root: Path):
    for root, dirs, files in os.walk(repo_root):
        for f in files:
            if f.lower().endswith(".json"):
                yield Path(root) / f


def load_json_safe(path: Path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            return json.loads(raw.decode("utf-8", errors="ignore"))
        except Exception as e:
            print(f"[-] Failed to parse JSON {path}: {e}", file=sys.stderr)
            return None


def collect_patterns_and_relationships(repo_root: Path, filter_dirs: List[str] = None):
    """
    Scans JSON files but optionally limits to specified directories to speed up.
    If filter_dirs provided (relative dir names in repo), only files under them are checked.
    """
    attack_patterns = {}
    capec_patterns = {}
    relationships = []

    print("[+] Scanning JSON files for STIX objects (filtered)...")
    for jf in iter_json_files(repo_root):
        # If filtering on directories, skip files not under them
        if filter_dirs:
            rel = jf.relative_to(repo_root)
            if not any(str(rel).startswith(fd) for fd in filter_dirs):
                continue
        j = load_json_safe(jf)
        if not j:
            continue
        objs = j.get("objects") if isinstance(j, dict) else j if isinstance(j, list) else None
        if not objs:
            continue
        for obj in objs:
            if not isinstance(obj, dict):
                continue
            typ = obj.get("type")
            if typ == "attack-pattern":
                uid = obj.get("id")
                if uid:
                    attack_patterns[uid] = obj
                    # detect CAPEC-like via external_references
                    for ref in obj.get("external_references", []) or []:
                        if ref.get("source_name") and "capec" in str(ref.get("source_name")).lower():
                            capec_patterns[uid] = obj
            elif typ == "relationship":
                relationships.append(obj)
    print(f"[+] Collected attack-patterns: {len(attack_patterns)}")
    print(f"[+] Detected CAPEC-like patterns by external refs: {len(capec_patterns)}")
    print(f"[+] Collected relationships: {len(relationships)}")
    return attack_patterns, capec_patterns, relationships


def extract_external_id_and_description(obj: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Return (external_id, name, description) if available.
    External id chosen: mitre-attack or capec if present in external_references.
    """
    ext_id = ""
    name = obj.get("name", "") or ""
    desc = obj.get("description", "") or ""
    # some descriptions are under 'description' or x_mitre_data_sources or elsewhere; prefer 'description'
    for ref in obj.get("external_references", []) or []:
        src = (ref.get("source_name") or "").lower()
        eid = ref.get("external_id") or ref.get("id") or ""
        if "mitre-attack" in src and eid:
            ext_id = str(eid).strip()
            break
        if "capec" in src and eid and not ext_id:
            ext_id = str(eid).strip()
    # fallback: try to parse name for "T1234" style
    if not ext_id:
        # sometimes MITRE stores external_id in custom props - skip for speed
        pass
    # normalize desc: strip html tags
    desc = strip_html_tags(desc)
    return ext_id, name, desc


def strip_html_tags(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&[a-zA-Z]+;", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def build_uuid_meta(all_patterns: Dict[str, Dict[str, Any]]):
    meta = {}
    for uid, obj in all_patterns.items():
        ext_id, name, desc = extract_external_id_and_description(obj)
        # if description empty, try to get description from 'x_mitre_description' fields
        if not desc:
            for k, v in obj.items():
                if isinstance(k, str) and "description" in k and isinstance(v, str):
                    desc = v
                    break
        meta[uid] = {"external_id": ext_id, "name": name, "description": desc}
    return meta


def find_explicit_mappings(uuid_meta: Dict[str, Dict[str, Any]], relationships: List[Dict[str, Any]]):
    explicit = []
    # first relationships
    for rel in relationships:
        src = rel.get("source_ref")
        tgt = rel.get("target_ref")
        rtype = rel.get("relationship_type") or ""
        if not src or not tgt:
            continue
        if src not in uuid_meta or tgt not in uuid_meta:
            continue
        s_meta = uuid_meta[src]
        t_meta = uuid_meta[tgt]
        s_e = s_meta.get("external_id","") or ""
        t_e = t_meta.get("external_id","") or ""
        s_hint = (s_meta.get("external_id") or "").upper()
        t_hint = (t_meta.get("external_id") or "").upper()
        # heuristics detect ATTACK (T...) vs CAPEC (CAPEC-...)
        def is_attack(e): return bool(e and str(e).upper().startswith("T"))
        def is_capec(e): return bool(e and str(e).upper().startswith("CAPEC"))
        if is_attack(s_e) and is_capec(t_e):
            explicit.append({
                "attack_id": s_e.upper(),
                "attack_name": s_meta.get("name",""),
                "attack_desc": s_meta.get("description",""),
                "capec_id": t_e.upper(),
                "capec_name": t_meta.get("name",""),
                "capec_desc": t_meta.get("description",""),
                "source": "relationship",
                "relation_type": rtype
            })
        elif is_attack(t_e) and is_capec(s_e):
            explicit.append({
                "attack_id": t_e.upper(),
                "attack_name": t_meta.get("name",""),
                "attack_desc": t_meta.get("description",""),
                "capec_id": s_e.upper(),
                "capec_name": s_meta.get("name",""),
                "capec_desc": s_meta.get("description",""),
                "source": "relationship",
                "relation_type": rtype
            })
    # second: external_references inside patterns (attack -> capec)
    for uid, m in uuid_meta.items():
        a_id = m.get("external_id","") or ""
        if not a_id or not a_id.upper().startswith("T"):
            continue
        # check original object external refs: but uuid_meta doesn't store all external refs, so skip here
        # explicit external refs were earlier detected when scanning repo as capec_patterns; to be robust, we won't double-scan here.
    return explicit


def fetch_capec_json(timeout: int = 30):
    try:
        print("[+] Fetching CAPEC JSON ...")
        r = requests.get(CAPEC_JSON_URL, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[!] Could not fetch CAPEC JSON: {e}", file=sys.stderr)
        return None


def build_capec_lookup_from_json(capec_json) -> Dict[str, Dict[str, str]]:
    """
    Build CAPEC-ID -> {name, description} from CAPEC JSON (attackPatterns or attack_patterns)
    """
    lookup = {}
    if not capec_json:
        return lookup
    arr = capec_json.get("attack_patterns") or capec_json.get("attackPatterns") or capec_json.get("attack_patterns") or []
    if not arr and isinstance(capec_json, dict):
        # sometimes nested keys
        for k in ["attack_patterns", "attackPatterns", "attack-patterns"]:
            if k in capec_json:
                arr = capec_json[k]
                break
    for item in arr:
        cid = item.get("ID") or item.get("id") or item.get("Capec_ID") or item.get("capec_id")
        name = item.get("Name") or item.get("name") or item.get("Title") or ""
        desc = item.get("Description") or item.get("description") or ""
        if cid:
            key = str(cid).upper()
            lookup[key] = {"name": (name or "").strip(), "description": strip_html_tags(desc or "")}
    return lookup


def aggregate_attack_and_capec_entries(uuid_meta: Dict[str, Dict[str, Any]], capec_json_lookup: Dict[str, Dict[str,str]], capec_patterns_in_repo: Dict[str, Dict[str,Any]]):
    """
    Build two lists:
      - attacks: list of dict {attack_id, name, description}
      - capecs: list of dict {capec_id, name, description}
    Uses:
      - uuid_meta (all patterns parsed) to extract ATT&CK techniques (external_id starts with T)
      - capec_json_lookup for CAPEC entries
      - capec_patterns_in_repo for CAPEC entries referenced inside repo objects
    """
    attacks = {}
    capecs = {}

    for uid, m in uuid_meta.items():
        eid = (m.get("external_id") or "").strip()
        name = m.get("name","") or ""
        desc = m.get("description","") or ""
        if eid and eid.upper().startswith("T"):
            key = eid.upper()
            if key not in attacks:
                attacks[key] = {"attack_id": key, "attack_name": name, "attack_desc": desc}
            else:
                # prefer non-empty desc
                if not attacks[key]["attack_desc"] and desc:
                    attacks[key]["attack_desc"] = desc

    # fill capecs from capec_json_lookup
    for cid, info in capec_json_lookup.items():
        capecs[cid] = {"capec_id": cid, "capec_name": info.get("name",""), "capec_desc": info.get("description","")}

    # also fill capecs from repo-detected capec patterns (capec_patterns_in_repo)
    for uid, obj in capec_patterns_in_repo.items():
        # find external capec id
        cid = ""
        for ref in obj.get("external_references", []) or []:
            if (ref.get("source_name") or "").lower().startswith("capec") and ref.get("external_id"):
                cid = str(ref.get("external_id")).strip().upper()
                break
        if cid:
            name = obj.get("name","") or ""
            desc = obj.get("description","") or ""
            if cid not in capecs:
                capecs[cid] = {"capec_id": cid, "capec_name": name, "capec_desc": strip_html_tags(desc)}
            else:
                if not capecs[cid]["capec_desc"] and desc:
                    capecs[cid]["capec_desc"] = strip_html_tags(desc)

    return list(attacks.values()), list(capecs.values())


def embed_and_match(attacks: List[Dict[str,str]], capecs: List[Dict[str,str]], use_sbert=USE_SBERT,
                    sbert_threshold=SBERT_THRESHOLD, tfidf_threshold=TFIDF_THRESHOLD, top_k=MAX_SEMANTIC_PER_ATTACK):
    """
    Compute embeddings and cosine similarities. Returns list of semantic matches:
      [{attack_id, attack_name, capec_id, capec_name, score, method}, ...]
    """
    # prepare texts
    attack_texts = []
    for a in attacks:
        text = " ".join([a.get("attack_name",""), a.get("attack_desc","") or ""])
        attack_texts.append(text if text.strip() else a.get("attack_name",""))

    capec_texts = []
    for c in capecs:
        text = " ".join([c.get("capec_name",""), c.get("capec_desc","") or ""])
        capec_texts.append(text if text.strip() else c.get("capec_name",""))

    matches = []
    if use_sbert:
        print("[+] Using Sentence-BERT for embeddings (fast & accurate).")
        model_name = "all-MiniLM-L6-v2"
        try:
            model = SentenceTransformer(model_name)
        except Exception as e:
            print(f"[!] Could not load SBERT model '{model_name}': {e}", file=sys.stderr)
            use_sbert = False

    if use_sbert:
        # compute embeddings
        attack_emb = model.encode(attack_texts, convert_to_tensor=True, show_progress_bar=True)
        capec_emb = model.encode(capec_texts, convert_to_tensor=True, show_progress_bar=True)
        # compute cosine similarities efficiently (matrix)
        sim_matrix = util.cos_sim(attack_emb, capec_emb).cpu().numpy()
        for i, a in enumerate(attacks):
            row = sim_matrix[i]
            # get top-k indices sorted by score desc
            idxs = list(islice(sorted(range(len(row)), key=lambda j: row[j], reverse=True), top_k))
            for j in idxs:
                score = float(row[j])
                if score >= sbert_threshold:
                    c = capecs[j]
                    matches.append({
                        "attack_id": a["attack_id"],
                        "attack_name": a.get("attack_name",""),
                        "capec_id": c["capec_id"],
                        "capec_name": c.get("capec_name",""),
                        "score": score,
                        "method": "sbert"
                    })
    else:
        # TF-IDF fallback
        print("[+] Using TF-IDF fallback for semantic matching.")
        vectorizer = TfidfVectorizer(max_df=0.9, min_df=1, ngram_range=(1,2))
        # combine corpora to ensure same feature space
        combined = attack_texts + capec_texts
        X = vectorizer.fit_transform(combined)
        A = X[:len(attack_texts)]
        C = X[len(attack_texts):]
        sim_matrix = cosine_similarity(A, C)
        for i, a in enumerate(attacks):
            row = sim_matrix[i]
            idxs = list(islice(sorted(range(len(row)), key=lambda j: row[j], reverse=True), top_k))
            for j in idxs:
                score = float(row[j])
                if score >= tfidf_threshold:
                    c = capecs[j]
                    matches.append({
                        "attack_id": a["attack_id"],
                        "attack_name": a.get("attack_name",""),
                        "capec_id": c["capec_id"],
                        "capec_name": c.get("capec_name",""),
                        "score": score,
                        "method": "tfidf"
                    })
    print(f"[+] Semantic matches found: {len(matches)} (thresholds: SBERT={sbert_threshold}, TFIDF={tfidf_threshold})")
    return matches


def combine_and_write(explicit_mappings: List[Dict[str,Any]], semantic_matches: List[Dict[str,Any]]):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    # Explicit first (relationship/external_reference)
    df_exp = pd.DataFrame(explicit_mappings)
    if df_exp.empty:
        df_exp = pd.DataFrame(columns=["ATTACK_ID","ATTACK_NAME","CAPEC_ID","CAPEC_NAME","SOURCE","RELATION_TYPE","NOTE"])
    else:
        # normalize columns for explicit
        df_exp = df_exp.rename(columns={
            "attack_id":"ATTACK_ID","attack_name":"ATTACK_NAME",
            "capec_id":"CAPEC_ID","capec_name":"CAPEC_NAME",
            "source":"SOURCE","relation_type":"RELATION_TYPE","note":"NOTE"
        })[["ATTACK_ID","ATTACK_NAME","CAPEC_ID","CAPEC_NAME","SOURCE","RELATION_TYPE","NOTE"]]
    # write explicit CSV
    df_exp.to_csv(OUTPUT_EXPLICIT, index=False, encoding="utf-8-sig")
    print(f"[+] Wrote explicit mapping CSV: {OUTPUT_EXPLICIT} rows={len(df_exp)}")

    # prepare semantic df and merge with explicit
    if semantic_matches:
        df_sem = pd.DataFrame(semantic_matches)
        df_sem = df_sem.rename(columns={
            "attack_id":"ATTACK_ID","attack_name":"ATTACK_NAME",
            "capec_id":"CAPEC_ID","capec_name":"CAPEC_NAME",
            "score":"SIMILARITY","method":"MATCH_METHOD"
        })[["ATTACK_ID","ATTACK_NAME","CAPEC_ID","CAPEC_NAME","SIMILARITY","MATCH_METHOD"]]
    else:
        df_sem = pd.DataFrame(columns=["ATTACK_ID","ATTACK_NAME","CAPEC_ID","CAPEC_NAME","SIMILARITY","MATCH_METHOD"])

    # Combine: prefer explicit rows; include semantic rows that are not duplicates.
    # Create set of explicit pairs:
    explicit_pairs = set((str(r["ATTACK_ID"]).upper(), str(r["CAPEC_ID"]).upper()) for _, r in df_exp.iterrows())
    rows = []
    # add explicit rows with metrics empty
    for _, r in df_exp.iterrows():
        rows.append({
            "ATTACK_ID": r["ATTACK_ID"],
            "ATTACK_NAME": r["ATTACK_NAME"],
            "CAPEC_ID": r["CAPEC_ID"],
            "CAPEC_NAME": r["CAPEC_NAME"],
            "SOURCE": r["SOURCE"],
            "RELATION_TYPE": r["RELATION_TYPE"],
            "NOTE": r.get("NOTE",""),
            "SIMILARITY": "",
            "MATCH_METHOD": "explicit"
        })
    # add semantic ones if not in explicit_pairs
    for _, r in df_sem.iterrows():
        key = (str(r["ATTACK_ID"]).upper(), str(r["CAPEC_ID"]).upper())
        if key in explicit_pairs:
            continue
        rows.append({
            "ATTACK_ID": r["ATTACK_ID"],
            "ATTACK_NAME": r["ATTACK_NAME"],
            "CAPEC_ID": r["CAPEC_ID"],
            "CAPEC_NAME": r.get("CAPEC_NAME",""),
            "SOURCE": "semantic",
            "RELATION_TYPE": "semantic_similarity",
            "NOTE": "",
            "SIMILARITY": round(float(r["SIMILARITY"]), 4) if r["SIMILARITY"] != "" else "",
            "MATCH_METHOD": r["MATCH_METHOD"]
        })
    df_out = pd.DataFrame(rows, columns=["ATTACK_ID","ATTACK_NAME","CAPEC_ID","CAPEC_NAME","SOURCE","RELATION_TYPE","NOTE","SIMILARITY","MATCH_METHOD"])
    df_out.to_csv(OUTPUT_SEMANTIC, index=False, encoding="utf-8-sig")
    print(f"[+] Wrote semantic-augmented CSV: {OUTPUT_SEMANTIC} rows={len(df_out)}")


def main():
    tmpdir = Path(tempfile.mkdtemp(prefix=TMP_PREFIX))
    try:
        repo_root = download_and_extract_cti(tmpdir)

        # Option: to speed up, only scan directories likely to contain relevant JSON
        # Common directories inside MITRE CTI repo:
        filter_dirs = [
            "enterprise-attack", "mobile-attack", "ics-attack", "capec"
        ]
        attack_patterns, capec_patterns_in_repo, relationships = collect_patterns_and_relationships(repo_root, filter_dirs=filter_dirs)

        # build uuid metadata for all patterns we found
        all_patterns = {**attack_patterns, **capec_patterns_in_repo}
        uuid_meta = build_uuid_meta(all_patterns)

        # explicit mappings via relationships & external refs
        explicit = find_explicit_mappings(uuid_meta, relationships)

        # fetch CAPEC JSON (optional) to get wider CAPEC descriptions
        capec_json = fetch_capec_json()
        capec_json_lookup = build_capec_lookup_from_json(capec_json) if capec_json else {}

        # build attack & capec entry lists for semantic matching
        attacks_list, capecs_list = aggregate_attack_and_capec_entries(uuid_meta, capec_json_lookup, capec_patterns_in_repo)

        # If no capec entries from capec_json, attempt to build from capec_patterns_in_repo
        if not capecs_list and capec_patterns_in_repo:
            # transform repo capec patterns
            for uid, obj in capec_patterns_in_repo.items():
                cid = ""
                for ref in obj.get("external_references", []) or []:
                    if (ref.get("source_name") or "").lower().startswith("capec") and ref.get("external_id"):
                        cid = str(ref.get("external_id")).strip().upper()
                        break
                if not cid:
                    continue
                name = obj.get("name","") or ""
                desc = strip_html_tags(obj.get("description","") or "")
                capecs_list.append({"capec_id":cid,"capec_name":name,"capec_desc":desc})

        # perform semantic matching (SBERT preferred)
        semantic_matches = []
        if attacks_list and capecs_list:
            semantic_matches = embed_and_match(attacks_list, capecs_list, use_sbert=USE_SBERT,
                                               sbert_threshold=SBERT_THRESHOLD, tfidf_threshold=TFIDF_THRESHOLD,
                                               top_k=MAX_SEMANTIC_PER_ATTACK)
        else:
            print("[!] No attacks or capecs available for semantic matching.", file=sys.stderr)

        # write outputs
        combine_and_write(explicit, semantic_matches)

    finally:
        try:
            import shutil
            shutil.rmtree(tmpdir)
        except Exception:
            pass


if __name__ == "__main__":
    main()
