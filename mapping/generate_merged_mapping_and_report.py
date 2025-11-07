#!/usr/bin/env python3
"""
generate_full_attack_capec_mapping.py

- Downloads MITRE CTI master.zip (if not already present) and extracts.
- Parses attack-pattern objects (ATT&CK & CAPEC patterns) and relationship objects.
- Builds ATT&CK <-> CAPEC mappings using:
    1) attack-pattern.external_references (source_name == "capec")
    2) relationship objects that link attack-pattern <-> attack-pattern where one side is ATT&CK (T...) and the other is CAPEC.
- Outputs CSVs:
    - mapping/full_attack_capec_mapping.csv
    - mapping/full_attack_capec_mapping_relationships_expanded.csv

Requirements:
    pip install requests pandas
"""

from pathlib import Path
import zipfile
import tempfile
import requests
import json
import os
import sys
import pandas as pd
from typing import Dict, Any, List, Tuple, Set

CTI_ZIP_URL = "https://github.com/mitre/cti/archive/refs/heads/master.zip"
OUT_DIR = Path("mapping")
OUT_CSV = OUT_DIR / "full_attack_capec_mapping.csv"
OUT_CSV_EXPANDED = OUT_DIR / "full_attack_capec_mapping_relationships_expanded.csv"
TMP_PREFIX = "mitre_cti_"

# ---------------- Utility ----------------
def download_cti_zip(tmpdir: Path) -> Path:
    zip_path = tmpdir / "cti_master.zip"
    if not zip_path.exists():
        print("[+] Downloading MITRE CTI master zip...")
        r = requests.get(CTI_ZIP_URL, stream=True, timeout=60)
        r.raise_for_status()
        with open(zip_path, "wb") as fh:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    fh.write(chunk)
    else:
        print("[+] Using cached CTI zip:", zip_path)
    return zip_path

def extract_zip(zip_path: Path, extract_to: Path) -> Path:
    print(f"[+] Extracting {zip_path} -> {extract_to}")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_to)
    # return repo root (first directory)
    for p in extract_to.iterdir():
        if p.is_dir():
            return p
    return extract_to

def iter_json_files(repo_root: Path):
    for p in repo_root.rglob("*.json"):
        yield p

def load_json_safe(path: Path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            return json.loads(raw.decode("utf-8", errors="ignore"))
        except Exception:
            return None

def normalize_capec_id(s: str) -> str:
    if not s:
        return ""
    s = str(s).strip().upper()
    if s.isdigit():
        return f"CAPEC-{s}"
    if s.startswith("CAPEC-"):
        return s
    if s.startswith("CAPEC"):
        return s.replace("CAPEC", "CAPEC-")
    return s

# ---------------- Collect patterns & relationships ----------------
def collect_patterns_and_relationships(repo_root: Path):
    """
    Returns:
      attack_patterns: uuid -> object (all attack-pattern STIX objects)
      relationships: list of relationship objects
      attack_by_extid: ATTACK_ID (T...) -> {uuid, name, description, external_references, kill_chain_phases}
      capec_by_extid: CAPEC_ID (CAPEC-...) -> {uuid, name, description, external_references}
    """
    attack_patterns = {}
    relationships = []
    attack_by_extid = {}
    capec_by_extid = {}

    print("[+] Scanning JSON files for STIX objects...")
    for jf in iter_json_files(repo_root):
        j = load_json_safe(jf)
        if not j:
            continue
        objs = j.get("objects") if isinstance(j, dict) else (j if isinstance(j, list) else None)
        if not objs:
            continue
        for obj in objs:
            if not isinstance(obj, dict):
                continue
            typ = obj.get("type")
            if typ == "attack-pattern":
                uid = obj.get("id")
                if not uid:
                    continue
                attack_patterns[uid] = obj
                # extract external_references to find ext ids
                ext_id = ""
                src_hint = ""
                for ref in obj.get("external_references", []) or []:
                    src = (ref.get("source_name") or "").lower()
                    eid = ref.get("external_id") or ref.get("id") or ""
                    if not eid:
                        continue
                    if "mitre-attack" in src:
                        ext_id = str(eid).strip().upper()
                        src_hint = "mitre-attack"
                        break
                    if "capec" in src:
                        # record capec pattern too
                        cid = normalize_capec_id(eid)
                        capec_by_extid[cid] = {
                            "uuid": uid,
                            "capec_id": cid,
                            "capec_name": obj.get("name","") or "",
                            "capec_desc": (obj.get("description","") or "").strip()
                        }
                        # also mark ext_id if MITRE attack present later
                        src_hint = "capec"
                # if ext_id not empty and looks like T..., record attack_by_extid
                if ext_id and str(ext_id).upper().startswith("T"):
                    attack_by_extid[ext_id] = {
                        "uuid": uid,
                        "attack_id": ext_id,
                        "attack_name": obj.get("name","") or "",
                        "attack_desc": (obj.get("description","") or "").strip(),
                        "external_references": obj.get("external_references", []) or [],
                        "kill_chain_phases": obj.get("kill_chain_phases", []) or []
                    }
            elif typ == "relationship":
                relationships.append(obj)
    print(f"[+] Collected attack-pattern objects: {len(attack_patterns)}")
    print(f"[+] Collected relationship objects: {len(relationships)}")
    print(f"[+] ATT&CK techniques with external IDs found: {len(attack_by_extid)}")
    print(f"[+] CAPEC candidates found via external refs: {len(capec_by_extid)}")
    return attack_patterns, attack_by_extid, capec_by_extid, relationships

# ---------------- Build mappings ----------------
def find_mappings_from_external_refs(attack_by_extid: Dict[str,Any], capec_lookup: Dict[str,Any]):
    """
    For attack pattern objects that have external_references referencing CAPEC,
    create mapping rows.
    """
    rows = []
    for aid, meta in attack_by_extid.items():
        ext_refs = meta.get("external_references", []) or []
        for ref in ext_refs:
            src = (ref.get("source_name") or "").lower()
            eid = ref.get("external_id") or ""
            if "capec" in src and eid:
                cid = normalize_capec_id(eid)
                capec_info = capec_lookup.get(cid, {"capec_name":"", "capec_desc":""})
                rows.append({
                    "ATTACK_ID": aid,
                    "ATTACK_NAME": meta.get("attack_name",""),
                    "CAPEC_ID": cid,
                    "CAPEC_NAME": capec_info.get("capec_name",""),
                    "CAPEC_DESCRIPTION": capec_info.get("capec_desc",""),
                    "SOURCE": "external_reference",
                    "RELATION_TYPE": ref.get("relationship_type","") or "",
                    "NOTE": ref.get("description","") or ""
                })
    print(f"[+] External-reference based mappings: {len(rows)}")
    return rows

def find_mappings_from_relationships(attack_patterns: Dict[str,Any], attack_by_extid: Dict[str,Any], capec_lookup: Dict[str,Any], relationships: List[Dict[str,Any]]):
    """
    Iterate relationship objects and find relationships linking attack-pattern <-> attack-pattern.
    If one side maps to ATTACK (T...) and the other side maps to CAPEC (CAPEC-...), record mapping.
    """
    rows = []
    # helper: map uuid -> meta ext id (if any)
    uuid_to_ext = {}
    for ext, m in attack_by_extid.items():
        uuid_to_ext[m.get("uuid")] = {"ext_id": ext, "type": "attack"}
    for cid, cmeta in capec_lookup.items():
        uuid_to_ext[cmeta.get("uuid")] = {"ext_id": cid, "type": "capec"}

    # But capec_lookup uuid might be same as attack_patterns uuid (we recorded capec patterns earlier)
    # Additionally, there can be relationships where both sides are attack-pattern UUIDs but ext ids indicate capec/attack.

    for rel in relationships:
        try:
            src = rel.get("source_ref")
            tgt = rel.get("target_ref")
            rtype = rel.get("relationship_type","")
            if not src or not tgt:
                continue
            # Both should be in attack_patterns to be relevant
            if src not in attack_patterns or tgt not in attack_patterns:
                continue
            # try to extract external ids from objects
            src_obj = attack_patterns.get(src)
            tgt_obj = attack_patterns.get(tgt)
            # get external IDs (mitre-attack or capec) from each object
            def extract_ext_ids(obj):
                ids = []
                for ref in obj.get("external_references",[]) or []:
                    eid = ref.get("external_id") or ref.get("id") or ""
                    srcn = (ref.get("source_name") or "").lower()
                    if eid:
                        # normalize capec ids
                        if "capec" in srcn:
                            ids.append(("capec", normalize_capec_id(eid)))
                        elif "mitre-attack" in srcn:
                            ids.append(("attack", str(eid).strip().upper()))
                        else:
                            # other refs ignored
                            pass
                return ids

            src_ids = extract_ext_ids(src_obj)
            tgt_ids = extract_ext_ids(tgt_obj)

            # now determine if one side is attack and other is capec
            # pick first matching pair if exists
            found_any = False
            for stype, seid in src_ids:
                for ttype, teid in tgt_ids:
                    if stype == "attack" and ttype == "capec":
                        # src attack -> tgt capec
                        capec_info = capec_lookup.get(teid, {"capec_name":"", "capec_desc":""})
                        rows.append({
                            "ATTACK_ID": seid,
                            "ATTACK_NAME": src_obj.get("name",""),
                            "CAPEC_ID": teid,
                            "CAPEC_NAME": capec_info.get("capec_name",""),
                            "CAPEC_DESCRIPTION": capec_info.get("capec_desc",""),
                            "SOURCE": "relationship",
                            "RELATION_TYPE": rtype,
                            "NOTE": rel.get("description","") or ""
                        })
                        found_any = True
                    elif stype == "capec" and ttype == "attack":
                        # src capec -> tgt attack (reverse)
                        capec_info = capec_lookup.get(seid, {"capec_name":"", "capec_desc":""})
                        rows.append({
                            "ATTACK_ID": teid,
                            "ATTACK_NAME": tgt_obj.get("name",""),
                            "CAPEC_ID": seid,
                            "CAPEC_NAME": capec_info.get("capec_name",""),
                            "CAPEC_DESCRIPTION": capec_info.get("capec_desc",""),
                            "SOURCE": "relationship",
                            "RELATION_TYPE": rtype,
                            "NOTE": rel.get("description","") or ""
                        })
                        found_any = True
            # If no direct external ref pairing found, try heuristics:
            # If one object has mitre-attack external_id and the other has no mitre but looks like capec (by ext refs),
            # check for capec refs in either object's external_references
            if not found_any:
                # gather any capec external ids present in either object
                src_capecs = [normalize_capec_id(ref.get("external_id")) for ref in src_obj.get("external_references",[]) or [] if (ref.get("source_name") or "").lower().startswith("capec") and ref.get("external_id")]
                tgt_capecs = [normalize_capec_id(ref.get("external_id")) for ref in tgt_obj.get("external_references",[]) or [] if (ref.get("source_name") or "").lower().startswith("capec") and ref.get("external_id")]
                src_attacks = [str(ref.get("external_id")).strip().upper() for ref in src_obj.get("external_references",[]) or [] if (ref.get("source_name") or "").lower().startswith("mitre-attack") and ref.get("external_id")]
                tgt_attacks = [str(ref.get("external_id")).strip().upper() for ref in tgt_obj.get("external_references",[]) or [] if (ref.get("source_name") or "").lower().startswith("mitre-attack") and ref.get("external_id")]
                # pairing
                for a in src_attacks:
                    for c in tgt_capecs:
                        capec_info = capec_lookup.get(c, {"capec_name":"", "capec_desc":""})
                        rows.append({
                            "ATTACK_ID": a,
                            "ATTACK_NAME": src_obj.get("name",""),
                            "CAPEC_ID": c,
                            "CAPEC_NAME": capec_info.get("capec_name",""),
                            "CAPEC_DESCRIPTION": capec_info.get("capec_desc",""),
                            "SOURCE": "relationship_heuristic",
                            "RELATION_TYPE": rtype,
                            "NOTE": rel.get("description","") or ""
                        })
                for a in tgt_attacks:
                    for c in src_capecs:
                        capec_info = capec_lookup.get(c, {"capec_name":"", "capec_desc":""})
                        rows.append({
                            "ATTACK_ID": a,
                            "ATTACK_NAME": tgt_obj.get("name",""),
                            "CAPEC_ID": c,
                            "CAPEC_NAME": capec_info.get("capec_name",""),
                            "CAPEC_DESCRIPTION": capec_info.get("capec_desc",""),
                            "SOURCE": "relationship_heuristic",
                            "RELATION_TYPE": rtype,
                            "NOTE": rel.get("description","") or ""
                        })
        except Exception:
            # skip problematic relationship entries but continue
            continue
    print(f"[+] Relationship-based mappings (incl. heuristics): {len(rows)}")
    return rows

# ---------------- Combine, dedupe, write ----------------
def combine_and_write(external_rows: List[Dict], relationship_rows: List[Dict]):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    # combine
    all_rows = external_rows + relationship_rows
    # normalize capec ids, attack ids to upper
    for r in all_rows:
        r["ATTACK_ID"] = (r.get("ATTACK_ID") or "").strip().upper()
        r["CAPEC_ID"] = normalize_capec_id(r.get("CAPEC_ID") or "")
        r["ATTACK_NAME"] = r.get("ATTACK_NAME") or ""
        r["CAPEC_NAME"] = r.get("CAPEC_NAME") or ""
        r["CAPEC_DESCRIPTION"] = r.get("CAPEC_DESCRIPTION") or ""
        r["SOURCE"] = r.get("SOURCE") or ""
        r["RELATION_TYPE"] = r.get("RELATION_TYPE") or ""
        r["NOTE"] = r.get("NOTE") or ""

    # remove duplicates by (ATTACK_ID, CAPEC_ID, SOURCE, RELATION_TYPE)
    seen = set()
    deduped = []
    for r in all_rows:
        key = (r["ATTACK_ID"], r["CAPEC_ID"], r["SOURCE"], r["RELATION_TYPE"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)

    df = pd.DataFrame(deduped, columns=["ATTACK_ID","ATTACK_NAME","CAPEC_ID","CAPEC_NAME","CAPEC_DESCRIPTION","SOURCE","RELATION_TYPE","NOTE"])
    # write combined CSV
    df.to_csv(OUT_CSV, index=False, encoding="utf-8-sig")
    # write expanded CSV (same as above but keep all fields; here identical)
    df.to_csv(OUT_CSV_EXPANDED, index=False, encoding="utf-8-sig")
    print(f"[+] Wrote {len(df)} unique rows to {OUT_CSV}")
    print(f"[+] Also wrote expanded rows to {OUT_CSV_EXPANDED}")

# ---------------- Main ----------------
def main():
    tmpdir = Path(tempfile.mkdtemp(prefix=TMP_PREFIX))
    try:
        zip_path = download_cti_zip(tmpdir)
        repo_root = extract_zip(zip_path, tmpdir)
        # collect objects
        attack_patterns, attack_by_extid, capec_by_extid, relationships = collect_patterns_and_relationships(repo_root)
        # build CAPEC lookup: use capec_by_extid found earlier; if empty, try scanning capec dir
        capec_lookup = dict(capec_by_extid)  # start with what we have
        # if capec dir exists, scan for more (robust)
        capec_dir = repo_root / "capec" / "2.1" / "attack-pattern"
        if capec_dir.exists():
            for jf in capec_dir.rglob("*.json"):
                j = load_json_safe(jf)
                if not j: continue
                for obj in j.get("objects", []) or []:
                    if obj.get("type") != "attack-pattern": continue
                    for ref in obj.get("external_references", []) or []:
                        if (ref.get("source_name") or "").lower().startswith("capec") and ref.get("external_id"):
                            cid = normalize_capec_id(ref.get("external_id"))
                            if cid not in capec_lookup:
                                capec_lookup[cid] = {
                                    "uuid": obj.get("id",""),
                                    "capec_id": cid,
                                    "capec_name": obj.get("name","") or "",
                                    "capec_desc": (obj.get("description","") or "").strip()
                                }
        print(f"[+] Final CAPEC lookup size: {len(capec_lookup)}")

        # mappings from external references
        external_rows = find_mappings_from_external_refs(attack_by_extid, capec_lookup)
        # mappings from relationships
        relationship_rows = find_mappings_from_relationships(attack_patterns, attack_by_extid, capec_lookup, relationships)

        combine_and_write(external_rows, relationship_rows)

    finally:
        # cleanup
        try:
            import shutil
            shutil.rmtree(tmpdir)
        except Exception:
            pass

if __name__ == "__main__":
    main()
