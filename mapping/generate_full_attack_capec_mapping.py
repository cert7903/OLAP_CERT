#!/usr/bin/env python3
"""
generate_full_attack_capec_mapping.py

- Downloads the MITRE CTI repository zip, extracts STIX JSON files, and builds a
  comprehensive mapping between ATT&CK techniques (ATTACK IDs) and CAPEC patterns.
- Output CSV: mapping/full_attack_capec_mapping.csv

Output columns:
  - ATTACK_ID: e.g., T1059
  - ATTACK_NAME: technique name
  - CAPEC_ID: e.g., CAPEC-248
  - CAPEC_NAME: CAPEC title (if available)
  - SOURCE: 'relationship' or 'external_reference'
  - RELATION_TYPE: relationship_type (if relationship source) or external reference type
  - NOTE: additional info (e.g., file origin)
"""

from pathlib import Path
import requests
import zipfile
import tempfile
import json
import os
import pandas as pd
import sys
from typing import Dict, Any, Tuple, List, Set

CTI_ZIP_URL = "https://github.com/mitre/cti/archive/refs/heads/master.zip"
OUTPUT_CSV = Path("mapping/full_attack_capec_mapping.csv")
TMP_PREFIX = "mitre_cti_"

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
    # The zip extracts to a folder like cti-master or cti-<branch>
    top_entries = [p for p in extract_dir.iterdir() if p.is_dir()]
    if top_entries:
        return top_entries[0]  # return path to extracted repo root
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
        # sometimes files may have non-utf8 or be very large; try fallback
        with open(path, "rb") as fh:
            raw = fh.read()
        try:
            return json.loads(raw.decode("utf-8", errors="ignore"))
        except Exception as e:
            print(f"[-] Failed to parse JSON {path}: {e}", file=sys.stderr)
            return None

def collect_attack_patterns_and_relationships(repo_root: Path):
    """
    Parse all JSON files and collect:
      - attack_patterns: uuid -> object
      - relationships: list of relationship objects
    """
    attack_patterns: Dict[str, Dict[str, Any]] = {}
    relationships: List[Dict[str, Any]] = []
    capec_patterns: Dict[str, Dict[str, Any]] = {}

    print("[+] Scanning JSON files for STIX objects...")
    for jf in iter_json_files(repo_root):
        j = load_json_safe(jf)
        if not j:
            continue
        # STIX bundle format often has "objects" top-level list
        objs = j.get("objects") if isinstance(j, dict) else None
        if objs is None and isinstance(j, list):
            objs = j
        if not objs:
            continue
        for obj in objs:
            if not isinstance(obj, dict):
                continue
            typ = obj.get("type")
            if typ == "attack-pattern":
                # store by id (uuid)
                uid = obj.get("id")
                if uid:
                    attack_patterns[uid] = obj
                    # check if this looks like CAPEC (external_references contain 'capec' source)
                    # but also CAPEC collection in repo contains CAPEC attack-patterns
                    # record separately if external_references indicate capec
                    for ref in obj.get("external_references", []) or []:
                        if ref.get("source_name") and "capec" in ref.get("source_name").lower():
                            capec_patterns[uid] = obj
            elif typ == "relationship":
                relationships.append(obj)
    print(f"[+] Collected attack-pattern objects: {len(attack_patterns)}")
    print(f"[+] Collected relationship objects: {len(relationships)}")
    print(f"[+] Detected CAPEC-like patterns by external refs: {len(capec_patterns)}")
    return attack_patterns, capec_patterns, relationships

def extract_external_id(obj: Dict[str, Any]) -> Tuple[str, str]:
    """
    From an attack-pattern object  -> find external_id for mitre-attack or capec
    Return (external_id, source_name) e.g. ("T1059","mitre-attack") or ("CAPEC-248","capec")
    """
    for ref in obj.get("external_references", []) or []:
        src = ref.get("source_name", "")
        eid = ref.get("external_id") or ref.get("id")
        if src and eid:
            return str(eid).strip(), src.strip().lower()
    # fallback: sometimes external id stored at top-level property (rare)
    return "", ""

def build_uuid_to_metadata(all_attack_patterns: Dict[str, Dict[str, Any]]):
    """
    Create lookup: uuid -> (external_id, name, source_hint)
    where source_hint attempts to indicate 'mitre-attack' or 'capec' based on external_references.
    """
    mapping = {}
    for uid, obj in all_attack_patterns.items():
        ext_id = ""
        src_name = ""
        # some have multiple external_references: choose one with mitre-attack or capec if present
        for ref in obj.get("external_references", []) or []:
            s = (ref.get("source_name") or "").lower()
            e = ref.get("external_id") or ref.get("id") or ""
            if e and s:
                if "mitre-attack" in s:
                    ext_id = str(e).strip()
                    src_name = "mitre-attack"
                    break
                if "capec" in s:
                    ext_id = str(e).strip()
                    src_name = "capec"
                    break
        # if not found, fallback to first external_reference
        if not ext_id:
            for ref in obj.get("external_references", []) or []:
                e = ref.get("external_id") or ref.get("id") or ""
                s = (ref.get("source_name") or "").lower()
                if e:
                    ext_id = str(e).strip()
                    src_name = s or ""
                    break
        name = obj.get("name") or ""
        mapping[uid] = {
            "external_id": ext_id,
            "name": name,
            "source_hint": src_name
        }
    return mapping

def find_mappings_via_relationships(uuid_meta: Dict[str, Dict[str, Any]], relationships: List[Dict[str, Any]]):
    """
    For each relationship of type that links attack-pattern <-> attack-pattern, if one side is ATT&CK and the other is CAPEC (by source_hint or external_id format), record mapping.
    """
    results = []
    for rel in relationships:
        src = rel.get("source_ref")
        tgt = rel.get("target_ref")
        rtype = rel.get("relationship_type") or ""
        if not src or not tgt:
            continue
        # both must be attack-pattern references (id format attack-pattern--uuid)
        # but sometimes relationships link other types; we'll check if both are in uuid_meta
        if src not in uuid_meta or tgt not in uuid_meta:
            continue
        src_meta = uuid_meta[src]
        tgt_meta = uuid_meta[tgt]

        src_ext = src_meta.get("external_id","") or ""
        tgt_ext = tgt_meta.get("external_id","") or ""
        src_hint = src_meta.get("source_hint","")
        tgt_hint = tgt_meta.get("source_hint","")

        # Determine which is ATT&CK vs CAPEC
        def is_attack(eid, hint):
            if hint and "mitre-attack" in hint:
                return True
            if isinstance(eid, str) and eid.upper().startswith("T"):
                return True
            return False
        def is_capec(eid, hint):
            if hint and "capec" in hint:
                return True
            if isinstance(eid, str) and eid.upper().startswith("CAPEC"):
                return True
            return False

        # check both orientations
        if is_attack(src_ext, src_hint) and is_capec(tgt_ext, tgt_hint):
            results.append({
                "attack_uuid": src,
                "attack_id": src_ext,
                "attack_name": src_meta.get("name",""),
                "capec_uuid": tgt,
                "capec_id": tgt_ext,
                "capec_name": tgt_meta.get("name",""),
                "source": "relationship",
                "relation_type": rtype,
                "note": rel.get("description","") or ""
            })
        elif is_attack(tgt_ext, tgt_hint) and is_capec(src_ext, src_hint):
            results.append({
                "attack_uuid": tgt,
                "attack_id": tgt_ext,
                "attack_name": tgt_meta.get("name",""),
                "capec_uuid": src,
                "capec_id": src_ext,
                "capec_name": src_meta.get("name",""),
                "source": "relationship",
                "relation_type": rtype,
                "note": rel.get("description","") or ""
            })
    return results

def find_mappings_via_external_refs(all_attack_patterns: Dict[str, Dict[str, Any]], uuid_meta: Dict[str, Dict[str, Any]]):
    """
    Some ATT&CK technique objects include external_references that directly reference CAPEC IDs (source_name==capec).
    Extract those as mappings (source: external_reference).
    """
    results = []
    for uid, obj in all_attack_patterns.items():
        # attempt to find mitre-attack external id for this object
        att_id = ""
        for ref in obj.get("external_references", []) or []:
            if (ref.get("source_name") or "").lower() == "mitre-attack" and ref.get("external_id"):
                att_id = str(ref.get("external_id")).strip()
                break
        # if object itself is capec-pattern, skip here
        # find any external_references that are capec
        capec_refs = []
        for ref in obj.get("external_references", []) or []:
            if (ref.get("source_name") or "").lower() == "capec" and ref.get("external_id"):
                capec_refs.append(str(ref.get("external_id")).strip())
        # If att_id present and capec_refs exists, record mapping(s)
        if att_id and capec_refs:
            name = obj.get("name","")
            for cid in capec_refs:
                results.append({
                    "attack_uuid": uid,
                    "attack_id": att_id,
                    "attack_name": name,
                    "capec_uuid": "",  # unknown here (external ref only)
                    "capec_id": cid,
                    "capec_name": "",
                    "source": "external_reference",
                    "relation_type": "external_reference_capec",
                    "note": ""
                })
    return results

def augment_capec_names(capec_candidates: Set[str], repo_capec_patterns: Dict[str, Dict[str, Any]]):
    """
    Build a mapping CAPEC-ID -> CAPEC Name by scanning known CAPEC pattern objects in the repo (if any)
    Also try to parse CAPEC JSON in repository directories if present (fallback).
    """
    lookup = {}
    # search repo patterns for external_id matching CAPEC-ID
    for uid, obj in repo_capec_patterns.items():
        # find external id
        ext_id = ""
        for ref in obj.get("external_references", []) or []:
            if (ref.get("source_name") or "").lower().startswith("capec") and ref.get("external_id"):
                ext_id = str(ref.get("external_id")).strip().upper()
                break
        if not ext_id:
            continue
        name = obj.get("name","") or ""
        lookup[ext_id] = name

    # For any candidate capec ids not found, keep as empty name
    for c in capec_candidates:
        if c not in lookup:
            lookup[c] = ""
    return lookup

def normalize_capec_id_str(s: str) -> str:
    if not s:
        return ""
    s = s.strip()
    if s.isdigit():
        return f"CAPEC-{s}"
    return s.upper()

def main():
    tmpdir = Path(tempfile.mkdtemp(prefix=TMP_PREFIX))
    try:
        repo_root = download_and_extract_cti(tmpdir)
        attack_patterns, capec_patterns, relationships = collect_attack_patterns_and_relationships(repo_root)
        # unify all attack-patterns into one dict for meta extraction
        all_attack_patterns = {**attack_patterns}
        # ensure capec patterns present too
        for k, v in capec_patterns.items():
            all_attack_patterns[k] = v

        uuid_meta = build_uuid_to_metadata(all_attack_patterns)
        # mappings from relationships (explicit STIX relationships)
        rel_mappings = find_mappings_via_relationships(uuid_meta, relationships)
        print(f"[+] Relationship-based mappings found: {len(rel_mappings)}")
        # mappings from external references inside technique objects
        extref_mappings = find_mappings_via_external_refs(all_attack_patterns, uuid_meta)
        print(f"[+] External-ref-based mappings found: {len(extref_mappings)}")

        # combine and normalize CAPEC IDs & collect capec id set
        combined = rel_mappings + extref_mappings
        unique_pairs = {}
        capec_set = set()
        for rec in combined:
            a_id = (rec.get("attack_id") or "").strip()
            c_id_raw = (rec.get("capec_id") or "").strip()
            if not a_id or not c_id_raw:
                # skip incomplete unless we can try to extract from names? keep but mark
                pass
            # normalize capec id (e.g., '13' -> 'CAPEC-13')
            c_id = normalize_capec_id_str(c_id_raw)
            rec["capec_id"] = c_id
            capec_set.add(c_id)
            key = (a_id.upper() if a_id else "", c_id)
            # prefer relationship source over external_reference for note; keep first
            if key not in unique_pairs:
                unique_pairs[key] = rec

        print(f"[+] Unique ATTACK↔CAPEC pairs found (pre-augment): {len(unique_pairs)}")

        # augment capec names from repo capec patterns if available
        capec_name_lookup = augment_capec_names(capec_set, capec_patterns)

        # build output rows
        rows = []
        for (a_id, c_id), rec in unique_pairs.items():
            rows.append({
                "ATTACK_ID": a_id,
                "ATTACK_NAME": rec.get("attack_name",""),
                "CAPEC_ID": c_id,
                "CAPEC_NAME": capec_name_lookup.get(c_id,""),
                "SOURCE": rec.get("source",""),
                "RELATION_TYPE": rec.get("relation_type",""),
                "NOTE": rec.get("note","")
            })

        # sort rows
        rows_sorted = sorted(rows, key=lambda x: (x["ATTACK_ID"] or "", x["CAPEC_ID"] or ""))

        # write CSV
        df = pd.DataFrame(rows_sorted, columns=["ATTACK_ID","ATTACK_NAME","CAPEC_ID","CAPEC_NAME","SOURCE","RELATION_TYPE","NOTE"])
        OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")
        print(f"[+] Wrote {len(df)} rows to {OUTPUT_CSV}")
    finally:
        # cleanup tmpdir if you want; keep for debugging by default we remove
        try:
            import shutil
            shutil.rmtree(tmpdir)
        except Exception:
            pass

if __name__ == "__main__":
    main()
