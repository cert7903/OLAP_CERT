#!/usr/bin/env python3
"""
generate_full_attack_capec_mapping.py

- Downloads MITRE CTI master.zip (if not already present), extracts.
- Reads enterprise-attack JSON (or attack-pattern JSONs under enterprise-attack/) to find ATT&CK techniques.
- Reads CAPEC attack-pattern JSONs from CTI repo (capec/2.1/attack-pattern/) to build CAPEC lookup (ID->name,description).
- Builds mapping ATTACK_ID -> CAPEC_ID (from external_references or relationship if present) and writes CSV.

Output:
  mapping/full_attack_capec_mapping.csv
Columns:
  ATTACK_ID,ATTACK_NAME,CAPEC_ID,CAPEC_NAME,CAPEC_DESCRIPTION,SOURCE,RELATION_TYPE,NOTE

Requirements:
  pip install requests pandas
"""

import os
import zipfile
import tempfile
import json
import requests
from pathlib import Path
from typing import Dict, Tuple, List
import pandas as pd

CTI_ZIP_URL = "https://github.com/mitre/cti/archive/refs/heads/master.zip"
OUT_DIR = Path("mapping")
OUT_CSV = OUT_DIR / "full_attack_capec_mapping.csv"
TMP_PREFIX = "mitre_cti_"

def download_cti_zip(tmpdir: Path) -> Path:
    zip_path = tmpdir / "cti_master.zip"
    if not zip_path.exists():
        print("[+] Downloading CTI master zip...")
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
    # find extracted repo folder (cti-master or cti-<branch>)
    children = [p for p in extract_to.iterdir() if p.is_dir()]
    if children:
        return children[0]
    return extract_to

def find_enterprise_attack_json(repo_root: Path) -> List[Path]:
    """
    Look for enterprise-attack.json or attack-pattern jsons under enterprise-attack folder.
    Returns list of json file paths to parse for attack-pattern objects.
    """
    cand = []
    # prefer single enterprise-attack.json
    p1 = repo_root / "enterprise-attack" / "enterprise-attack.json"
    if p1.exists():
        cand.append(p1)
        return cand
    # else collect all json files under enterprise-attack
    ent_dir = repo_root / "enterprise-attack"
    if ent_dir.exists():
        for p in ent_dir.rglob("*.json"):
            cand.append(p)
    return cand

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
            print(f"[-] Failed to load JSON {path}: {e}")
            return None

def collect_attack_patterns(json_files: List[Path]) -> Dict[str, Dict]:
    """
    Return dict ATTACK_ID -> {name, description, uuid, external_references}
    Only includes objects that have a mitre-attack external_id (Txxx)
    """
    attacks = {}
    for jf in json_files:
        j = load_json_safe(jf)
        if not j:
            continue
        objs = j.get("objects") if isinstance(j, dict) else None
        if objs is None:
            continue
        for obj in objs:
            if not isinstance(obj, dict):
                continue
            if obj.get("type") != "attack-pattern":
                continue
            # find mitre-attack external id
            ext_id = ""
            for ref in obj.get("external_references", []) or []:
                if (ref.get("source_name") or "").lower() == "mitre-attack" and ref.get("external_id"):
                    ext_id = str(ref.get("external_id")).strip().upper()
                    break
            if not ext_id:
                # skip patterns with no ATT&CK external id (we only want ATT&CK techniques)
                continue
            attacks[ext_id] = {
                "uuid": obj.get("id",""),
                "attack_id": ext_id,
                "attack_name": obj.get("name","") or "",
                "attack_desc": (obj.get("description","") or "").strip(),
                "external_references": obj.get("external_references", []) or [],
                "kill_chain_phases": obj.get("kill_chain_phases", []) or []
            }
    print(f"[+] Collected {len(attacks)} ATT&CK attack-patterns")
    return attacks

def collect_capec_lookup(repo_root: Path) -> Dict[str, Dict]:
    """
    Build CAPEC lookup from CTI repo capec/2.1/attack-pattern/*.json files (external_references with source_name 'capec')
    Returns dict CAPEC-ID -> {capec_name, capec_desc, uuid}
    """
    capec_lookup = {}
    capec_dir = repo_root / "capec" / "2.1" / "attack-pattern"
    if not capec_dir.exists():
        # fallback: search repo for attack-pattern objects that reference capec
        print("[!] capec folder not found at expected path; attempting fallback scan in whole repo")
        for p in repo_root.rglob("*.json"):
            j = load_json_safe(p)
            if not j:
                continue
            objs = j.get("objects") if isinstance(j, dict) else None
            if not objs:
                continue
            for obj in objs:
                if obj.get("type") != "attack-pattern":
                    continue
                for ref in obj.get("external_references", []) or []:
                    if (ref.get("source_name") or "").lower().startswith("capec") and ref.get("external_id"):
                        cid = str(ref.get("external_id")).strip().upper()
                        capec_lookup.setdefault(cid, {"capec_name": obj.get("name","") or "", "capec_desc": (obj.get("description","") or "").strip(), "uuid": obj.get("id","")})
        print(f"[+] Fallback CAPEC entries found: {len(capec_lookup)}")
        return capec_lookup

    print("[+] Scanning CAPEC files under capec/2.1/attack-pattern ...")
    for jf in capec_dir.rglob("*.json"):
        j = load_json_safe(jf)
        if not j:
            continue
        objs = j.get("objects") if isinstance(j, dict) else None
        if not objs:
            continue
        for obj in objs:
            if obj.get("type") != "attack-pattern":
                continue
            # find capec external id
            for ref in obj.get("external_references", []) or []:
                s = (ref.get("source_name") or "").lower()
                if "capec" in s and ref.get("external_id"):
                    cid = str(ref.get("external_id")).strip().upper()
                    capec_lookup[cid] = {
                        "capec_name": obj.get("name","") or "",
                        "capec_desc": (obj.get("description","") or "").strip(),
                        "uuid": obj.get("id","")
                    }
                    break
    print(f"[+] Collected {len(capec_lookup)} CAPEC entries from repo")
    return capec_lookup

def build_attack_capec_mappings(attacks: Dict[str, Dict], capec_lookup: Dict[str, Dict]) -> List[Dict]:
    """
    For each attack, inspect external_references for capec refs.
    Output list of mapping rows.
    """
    rows = []
    for aid, aobj in attacks.items():
        ext_refs = aobj.get("external_references", []) or []
        found = False
        for ref in ext_refs:
            s = (ref.get("source_name") or "").lower()
            eid = ref.get("external_id") or ""
            if "capec" in s and eid:
                cid = str(eid).strip().upper()
                capec_info = capec_lookup.get(cid, {"capec_name":"", "capec_desc":""})
                rows.append({
                    "ATTACK_ID": aid,
                    "ATTACK_NAME": aobj.get("attack_name",""),
                    "CAPEC_ID": cid,
                    "CAPEC_NAME": capec_info.get("capec_name",""),
                    "CAPEC_DESCRIPTION": capec_info.get("capec_desc",""),
                    "SOURCE": "external_reference",
                    "RELATION_TYPE": ref.get("relationship_type","") or "",
                    "NOTE": ref.get("description","") or ""
                })
                found = True
        # optional: if none found, still emit row with empty CAPEC columns (so user can see missing)
        if not found:
            rows.append({
                "ATTACK_ID": aid,
                "ATTACK_NAME": aobj.get("attack_name",""),
                "CAPEC_ID": "",
                "CAPEC_NAME": "",
                "CAPEC_DESCRIPTION": "",
                "SOURCE": "",
                "RELATION_TYPE": "",
                "NOTE": ""
            })
    return rows

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmpdir = Path(tempfile.mkdtemp(prefix=TMP_PREFIX))
    try:
        zip_path = download_cti_zip(tmpdir)
        repo_root = extract_zip(zip_path, tmpdir)
        # repo_root typically like .../cti-master or cti-<branch>
        # find enterprise attack json files
        ea_jsons = find_enterprise_attack_json(repo_root)
        if not ea_jsons:
            print("[-] enterprise-attack JSON files not found in CTI repo. Exiting.")
            return
        attacks = collect_attack_patterns(ea_jsons)
        capec_lookup = collect_capec_lookup(repo_root)

        rows = build_attack_capec_mappings(attacks, capec_lookup)
        df = pd.DataFrame(rows, columns=["ATTACK_ID","ATTACK_NAME","CAPEC_ID","CAPEC_NAME","CAPEC_DESCRIPTION","SOURCE","RELATION_TYPE","NOTE"])
        df.to_csv(OUT_CSV, index=False, encoding="utf-8-sig")
        print(f"[+] Wrote {len(df)} rows to {OUT_CSV}")
    finally:
        # cleanup temporary extraction directory
        try:
            import shutil
            shutil.rmtree(tmpdir)
        except Exception:
            pass

if __name__ == "__main__":
    main()
