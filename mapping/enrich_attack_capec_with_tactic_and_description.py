#!/usr/bin/env python3
"""
enrich_attack_capec_with_tactic_and_description.py

- 입력: mapping/attack_capec_mapping.csv (columns: ATTACK_ID, ATTACK_NAME, CAPEC_ID)
- 동작:
    1) MITRE enterprise-attack STIX JSON을 원격에서 내려받아 technique -> tactic 매핑을 생성
    2) CAPEC JSON을 내려받아 CAPEC ID -> (Name, Description) lookup 생성
    3) 입력 CSV와 병합하여 output CSV 생성
- 출력: mapping/attack_capec_mapping_with_tactic_and_desc.csv
"""

import requests
import pandas as pd
import sys
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Tuple

# 원본 데이터 URL
ATTACK_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CAPEC_JSON_URL = "https://capec.mitre.org/data/json/attackPatterns.json"

INPUT_CSV = Path("mapping/attack_capec_mapping.csv")
OUTPUT_CSV = Path("mapping/attack_capec_mapping_with_tactic_and_desc.csv")

def fetch_json(url: str, timeout: int = 30):
    print(f"[+] Fetching: {url}")
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()

def strip_html_tags(text: str) -> str:
    if not text:
        return ""
    # remove common HTML tags & entities (basic)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&[a-zA-Z]+;", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def build_attackid_to_tactics(attack_json) -> Tuple[Dict[str, list], Dict[str, str]]:
    objs = attack_json.get("objects", []) or []
    attack_to_tactics = {}
    attack_to_name = {}
    for obj in objs:
        if obj.get("type") != "attack-pattern":
            continue

        # find MITRE ATT&CK external id (Txxxxx)
        external_refs = obj.get("external_references", []) or []
        attack_id = None
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                break
        if not attack_id:
            continue

        attack_name = obj.get("name", "") or ""
        attack_to_name[attack_id] = attack_name

        tactics = set()
        # kill_chain_phases
        for kc in obj.get("kill_chain_phases", []) or []:
            p = kc.get("phase_name")
            if p:
                tactics.add(p)
        # x_mitre_tactic or other custom fields
        for k, v in obj.items():
            if isinstance(k, str) and k.startswith("x_mitre") and "tactic" in k and v:
                if isinstance(v, list):
                    tactics.update([str(x) for x in v if x])
                else:
                    tactics.add(str(v))
        attack_to_tactics[attack_id] = sorted(tactics)
    print(f"[+] Built tactic mapping for {len(attack_to_tactics)} techniques")
    return attack_to_tactics, attack_to_name

def build_capec_lookup(capec_json) -> Dict[str, Tuple[str,str]]:
    """
    Returns dict: CAPEC-ID (e.g., 'CAPEC-13') -> (Name, Description)
    CAPEC JSON may have various keys; we try common ones.
    """
    lookup = {}
    # try common top-level keys
    arr = capec_json.get("attack_patterns") or capec_json.get("attackPatterns") or capec_json.get("attack_patterns") or []
    if not arr and isinstance(capec_json, dict):
        # some providers embed differently
        for k in ["attack_patterns", "attackPatterns", "attack-patterns"]:
            if k in capec_json:
                arr = capec_json[k]
                break

    for item in arr:
        # CAPEC keys vary; try to find ID, Name, Description
        cid = item.get("ID") or item.get("id") or item.get("Capec_ID") or item.get("capec_id")
        name = item.get("Name") or item.get("name") or item.get("Title")
        desc = item.get("Description") or item.get("description") or item.get("Summary") or ""
        if not cid:
            # some CAPEC JSON entries use numeric 'ID' or nested structure, attempt other keys
            for k in item.keys():
                if isinstance(k, str) and "id" in k.lower():
                    maybe = item.get(k)
                    if maybe and str(maybe).upper().startswith("CAPEC"):
                        cid = maybe
                        break
        if cid:
            cid = str(cid).upper()
            name = (name or "").strip()
            desc = strip_html_tags(desc or "")
            lookup[cid] = (name, desc)
    print(f"[+] Built CAPEC lookup for {len(lookup)} CAPEC entries")
    return lookup

def normalize_capec_id(raw: str) -> str:
    if not raw:
        return ""
    r = raw.strip()
    # allow multiple CAPECs separated by commas; this function normalizes a single token
    if r.isdigit():
        return f"CAPEC-{r}"
    # already CAPEC-...
    return r.upper()

def enrich_rows(df: pd.DataFrame, attack_to_tactics, attack_to_name, capec_lookup: dict):
    rows = []
    for _, r in df.iterrows():
        aid = (r.get("ATTACK_ID") or "").strip()
        aname = (r.get("ATTACK_NAME") or "").strip()
        capec_field = (r.get("CAPEC_ID") or "").strip()
        # tactics
        tactics = attack_to_tactics.get(aid, [])
        if not tactics and aname:
            # fallback by name match
            for k, v in attack_to_name.items():
                if v and v.lower() == aname.lower():
                    tactics = attack_to_tactics.get(k, [])
                    break
        capec_ids = [c.strip() for c in re.split(r"[;,/]", capec_field) if c.strip()]
        capec_names = []
        capec_descs = []
        for cid in capec_ids:
            ncid = normalize_capec_id(cid)
            name_desc = capec_lookup.get(ncid) or capec_lookup.get(cid.upper()) or ("", "")
            capec_names.append(name_desc[0] or "")
            capec_descs.append(name_desc[1] or "")
        rows.append({
            "ATTACK_ID": aid,
            "ATTACK_NAME": aname,
            "TACTICS": "; ".join(tactics),
            "CAPEC_ID": ", ".join([normalize_capec_id(c) for c in capec_ids]),
            "CAPEC_NAME": "; ".join([n for n in capec_names if n]),
            "CAPEC_DESCRIPTION": " || ".join([d for d in capec_descs if d])
        })
    return pd.DataFrame(rows, columns=["ATTACK_ID","ATTACK_NAME","TACTICS","CAPEC_ID","CAPEC_NAME","CAPEC_DESCRIPTION"])

def main():
    if not INPUT_CSV.exists():
        print(f"[-] Input CSV not found: {INPUT_CSV}", file=sys.stderr)
        return

    df_in = pd.read_csv(INPUT_CSV, dtype=str).fillna("")
    # fetch ATT&CK
    attack_json = fetch_json(ATTACK_JSON_URL)
    attack_to_tactics, attack_to_name = build_attackid_to_tactics(attack_json)

    # fetch CAPEC (optional but requested)
    capec_lookup = {}
    try:
        capec_json = fetch_json(CAPEC_JSON_URL)
        capec_lookup = build_capec_lookup(capec_json)
    except Exception as e:
        print(f"[!] Warning: could not fetch CAPEC JSON: {e}", file=sys.stderr)

    df_out = enrich_rows(df_in, attack_to_tactics, attack_to_name, capec_lookup)
    # add metadata header row? we just save CSV normally
    df_out.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")
    print(f"[+] Written: {OUTPUT_CSV} rows={len(df_out)}")
    print(f"[✓] Completed at {datetime.utcnow().isoformat()} UTC")

if __name__ == "__main__":
    main()
