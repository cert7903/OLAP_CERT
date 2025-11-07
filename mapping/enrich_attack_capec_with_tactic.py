#!/usr/bin/env python3
"""
enrich_attack_capec_with_tactic.py

- 입력: mapping/attack_capec_mapping.csv (columns: ATTACK_ID, ATTACK_NAME, CAPEC_ID)
- 동작:
    1) MITRE enterprise-attack STIX JSON을 원격에서 내려받아 technique -> tactic 매핑을 생성
    2) (선택) CAPEC API/JSON에서 CAPEC 이름(또는 설명)을 조회 (네트워크 연결 필요)
    3) 입력 CSV와 병합하여 output CSV 생성
- 출력: mapping/attack_capec_mapping_with_tactic.csv
"""

import requests
import pandas as pd
import time
import sys
from pathlib import Path

# MITRE CTI enterprise-attack raw JSON (STIX) — 공식 리포지토리
ATTACK_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# (선택) CAPEC JSON (MITRE 제공) — 이 파일은 대형이므로 요청 시 네트워크 환경을 고려하세요.
CAPEC_JSON_URL = "https://capec.mitre.org/data/json/attackPatterns.json"

INPUT_CSV = Path("mapping/attack_capec_mapping.csv")
OUTPUT_CSV = Path("mapping/attack_capec_mapping_with_tactic.csv")

def fetch_json(url, timeout=30):
    print(f"[+] Fetching: {url}")
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()

def build_attackid_to_tactics(attack_json):
    """
    STIX objects에는 technique (type == 'attack-pattern')와
    tactic/breakdown 정보가 다른 객체로 표현되어 있을 수 있음.
    일반적으로 technique 객체의 'kill_chain_phases' 또는 external_references / x_mitre_tactic에 tactic 정보가 있음.
    """
    print("[+] Building technique -> tactics mapping from ATT&CK JSON")
    objs = attack_json.get("objects", [])
    attack_to_tactics = {}   # ATTACK_ID -> set(tactic_name)
    attack_to_name = {}      # ATTACK_ID -> technique name

    # First pass: iterate through all objects
    for obj in objs:
        typ = obj.get("type")
        if typ != "attack-pattern":
            continue

        # find MITRE ATT&CK external id (e.g., T1059)
        external_refs = obj.get("external_references", []) or []
        attack_id = None
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                break

        if not attack_id:
            # some items may not have external id — skip
            continue

        # technique name
        name = obj.get("name") or ""
        attack_to_name[attack_id] = name

        tactics = set()

        # 1) x_mitre_data_sources or custom fields sometimes contain tactic info
        # 2) kill_chain_phases: list of {kill_chain_name, phase_name}
        kcp = obj.get("kill_chain_phases") or []
        for kc in kcp:
            phase = kc.get("phase_name")
            if phase:
                tactics.add(phase)

        # 3) sometimes there's an x_mitre_tactic or x_mitre_platforms etc
        # check custom properties
        # STIX may include "x_mitre_tactic" or "x_mitre_shortname" in some objects
        for k, v in (obj.items() if isinstance(obj, dict) else []):
            if isinstance(k, str) and k.startswith("x_mitre") and isinstance(v, (str, list)):
                if "tactic" in k and v:
                    if isinstance(v, list):
                        tactics.update(v)
                    else:
                        tactics.add(v)

        # 4) Some techniques include external references linking to tactics (less common)
        # save
        attack_to_tactics[attack_id] = sorted(tactics)

    return attack_to_tactics, attack_to_name

def build_capec_lookup(capec_json):
    """
    Build a CAPEC ID -> name lookup from CAPEC JSON (attackPatterns.json)
    The CAPEC JSON structure: { "attack_patterns": [ { "ID": "CAPEC-xxx", "Name": "...", ... }, ... ] }
    """
    print("[+] Building CAPEC lookup (id -> name)")
    lookup = {}
    try:
        arr = capec_json.get("attack_patterns") or capec_json.get("attackPatterns") or []
        for item in arr:
            # canonical CAPEC ID keys differ by source: try several possibilities
            cid = item.get("ID") or item.get("id") or item.get("capec_id") or item.get("capecId")
            name = item.get("Name") or item.get("name") or item.get("title") or item.get("Description")
            if cid and name:
                lookup[cid] = name
    except Exception as e:
        print(f"[-] Failed to build CAPEC lookup: {e}", file=sys.stderr)
    return lookup

def enrich_csv(input_csv: Path):
    if not input_csv.exists():
        print(f"[-] Input CSV not found: {input_csv}", file=sys.stderr)
        return

    df_in = pd.read_csv(input_csv, dtype=str).fillna("")
    # Normalize CAPEC_ID column (some rows may have multiple comma-separated CAPECs)
    df_in["CAPEC_ID"] = df_in["CAPEC_ID"].str.strip()

    # 1) fetch ATT&CK JSON and build mapping
    attack_json = fetch_json(ATTACK_JSON_URL)
    attack_to_tactics, attack_to_name = build_attackid_to_tactics(attack_json)

    # 2) (optional) fetch CAPEC JSON to get names
    capec_lookup = {}
    try:
        capec_json = fetch_json(CAPEC_JSON_URL)
        capec_lookup = build_capec_lookup(capec_json)
    except Exception as e:
        print(f"[!] Could not fetch CAPEC JSON ({e}) — continuing without CAPEC names", file=sys.stderr)

    # 3) build enriched rows
    enriched_rows = []
    for _, row in df_in.iterrows():
        attack_id = (row.get("ATTACK_ID") or "").strip()
        attack_name = (row.get("ATTACK_NAME") or "").strip()
        capec_field = (row.get("CAPEC_ID") or "").strip()

        # tactic(s) lookup
        tactics = attack_to_tactics.get(attack_id, [])
        # fallback: if tactics empty but attack_name present, try to find by name (case-insensitive)
        if not tactics and attack_name:
            for aid, aname in attack_to_name.items():
                if aname and aname.lower() == attack_name.lower():
                    tactics = attack_to_tactics.get(aid, [])
                    break

        # CAPEC name lookup (support multiple CAPECs comma separated)
        capec_entries = [c.strip() for c in capec_field.split(",") if c.strip()]
        capec_names = []
        for cid in capec_entries:
            # normalize e.g., CAPEC-13 or 13
            key = cid
            if cid.isdigit():
                key = f"CAPEC-{cid}"
            # Try few variants
            found = capec_lookup.get(key) or capec_lookup.get(cid.upper())
            capec_names.append(found or "")

        enriched_rows.append({
            "ATTACK_ID": attack_id,
            "ATTACK_NAME": attack_name,
            "TACTICS": "; ".join(tactics) if tactics else "",
            "CAPEC_ID": capec_field,
            "CAPEC_NAME": "; ".join([n for n in capec_names if n])
        })

    df_out = pd.DataFrame(enriched_rows, columns=["ATTACK_ID", "ATTACK_NAME", "TACTICS", "CAPEC_ID", "CAPEC_NAME"])
    df_out.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")
    print(f"[+] Enriched CSV written: {OUTPUT_CSV} (rows: {len(df_out)})")

if __name__ == "__main__":
    try:
        enrich_csv(INPUT_CSV)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(2)
