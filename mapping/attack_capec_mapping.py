"""
MITRE ATT&CK ↔ CAPEC Mapping Generator
Author: jonghwan.kim
Description:
  - MITRE ATT&CK의 Technique ID를 CAPEC 공격패턴과 자동 매핑합니다.
  - 공식 MITRE CTI 저장소의 JSON을 실시간으로 불러와 처리합니다.
  - 결과는 CSV 파일로 저장됩니다.
"""

import requests
import pandas as pd
from datetime import datetime
import sys

def fetch_attack_to_capec_mapping():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    print(f"[+] Fetching data from {url}")
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[-] Failed to fetch ATT&CK data: {e}", file=sys.stderr)
        return pd.DataFrame([])

    mapping = []
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            external_refs = obj.get("external_references", [])
            if not external_refs:
                continue

            attack_id = None
            capec_ids = []
            attack_name = obj.get("name", "")

            for ref in external_refs:
                src = ref.get("source_name")
                if src == "mitre-attack":
                    attack_id = ref.get("external_id")
                elif src == "capec":
                    ext_id = ref.get("external_id")
                    if ext_id:
                        # Normalize CAPEC IDs (some may be like "CAPEC-xxx")
                        capec_ids.append(ext_id)

            if attack_id and capec_ids:
                for capec_id in capec_ids:
                    mapping.append({
                        "ATTACK_ID": attack_id,
                        "ATTACK_NAME": attack_name,
                        "CAPEC_ID": capec_id
                    })

    df = pd.DataFrame(mapping, columns=["ATTACK_ID", "ATTACK_NAME", "CAPEC_ID"])
    return df


def main():
    print("[+] Generating MITRE ATT&CK ↔ CAPEC mapping...")
    df = fetch_attack_to_capec_mapping()

    if df.empty:
        print("[-] No mappings found or failed to fetch data.", file=sys.stderr)
        return

    output_file = "mapping/attack_capec_mapping.csv"
    df.to_csv(output_file, index=False, encoding="utf-8-sig")
    print(f"[+] Total mappings found: {len(df)}")
    print(f"[+] Mapping saved to {output_file}")
    print(f"[✓] Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
