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

def fetch_attack_to_capec_mapping():
    # MITRE 공식 ATT&CK 데이터셋 (Enterprise)
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    print(f"[+] Fetching data from {url}")
    data = requests.get(url).json()

    mapping = []
    for obj in data["objects"]:
        if obj.get("type") == "attack-pattern" and "external_references" in obj:
            attack_id = None
            capec_ids = []
            attack_name = obj.get("name", "")

            for ref in obj["external_references"]:
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id")
                if ref.get("source_name") == "capec":
                    capec_ids.append(ref.get("external_id"))

            if attack_id and capec_ids:
                for capec_id in capec_ids:
                    mapping.append({
                        "ATTACK_ID": attack_id,
                        "ATTACK_NAME": attack_name,
                        "CAPEC_ID": capec_id
                    })

    df = pd.DataFrame(mapping)
    return df


def main():
    print("[+] Generating MITRE ATT&CK ↔ CAPEC mapping...")
    df = fetch_attack_to_capec_mapping()

    print(f"[+] Total mappings found: {len(df)}")

    output_file = f"mapping/attack_capec_mapping.csv"
    df.to_csv(output_file, index=False, encoding="utf-8-sig")
    print(f"[+] Mapping saved to {output_file}")

    # 저장 완료 시 날짜 표시
    print(f"[✓] Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
