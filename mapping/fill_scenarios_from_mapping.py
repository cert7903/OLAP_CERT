#!/usr/bin/env python3
"""
fill_scenarios_from_mapping.py

시나리오명만 존재하는 merged_mapping_report.csv 파일을 입력받아
Sentence-BERT를 이용해 ATT&CK + CAPEC 매핑 결과에서 가장 유사한 항목을 찾아
ATTACK_ID, ATTACK_NAME, CAPEC_ID, CAPEC_NAME를 자동 유추합니다.

입력:
    mapping/merged_mapping_report.csv
    mapping/full_attack_capec_mapping.csv
출력:
    mapping/merged_mapping_report_filled.csv
"""

import pandas as pd
import numpy as np
from sentence_transformers import SentenceTransformer, util
from pathlib import Path

MODEL_NAME = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
INPUT_FILE = Path("mapping/merged_mapping_report.csv")
MAPPING_FILE = Path("mapping/full_attack_capec_mapping.csv")
OUTPUT_FILE = Path("mapping/merged_mapping_report_filled.csv")

def main():
    print("[+] Loading Sentence-BERT model...")
    model = SentenceTransformer(MODEL_NAME)

    print(f"[+] Loading mapping file: {MAPPING_FILE}")
    mapping_df = pd.read_csv(MAPPING_FILE, dtype=str).fillna("")
    mapping_df["text"] = mapping_df["ATTACK_NAME"].astype(str) + " " + mapping_df["CAPEC_NAME"].astype(str)

    print(f"[+] Encoding {len(mapping_df)} ATT&CK+CAPEC texts...")
    mapping_embeddings = model.encode(mapping_df["text"].tolist(), convert_to_tensor=True, show_progress_bar=True)

    print(f"[+] Loading scenario file: {INPUT_FILE}")
    scen_df = pd.read_csv(INPUT_FILE, dtype=str).fillna("")
    if "시나리오명" not in scen_df.columns:
        raise ValueError("입력 파일에 '시나리오명' 컬럼이 없습니다. 컬럼 이름을 확인하세요.")

    results = []
    for i, row in scen_df.iterrows():
        scenario = row["시나리오명"]
        if not scenario.strip():
            continue
        query_emb = model.encode(scenario, convert_to_tensor=True)
        sims = util.cos_sim(query_emb, mapping_embeddings)[0]
        top_idx = int(np.argmax(sims))
        best = mapping_df.iloc[top_idx]
        sim_score = float(sims[top_idx])
        results.append({
            "시나리오명": scenario,
            "ATTACK_ID": best["ATTACK_ID"],
            "ATTACK_NAME": best["ATTACK_NAME"],
            "CAPEC_ID": best["CAPEC_ID"],
            "CAPEC_NAME": best["CAPEC_NAME"],
            "SIMILARITY": round(sim_score, 4)
        })

    out_df = pd.DataFrame(results)
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(OUTPUT_FILE, index=False, encoding="utf-8-sig")
    print(f"[+] 결과 저장 완료: {OUTPUT_FILE}")
    print(f"[+] 총 {len(out_df)}건의 시나리오 매핑 완료!")

if __name__ == "__main__":
    main()
