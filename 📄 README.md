# 🧠 OLAP_CERT: MITRE ATT&CK ↔ CAPEC 매핑 프로젝트

이 프로젝트는 MITRE의 **ATT&CK 기술(Technique)** 과  
**CAPEC 공격 패턴(Attack Pattern)** 간의 관계를 자동으로 매핑합니다.  

보안 분석, 위협 헌팅, 공격 시나리오 자동화에 활용할 수 있습니다.

---
---

## 🚀 사용 방법

### 1️⃣ 환경 준비
Python 3.8 이상 설치 후, 필요한 라이브러리를 설치합니다.

```bash
pip install -r requirements.txt

```

## 📦 폴더 구조

OLAP_CERT/
├─ mapping/
│ ├─ attack_capec_mapping.py ← 매핑 자동 생성 스크립트
│ └─ attack_capec_mapping.csv ← 실행 시 생성되는 매핑 파일
├─ README.md
└─ requirements.txt

```
## 자동 업데이트

이 리포지토리는 GitHub Actions를 사용하여 매일 최신 MITRE ATT&CK 및 CAPEC 데이터를 내려받아
`mapping/attack_capec_mapping_with_tactic_and_desc.csv` 를 갱신합니다. 스케줄은 기본적으로 **KST 01:00**(UTC 16:00)로 설정되어 있으며,
변경을 원하면 `.github/workflows/update-mapping.yml` 의 cron 항목을 수정하세요.
