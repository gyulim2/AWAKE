# training

| 경로 | 내용 |
|---|---|
| `train_pdf.py` | PDF 모델 학습·평가. 출력: `models/pdf_model.joblib`, `models/pdf_model_card.json` |
| `data/result_ben.csv`, `data/result_mal.csv` | PDF 피처 데이터 (contagio 정상·악성 PDF에서 추출) |
| `data/legacy_docx/` | 기존 DOCX 모델 학습 데이터. 악성 929/940건 파싱 실패 및 생성 시각 누수로 미사용, 검증 근거로 보존 ([ADR-01](../docs/05-decisions.md)) |
| `notebooks_legacy/` | 2024년 학습 노트북과 PDF 피처 추출 원본(`Ex_pdf_Feature.py`). 기록용이며 경로는 당시 환경 기준 |
