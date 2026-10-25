# training

- `train_pdf.py` — PDF 모델 학습. 결과는 `models/pdf_model.joblib`, `models/pdf_model_card.json`
- `data/result_ben.csv`, `data/result_mal.csv` — PDF 피처 (정상: contagio CLEAN_PDF, 악성: contagio 악성 PDF에서 추출)
- `data/legacy_docx/` — 예전 DOCX 모델 학습 데이터. 악성 929/940개 파싱 실패·파일 시각 누수로 **사용하지 않음** (README의 "DOCX는 왜 규칙 기반인가" 참고)
- `notebooks_legacy/` — 2024년 프로젝트 당시 노트북과 PDF 피처 추출 원본(`Ex_pdf_Feature.py`). 기록용이며 실행 경로가 당시 환경 기준이다.
