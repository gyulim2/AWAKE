# A-Awake — 악성 이메일 탐지 시스템

KISIA 교육과정 4인 팀 프로젝트 (팀장). 메일 서버로 들어온 이메일을 **첨부파일 ML 분류**와 **LLM 문맥 분석** 두 갈래로 검사해, 악성으로 의심되면 격리하고 경고 메일을 보냅니다.

> 첨부 문서(PDF/DOCX)의 구조적 특징은 머신러닝으로, 제목·본문·첨부·링크가 서로 어울리는지는 LLM으로 본다는 점이 핵심 아이디어입니다.

## 동작 흐름

```
Maildir 수신 (inotify 감시)
   │
   ├─ PDF_DOCX_Predict.py   첨부 PDF/DOCX 추출 → 구조 피처 → ML 모델 → ML_results.json
   ├─ eml_llm.py            제목·본문·첨부 텍스트(PDF/DOCX/HWP)·링크 → LLM 분석 → GPT_result.json
   └─ move_email.py         두 결과 중 하나라도 악성(label=1)이면 mal/ 로 격리 + 경고 메일, 아니면 new/ 로 전달
```

| 단계 | 파일 | 설명 |
|---|---|---|
| 감시 | `src/Backend/C_monitoring.c` | inotify로 새 메일 생성 감지 후 분석 스크립트 실행 |
| 화면 | `src/Frontend/*.c` | GTK 기반 모니터링 UI |
| ML | `src/Python/Detection_Code/PDF_DOCX_Predict.py` | PDF는 PDFiD 구조 피처 + PyMuPDF 메타데이터, DOCX는 문단·이미지·임베디드 객체·VBA 매크로 등 |
| LLM | `src/Python/Detection_Code/eml_llm.py` | 메일 ↔ 첨부 ↔ 링크 연관성 분석, `VERDICT: MALICIOUS/BENIGN`으로 판정 수치화 |
| 후처리 | `src/Python/Detection_Code/move_email.py` | 판정 통합, 격리, 경고 메일 |
| 학습 | `src/Python/Train_Code/` | PDF(RandomForest), DOCX(앙상블) 학습 노트북 |

## 실행

```bash
pip install -r src/requirements.txt
export OPENAI_API_KEY=...            # 키는 환경변수로만 설정 (코드·저장소에 넣지 않음)
export AWAKE_MAILDIR=/path/to/Maildir # 선택: 기본값 /home/mail2/Maildir
python src/Python/Detection_Code/eml_llm.py
python src/Python/Detection_Code/PDF_DOCX_Predict.py <메일.eml>
python src/Python/Detection_Code/move_email.py
```

경로·모델명은 `src/Python/config.py`에서 환경변수로 바꿀 수 있습니다.

## 알려진 한계

- **학습/추론 전처리 불일치**: 학습 노트북은 스케일러·상수 피처 제거·SelectKBest를 거쳐 학습하지만, 현재는 모델(pkl)만 저장해서 추론 코드가 같은 전처리를 재현하지 못합니다. 전처리를 `sklearn.Pipeline`으로 묶어 함께 저장하고 재학습해야 정확도를 신뢰할 수 있습니다. (TODO)
- 모델 성능 수치(정확도 등)는 이 저장소에 검증된 형태로 기록돼 있지 않아 적지 않았습니다. (TODO)
- LLM 판정은 보조 지표이며, 프롬프트 인젝션이 담긴 메일에는 취약할 수 있습니다.

## 변경 이력 (정리 작업)

- 저장소에 커밋돼 있던 가상환경(`ML_Model/`, 파일 약 13,000개)과 컴파일된 바이너리 제거, `.gitignore` 추가
- 코드에 하드코딩돼 있던 API 키 제거 → `OPENAI_API_KEY` 환경변수 사용 (**노출된 키는 폐기 필요**)
- 폐기된 `openai.ChatCompletion`(0.x) → 현재 SDK(1.x) 클라이언트로 교체
- `move_email.py`: 분석된 메일 *파일*이 아니라 Maildir *폴더 전체*를 이동하던 문제, ML 결과 JSON을 읽지 못해 ML 판정이 항상 0이던 문제, LLM 판정 `label`이 항상 0으로 고정되던 문제 수정
- 첨부 추출: 첫 base64 블록만 정규식으로 잡던 방식 → `email` 모듈 사용, 고정 임시파일명 제거
- HWP 본문 추출: 섹션별 zlib 해제로 수정, DOCX 매크로 탐지(기존엔 항상 False) 구현
