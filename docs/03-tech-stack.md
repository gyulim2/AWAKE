# 03. 기술 스택

| 영역 | 기술 | 어디에 썼나 | 선택 이유 |
|---|---|---|---|
| 감시 | C, Linux inotify | `awake_monitor.c` | 커널 이벤트로 새 메일을 즉시 감지. 폴더를 주기적으로 훑는 방식보다 지연·부하가 적다 |
| 프로세스 실행 | `fork` / `execvp` | 감시기 → 파이프라인 | 셸을 거치지 않아 파일명이 명령어로 해석될 여지가 없다 |
| GUI | GTK 3 (GLib `g_spawn`, `GIOChannel`) | `awake_gui.c` | 리눅스 데스크톱 기본 툴킷. 자식 프로세스 출력을 이벤트 루프에서 비동기로 읽을 수 있다 |
| 메일 처리 | Python `email` (policy.default), Maildir | `mailparse.py`, `pipeline.py` | 표준 라이브러리로 MIME·인코딩 처리. Maildir은 파일 단위라 원자적 이동(rename)이 쉽다 |
| HTML 처리 | BeautifulSoup | `mailparse.py` | HTML 본문에서 텍스트와 `href` 링크 추출 |
| PDF 분석 | PyMuPDF, pdfid | `pdf_features.py` | PyMuPDF로 메타데이터·페이지·텍스트, pdfid로 `/JS`·`/OpenAction` 같은 위험 키워드 개수 |
| 문서 텍스트 | pdfplumber, python-docx, olefile + zlib | `mailparse.py` | LLM에 보낼 첨부 본문 추출. HWP는 OLE 스트림을 직접 풀어 읽는다 |
| DOCX 분석 | `zipfile`, 정규식 | `docx_rules.py` | OOXML은 ZIP 안의 XML이라 외부 관계(.rels)·필드 코드·매크로 파일을 직접 확인할 수 있다 |
| 머신러닝 | scikit-learn RandomForest, imbalanced-learn SMOTE, Pipeline | `train_pdf.py`, `attachments.py` | 표 형태 피처에 강하고 피처 중요도를 볼 수 있다. Pipeline으로 전처리까지 한 파일에 저장 |
| LLM | OpenAI Chat Completions (기본 `gpt-4o-mini`) | `llm.py` | 규칙·모델로 표현하기 어려운 "문맥이 어색한 메일"을 판단 |
| 테스트 | pytest | `tests/` | 규칙·파싱·판정 흐름을 샘플 파일로 자동 검증 |
| CI | GitHub Actions, Make | `.github/workflows/ci.yml`, `Makefile` | 푸시마다 C는 `-Werror`로 빌드, Python은 테스트 실행 |

## 위협 지식 기반

DOCX 규칙은 실제 공격에서 쓰인 기법을 기준으로 골랐다.

| 규칙 | 참고 |
|---|---|
| 외부 템플릿 인젝션 | MITRE ATT&CK T1221 Template Injection |
| 원격 OLE 객체 | CVE-2017-0199 (RTF/OLE 원격 객체를 이용한 코드 실행) 계열 |
| DDE 필드 | MITRE ATT&CK T1559.002 Dynamic Data Exchange |
| VBA 매크로 | MITRE ATT&CK T1137 Office Application Startup, T1204.002 Malicious File |

PDF 피처는 pdfid의 키워드 목록(`/JS`, `/JavaScript`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile` 등)을 그대로 썼다. 이 키워드들은 PDF 악성코드 분석에서 1차 선별에 널리 쓰이는 지표다.

## 데이터

| 데이터 | 출처 | 규모 | 사용 여부 |
|---|---|---|---|
| PDF 피처 | contagio 정상/악성 PDF에서 추출 (`training/data/result_*.csv`) | 정상 103, 악성 298 (정리 후 102 / 296) | 사용 |
| DOCX 피처 | `training/data/legacy_docx/` | 정상 1,004, 악성 940 | **사용 안 함** — 결함 내용은 [04-decisions.md](04-decisions.md) ADR-01 |
