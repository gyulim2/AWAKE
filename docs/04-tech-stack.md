# 04. 기술 스택

## 1. 구성 요약

| 계층 | 기술 | 버전 | 사용 위치 |
|---|---|---|---|
| 이벤트 감지 | Linux inotify, POSIX `fork`/`execvp`/`waitpid`, `sigaction` | 커널 API | `awake_monitor.c` |
| GUI | GTK 3, GLib (`g_spawn_async_with_pipes`, `GIOChannel`, `g_child_watch_add`) | 3.24 | `awake_gui.c` |
| 빌드 | GCC, GNU Make, pkg-config | C11 | `Makefile` |
| 메일 처리 | Python `email` (`policy.default`), BeautifulSoup | 표준 라이브러리, 4.15 | `mailparse.py` |
| PDF 분석 | PyMuPDF, pdfid | ≥ 1.24, 0.2.8 | `pdf_features.py` |
| 문서 텍스트 | pdfplumber, python-docx, olefile + zlib | 0.11, 1.2, 0.47 | `mailparse.py` |
| OOXML 분석 | `zipfile`, `re` | 표준 라이브러리 | `docx_rules.py` |
| 머신러닝 | scikit-learn, imbalanced-learn, pandas, joblib | 1.9.1, 0.14.2 (고정) | `train_pdf.py`, `attachments.py` |
| LLM | OpenAI Python SDK (Chat Completions) | ≥ 1.40 | `llm.py` |
| 테스트 | pytest | ≥ 8 | `tests/` |
| CI | GitHub Actions (ubuntu-24.04, Python 3.13) | | `.github/workflows/ci.yml` |

scikit-learn과 imbalanced-learn은 직렬화된 모델의 호환성을 위해 버전을 고정한다. 버전을 올리면 `training/train_pdf.py`로 재학습한다.

## 2. 계층별 선택 근거

### 2.1 이벤트 감지: inotify

| 대안 | 비교 |
|---|---|
| 주기적 폴링 (`listdir` 반복) | 감지 지연이 폴링 주기에 비례하고, 메일이 없어도 디스크 I/O 발생 |
| **inotify** | 커널이 이벤트를 푸시. `IN_MOVED_TO`로 Maildir의 원자적 배달 시점을 정확히 포착 |
| Python watchdog | 내부적으로 inotify 사용. 별도 상주 프로세스가 필요해 C 감시기와 역할이 같음 |

### 2.2 프로세스 실행: `fork`/`execvp`

`system(3)`은 `/bin/sh -c`로 문자열을 해석하므로 메타문자(`;`, `$()`, 백틱)가 포함된 파일명이 명령으로 실행될 수 있다. `execvp(3)`는 argv 배열을 그대로 전달해 파일명이 단일 인자로만 취급된다.

### 2.3 PDF 분석: PyMuPDF + pdfid

PyMuPDF는 렌더링 엔진(MuPDF) 기반으로 메타데이터·페이지·텍스트를 제공하고, pdfid는 PDF를 파싱하지 않고 바이트 스트림에서 키워드를 집계해 손상되거나 의도적으로 변형된 파일에서도 동작한다. 두 도구의 결과를 결합해 의미 수준 피처와 원시 구조 피처를 함께 확보한다.

### 2.4 분류기: RandomForest

| 고려 사항 | 판단 |
|---|---|
| 데이터 규모 | 398건. 심층 모델은 과적합 위험이 큼 |
| 피처 특성 | 스케일이 다른 개수형 피처. 트리 모델은 스케일링이 불필요 |
| 해석 | MDI 중요도로 의존 피처 확인 가능 (편향 분석에 활용) |
| 클래스 불균형 | 1:2.9. SMOTE를 학습 fold 내부에서만 적용 |

### 2.5 OOXML 분석: `zipfile` + 정규식

OOXML은 ZIP 컨테이너 안의 XML 파트와 관계(`.rels`)로 구성된다. 공격 기법 대부분이 관계 대상(`Target`)과 `TargetMode="External"` 조합 또는 특정 파트 존재로 식별되므로, 전체 XML 파싱 없이 대상 파트만 제한된 크기로 읽는다. XML 파서를 사용하지 않아 XXE 공격 표면이 없다.

### 2.6 LLM: OpenAI Chat Completions

규칙과 피처로 표현하기 어려운 의미적 불일치(제목과 첨부 내용 불일치, 업무 맥락에 맞지 않는 로그인 요청)를 판단한다. 판정을 구조화된 최종 행으로 강제하고, 실패 시 판정에서 제외하는 방식으로 비결정적 출력의 영향을 제한한다.

## 3. 위협 지식 매핑

| 탐지 항목 | MITRE ATT&CK / 취약점 |
|---|---|
| 외부 템플릿 인젝션 | T1221 Template Injection |
| 원격 OLE 객체 참조 | CVE-2017-0199 계열 (T1203 Exploitation for Client Execution) |
| DDE 필드 | T1559.002 Inter-Process Communication: Dynamic Data Exchange |
| VBA 매크로 | T1137 Office Application Startup, T1204.002 User Execution: Malicious File |
| PDF JavaScript·자동 실행 | T1204.002 User Execution: Malicious File |
| 피싱 링크·첨부 | T1566.001 Spearphishing Attachment, T1566.002 Spearphishing Link |

## 4. 데이터

| 데이터 | 경로 | 규모 | 상태 |
|---|---|---|---|
| PDF 피처 | `training/data/result_ben.csv`, `result_mal.csv` | 정상 103, 악성 298 (정제 후 102 / 296) | 사용 |
| DOCX 피처 | `training/data/legacy_docx/` | 정상 1,004, 악성 940 | 미사용 (결함 근거 보존용) |
| 테스트 문서 | `tests/fixtures/sample.pdf`, `sample.docx` | 각 1 | 악성 변형은 테스트 내에서 생성 |
