# 01. 요구사항 명세

## 1. 개요

### 1.1 목적

Maildir 기반 메일 수신 환경에서 수신 메일을 자동 분석해, 악성 첨부 또는 피싱 정황이 있는 메일을 사용자 열람 전에 격리한다.

### 1.2 탐지 대상 위협

| 위협 | 공격 벡터 | 대응 엔진 |
|---|---|---|
| 악성 PDF | `/JavaScript`, `/OpenAction`, `/Launch`, 임베디드 파일을 이용한 실행 유도 | PDF 분류 모델 |
| 악성 OOXML 문서 | 외부 템플릿 인젝션(T1221), 원격 OLE 객체(CVE-2017-0199 계열), DDE(T1559.002), VBA 매크로(T1137) | DOCX 규칙 엔진 |
| 확장자 위장 | OLE 복합 문서 또는 비ZIP 파일을 `.docx`로 위장 | DOCX 규칙 엔진 |
| 피싱(문맥 불일치) | 발신자·제목·본문·첨부·링크 간 불일치, 긴급성 유도, 자격 증명 수집 링크 | LLM 문맥 분석 |

### 1.3 범위

| 구분 | 포함 | 제외 |
|---|---|---|
| 입력 | Maildir 수신 폴더로 배달된 RFC 5322 메시지 | MTA 구성, SMTP 단계 필터링 |
| 첨부 분석 | PDF·DOCX 정적 분석, PDF·DOCX·HWP 텍스트 추출 | 동적 분석(샌드박스 실행), 압축 파일 재귀 분석 |
| 링크 분석 | 본문 URL 추출 및 문맥 판단 | URL 접속, 평판 조회 |
| 출력 | 격리, 경고 메일, 판정 근거 JSON, GUI 조회 | 웹 관리 콘솔, 다중 사용자 |

## 2. 시스템 환경 및 제약

| 항목 | 내용 |
|---|---|
| 운영체제 | Linux (inotify 필요) |
| 런타임 | Python 3.11 이상, GCC, GTK 3 (GUI 사용 시) |
| 외부 의존 | OpenAI API (선택. 미설정 시 LLM 단계 생략) |
| 메일 저장 형식 | Maildir. 배달은 `tmp/` 기록 후 대상 폴더로 `rename(2)` |

## 3. 기능 요구사항

| ID | 요구사항 | 수용 기준 | 구현 |
|---|---|---|---|
| FR-01 | 수신 폴더 감시 | 파일 기록 완료(`IN_CLOSE_WRITE`) 또는 rename 유입(`IN_MOVED_TO`) 시점에만 분석 시작 | `awake_monitor.c` |
| FR-02 | 기존 적재 메일 처리 | 감시 시작 시 폴더 내 미처리 메일을 순차 처리 | `process_existing()` |
| FR-03 | 메일 파싱 | 제목, 발신자, `text/plain`·`text/html` 본문, 전체 첨부, `href` 및 평문 URL 추출 | `mailparse.parse_email()` |
| FR-04 | PDF 정적 분석 | 28개 피처 추출 후 악성 확률 산출, 임계값 0.5 | `pdf_features`, `attachments.analyze_pdf()` |
| FR-05 | DOCX 정적 분석 | 규칙별 등급(HIGH/MEDIUM)과 근거 위치(파트 경로, 대상 URL) 반환 | `docx_rules.analyze()` |
| FR-06 | LLM 문맥 분석 | 첨부 또는 링크가 있을 때만 호출, 응답 마지막 줄로 판정 | `llm.analyze()` |
| FR-07 | 판정 통합 | 엔진 판정의 논리합. 판정 불가(`None`)는 제외하되 사유 기록 | `pipeline.analyze_bytes()` |
| FR-08 | 격리·전달 | 악성은 `mal/`, 정상은 `new/`로 이동 | `pipeline.deliver()` |
| FR-09 | 경고 통지 | 격리 시 `new/`에 RFC 5322 형식 경고 메일 생성 | `pipeline._warning_email()` |
| FR-10 | 판정 근거 기록 | 메일별 결과를 `awake-results/<메일명>.json`으로 저장 | `pipeline.deliver()` |
| FR-11 | 운영 화면 | 감시기 실행·중지, stdout/stderr 실시간 표시, 결과 목록 조회 | `awake_gui.c` |
| FR-12 | 단건 분석 CLI | 파일 이동 없이 결과 JSON 출력, LLM 생략 옵션 | `python -m awake.pipeline` |

## 4. 비기능 요구사항

| ID | 분류 | 요구사항 | 검증 |
|---|---|---|---|
| NFR-01 | 보안 | 외부 입력(파일명, 메일 내용)이 셸 명령·파일 경로로 해석되지 않을 것 | `execvp` 인자 배열, 첨부는 `mkstemp` 임시 경로 사용 |
| NFR-02 | 보안 | 비밀값을 코드·저장소에 포함하지 않을 것 | `OPENAI_API_KEY` 환경변수 |
| NFR-03 | 보안 | LLM 프롬프트 인젝션에 의한 판정 조작 완화 | `test_llm.py` |
| NFR-04 | 보안 | 리소스 고갈 입력 방어 | ZIP 항목 5,000개, XML 5 MiB, 메일 30 MiB 상한 |
| NFR-05 | 가용성 | 단일 엔진 실패가 전체 분석을 중단시키지 않을 것 | 엔진별 `status: error` 기록 후 계속 |
| NFR-06 | 무결성 | 분석 실패 메일은 이동하지 않을 것 | 파이프라인 비정상 종료 시 감시기가 원위치 유지 |
| NFR-07 | 설명 가능성 | 격리 사유를 사람이 읽을 수 있는 형태로 기록 | `reasons`, `findings` 필드 |
| NFR-08 | 재현성 | 동일 데이터·코드로 재학습 시 동일 지표 | 고정 시드(42), 재실행 비교 |
| NFR-09 | 일관성 | 학습과 추론의 피처 정의가 동일할 것 | 공용 추출기, 모델 로드 시 피처 목록 검사 |
| NFR-10 | 이식성 | 환경 의존 경로 하드코딩 금지 | `AWAKE_MAILDIR`, `AWAKE_MODEL_DIR` |
| NFR-11 | 품질 | 경고 없는 C 빌드, 전체 테스트 통과 | CI: `-Wall -Wextra -Werror`, pytest |
