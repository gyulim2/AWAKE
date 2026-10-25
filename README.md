# A-Awake — 악성 이메일 탐지 시스템

KISIA 교육과정 4인 팀 프로젝트 (팀장). 메일 서버로 들어온 이메일을 **첨부파일 정적 분석**과 **LLM 문맥 분석** 두 갈래로 검사해, 악성으로 의심되면 격리하고 경고 메일을 보냅니다.

> 첨부 문서의 구조적 특징은 정적 분석(PDF는 머신러닝, DOCX는 악성 문서 기법 규칙)으로, 제목·본문·첨부·링크가 서로 어울리는지는 LLM으로 본다는 점이 핵심 아이디어입니다.

## 동작 흐름

```
메일 배달 (Maildir/A-Awake)
   │  inotify (IN_CLOSE_WRITE | IN_MOVED_TO)
   ▼
awake_monitor (C)  ── fork/execvp ──▶  python -m awake.pipeline --deliver <메일 파일>
                                          │
                                          ├─ 첨부 PDF   → 피처 추출(PyMuPDF + pdfid) → RandomForest 확률
                                          ├─ 첨부 DOCX  → 규칙 검사 (템플릿 인젝션, 원격 OLE, DDE, VBA 매크로 …)
                                          └─ 제목·본문·첨부 텍스트·링크 → LLM 판정 (OPENAI_API_KEY 있을 때)
                                          │
                                          ▼  하나라도 악성이면 악성
                              악성: mal/ 로 격리 + new/ 에 경고 메일     정상: new/ 로 전달
                              메일별 판정 근거: awake-results/<메일>.json
```

| 구성 | 파일 | 설명 |
|---|---|---|
| 감시기 | `src/monitor/awake_monitor.c` | 수신 폴더 감시, 메일 1통씩 파이프라인 실행 |
| GUI | `src/gui/awake_gui.c` | GTK 3. 감시 시작/중지, 실시간 로그, 판정 결과 목록 |
| 파이프라인 | `src/awake/pipeline.py` | 메일 1통 분석 → 판정 통합 → 격리/전달 |
| PDF | `src/awake/pdf_features.py`, `attachments.py` | 학습과 추론이 같은 추출기를 공유 |
| DOCX | `src/awake/docx_rules.py` | 알려진 악성 문서 기법 규칙 검사 |
| LLM | `src/awake/llm.py` | 문맥 일관성·피싱 정황 판정 |
| 학습 | `training/train_pdf.py` | 재현 가능한 PDF 모델 학습, 모델 카드 생성 |

## PDF 모델 성능

`training/train_pdf.py` 실행 결과 (`models/pdf_model_card.json`). 정상 102개 · 악성 296개, 5-fold × 5회 반복 층화 교차검증, SMOTE는 학습 fold 안에서만 적용했습니다.

| 지표 | 평균 ± 표준편차 |
|---|---|
| F1 (악성) | 0.879 ± 0.035 |
| 정밀도 / 재현율 (악성) | 0.866 / 0.894 |
| 균형 정확도 | 0.745 ± 0.061 |
| ROC-AUC | 0.846 ± 0.047 |

한계도 그대로 적습니다. 정상 PDF 샘플이 적어 정상 메일을 악성으로 오판하는 비율이 높은 편이고(균형 정확도가 정확도보다 낮은 이유), 모델이 `/JS`·`/OpenAction` 같은 의미 있는 지표보다 파일 크기·객체 수에 더 의존합니다. 정상/악성 샘플의 출처 차이를 학습했을 가능성이 있어, 실제 메일 환경 성능을 보장하지 않습니다.

## DOCX는 왜 규칙 기반인가

이전 버전의 DOCX 모델은 테스트 정확도 100%로 기록돼 있었지만, 데이터를 다시 검증해 보니 신뢰할 수 없는 수치였습니다.

- 악성 DOCX 940개 중 **929개가 파싱에 실패**해 내용 피처가 전부 비어 있었고, 학습 때 평균값으로 채워졌습니다.
- 파일 **생성 시각 하나만으로 96.4%가 구분**됐습니다. 정상/악성을 다른 날 내려받은 흔적을 학습한 것입니다.

이 데이터로는 정직한 모델을 만들 수 없어, 판정 근거를 설명할 수 있는 규칙 검사로 바꿨습니다. 원본 데이터는 검증 근거로 `training/data/legacy_docx/`에 남겨 두었습니다.

| 수준 | 규칙 | 근거 |
|---|---|---|
| HIGH | 외부 템플릿 인젝션 (`attachedTemplate` → 외부 URL) | MITRE ATT&CK T1221 |
| HIGH | 원격 OLE·프레임 참조 (External `oleObject`/`frame`/`subDocument`) | CVE-2017-0199 계열 |
| HIGH | DDE/DDEAUTO 필드 코드 | T1559.002 |
| HIGH | VBA 매크로 (`vbaProject.bin`) | T1137, T1204.002 |
| MEDIUM | 임베디드 OLE 객체, ActiveX, 확장자 위장(OLE/비ZIP) | 결과에 기록, 단독으로는 격리하지 않음 |

## 실행

```bash
pip install -r requirements.txt
make                                   # build/awake_monitor, build/awake_gui (GUI는 libgtk-3-dev 필요)

export AWAKE_MAILDIR=~/Maildir         # 기본값. 수신 폴더는 $AWAKE_MAILDIR/A-Awake
export OPENAI_API_KEY=...              # 선택. 없으면 LLM 단계는 건너뜀 (키는 환경변수로만)

scripts/run_monitor.sh                 # 서버: 감시기만 실행
scripts/run_gui.sh                     # 데스크톱: GUI에서 감시 시작/중지

# 메일 한 통만 분석해 보기 (파일은 옮기지 않음)
PYTHONPATH=src python -m awake.pipeline 메일.eml --no-llm
```

## 테스트

```bash
pip install -r requirements-dev.txt
python -m pytest -q        # 28개: DOCX 규칙, LLM 판정 파싱, 메일 파싱, PDF 추출·모델 일치, 격리 흐름
python training/train_pdf.py   # 모델 재학습 (같은 결과가 재현됨)
```

GitHub Actions(`.github/workflows/ci.yml`)가 푸시마다 C 코드를 `-Wall -Wextra -Werror`로 빌드하고 테스트를 실행합니다.

## 보안상 고려한 점

- 첨부는 원본 파일명을 쓰지 않고 임시파일로 분석 후 삭제, 감시기는 셸을 거치지 않고(`execvp`) 실행
- LLM 프롬프트 인젝션 완화: 메일 내용을 매번 바뀌는 구분자로 감싸고 '데이터로만 취급'하도록 지시, 판정은 응답 마지막 줄만 인정. 그래도 완전히 막을 수는 없으므로 LLM은 보조 지표입니다.
- DOCX 검사 시 ZIP 항목 수·읽는 크기 상한(압축 폭탄 방지), 30MB 초과 메일은 분석 없이 격리

## 변경 이력

**2026-10 전면 정리**
- 감시기가 존재하지 않는 `python_script.py`를 호출해 실제로는 분석이 실행되지 않던 문제 수정
- `system()`에 파일명을 이어 붙이던 셸 명령 주입 가능성 제거, 감시 경로 하드코딩 제거
- 분석 스크립트가 "폴더의 가장 최근 파일"을 고르던 방식 → 감시기가 넘긴 메일 1통을 정확히 분석
- DOCX 추론이 샘플 1개로 스케일러를 새로 학습해 입력이 항상 0이 되던 문제 → DOCX는 규칙 기반으로 교체
- PDF 학습/추론 피처 불일치(학습은 SelectKBest가 고른 10개, 추론은 다른 10개) → 공용 추출기 + Pipeline 저장
- 첨부가 여러 개여도 첫 번째만 보던 문제, 첨부가 있으면 링크를 무시하던 문제 수정
- 중복 GUI 시안 4개 → 하나로 통합, 커밋돼 있던 바이너리·zip 삭제
- 테스트 28개와 CI 추가

**2026-10-02 1차 정리**
- 커밋돼 있던 가상환경(파일 약 13,000개)과 바이너리 제거, 하드코딩된 API 키 제거(노출된 키는 폐기 필요), OpenAI SDK 1.x로 교체
