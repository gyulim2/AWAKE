# 06. 테스트 결과

| 항목 | 내용 |
|---|---|
| 기준 | 2026-10-25, `cleanup` 브랜치 |
| 환경 | Linux, Python 3.13, GCC, GTK 3.24.41, 2 vCPU |
| CI | GitHub Actions `ci.yml`: C 빌드(`-Werror`) 후 pytest, 통과 |

## 1. 자동 테스트

```bash
pip install -r requirements-dev.txt
python -m pytest -q          # 28 passed
```

| 모듈 | 테스트 수 | 검증 항목 |
|---|---|---|
| `docx_rules` | 11 | 정상 문서 무탐지 / `template_injection`, `remote_object`(속성 순서 변형 포함), `dde_field`, `vba_macro` HIGH 판정 / 외부 하이퍼링크, 내부 템플릿, `<w:t>` 내 "DDE" 문자열 비탐지 / `embedded_object` MEDIUM 한정 / OLE 매직·비ZIP `extension_mismatch` |
| `llm` | 6 | 최종 행 판정 파싱, 응답 중간 판정 문구 무시, 빈 응답·None 처리, 호출마다 다른 구분자 생성, 첨부·링크 부재 시 생략, API 키 부재 시 생략 |
| `mailparse` | 3 | 평문·HTML 본문과 `href`·평문 URL 추출, 첨부 존재 시에도 링크 추출, URL 중복 제거 |
| `pdf_features`, `attachments`, `pipeline` | 8 | 28개 피처 순서·타입, 비PDF 예외, 저장 모델과 추출기 피처 목록 일치, 손상 PDF `status: error`, 정상·악성 판정, `deliver()`의 이동·결과 JSON·경고 메일 생성 |
| **합계** | **28** | **전부 통과** |

**테스트 데이터 설계**: 저장소에 실제 악성 표본을 두지 않는다. 정상 DOCX(`tests/fixtures/sample.docx`)의 ZIP 파트를 테스트 실행 중 수정해 공격 기법별 변형을 생성한다(`tests/conftest.py`의 `docx_with()`). 탐지 로직은 검증하되 저장소가 악성코드 배포 경로가 되지 않는다.

## 2. 빌드

```bash
make        # CFLAGS: -O2 -Wall -Wextra -Werror -std=c11
```

| 대상 | 경고 | 결과 |
|---|---|---|
| `build/awake_monitor` | 0 | 성공 |
| `build/awake_gui` | 0 | 성공 |

## 3. 통합 시험

임시 Maildir(`AWAKE_MAILDIR`)에서 `build/awake_monitor`를 실제 실행했다.

| ID | 절차 | 기대 결과 | 결과 |
|---|---|---|---|
| IT-01 | 감시 시작 전 정상 메일 적재 | 시작 직후 처리, `new/` 이동, 결과 JSON 생성 | 통과 |
| IT-02 | 외부 템플릿 인젝션 DOCX 첨부 메일을 `tmp` 기록 후 `rename(2)`로 배달 | `IN_MOVED_TO` 감지, `mal/` 격리, `new/`에 경고 메일, `findings`에 `template_injection`과 대상 URL | 통과 |
| IT-03 | 처리 대기 중 `SIGTERM` | 종료 코드 0, "감시 종료" 출력 | 통과 |

## 4. PDF 모델 평가

`python training/train_pdf.py` → `models/pdf_model_card.json`

| 설정 | 값 |
|---|---|
| 데이터 | 정상 102, 악성 296 |
| 검증 | `RepeatedStratifiedKFold(n_splits=5, n_repeats=5, random_state=42)`, 25회 |
| 누수 통제 | SMOTE를 Pipeline 내부에 두어 학습 fold에만 적용 |

| 지표 | 평균 | 표준편차 |
|---|---|---|
| Accuracy | 0.818 | 0.050 |
| Balanced accuracy | 0.745 | 0.061 |
| Precision (악성) | 0.866 | 0.031 |
| Recall (악성) | 0.894 | 0.051 |
| F1 (악성) | 0.879 | 0.035 |
| ROC-AUC | 0.846 | 0.047 |

동일 코드로 재학습 시 모든 지표가 일치함을 확인했다.

**분석**:
- 악성 재현율(0.894) 대비 균형 정확도(0.745)가 낮다. 정상 클래스 재현율이 약 0.60으로 추정되며(균형 정확도 = 두 클래스 재현율 평균), 정상 PDF 오탐률이 높다.
- 중요도 상위 피처가 `pdfsize`, `pages`, 객체 수이고, 악성 표본의 `/JS` 출현율이 4.7%에 그친다. 공격 특성이 아닌 표본 출처 특성을 학습했을 가능성이 있다. 상세는 [03-detection-engines.md](03-detection-engines.md#14-피처-분석).

**이전 평가와의 비교**: 기존 노트북의 Accuracy 0.825는 SMOTE를 분할 전에 적용해 테스트셋 120건 중 일부가 합성 표본인 상태의 단일 분할 결과다. 현재 Accuracy 0.818 ± 0.050은 원본 표본만으로 평가한 값이며 측정 방법상 신뢰도가 높다.

## 5. 처리 성능

`python -m awake.pipeline <메일> --no-llm` 프로세스 실행 시간 (7회 중앙값, 2 vCPU):

| 입력 | 시간 |
|---|---|
| 첨부 없음 | 390 ms |
| DOCX 첨부 (18 KB) | 413 ms |
| PDF 3.9 MB + DOCX 첨부 | 4,629 ms |

PDF 분석 구간 분해 (3.9 MB 표본, 동일 프로세스 내 측정):

| 단계 | 시간 | 비고 |
|---|---|---|
| pdfid 키워드 집계 | 2,266 ms | 순수 Python 바이트 스캔, 파일 크기에 비례 |
| 모델 로드 | 1,069 ms | 프로세스마다 반복 (ADR-03) |
| PyMuPDF 일반 피처 (최초 호출) | 499 ms | 라이브러리 초기화 포함 |

개선 방향: 모델 상주 로드(데몬화), pdfid 스캔 크기 상한 또는 네이티브 구현 대체. [07-audit.md](07-audit.md#6-잔여-리스크-및-향후-과제).

## 6. 미검증 항목

| 항목 | 사유 | 검증 계획 |
|---|---|---|
| LLM 실제 판정 품질 | API 키 미사용 | 공개 피싱 데이터셋으로 정확도·토큰 비용 측정 |
| GUI 화면 동작 | 헤드리스 환경 (빌드만 확인) | X11/Wayland 환경에서 시작·중지·결과 조회 수동 시험 |
| 실제 악성 메일 탐지율 | 실 표본 미보유 | 격리된 분석 환경에서 공개 악성 문서 표본으로 평가 |
