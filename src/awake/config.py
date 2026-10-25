"""경로·API 설정. 서버마다 다른 값은 환경변수로 덮어쓴다 (하드코딩 금지).

  AWAKE_MAILDIR      Maildir 루트                       (기본: ~/Maildir)
  AWAKE_MODEL_DIR    학습된 모델 폴더                    (기본: 저장소의 models/)
  AWAKE_LLM_MODEL    사용할 OpenAI 모델명                (기본: gpt-4o-mini)
  OPENAI_API_KEY     OpenAI API 키 (코드·저장소에 절대 넣지 말 것). 없으면 LLM 문맥 설명을 건너뛴다.
"""
import os
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parents[2]

MAILDIR = Path(os.environ.get("AWAKE_MAILDIR", Path.home() / "Maildir"))
INBOX_DIR = MAILDIR / "A-Awake"   # 분석 대기 메일 (감시 대상)
NEW_DIR = MAILDIR / "new"         # 정상 메일 전달 위치
MAL_DIR = MAILDIR / "mal"         # 악성 격리 위치
RESULT_DIR = MAILDIR / "awake-results"  # 메일별 분석 결과 JSON

MODEL_DIR = Path(os.environ.get("AWAKE_MODEL_DIR", REPO_DIR / "models"))
PDF_MODEL = MODEL_DIR / "pdf_model.joblib"

LLM_MODEL = os.environ.get("AWAKE_LLM_MODEL", "gpt-4o-mini")

# LLM에 보내는 텍스트 길이 상한 (비용·프롬프트 인젝션 표면 축소)
LLM_MAX_BODY_CHARS = 4000
LLM_MAX_ATTACHMENT_CHARS = 1000
LLM_MAX_LINKS = 30
