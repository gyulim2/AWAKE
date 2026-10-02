"""경로·API 설정. 서버마다 다른 값은 환경변수로 덮어쓴다 (하드코딩 금지).

  AWAKE_MAILDIR      Maildir 루트                  (기본: /home/mail2/Maildir)
  AWAKE_MODEL_DIR    학습된 모델(.pkl) 폴더         (기본: 이 파일 옆 Model/)
  AWAKE_WORK_DIR     첨부파일 추출 등 임시 작업 폴더 (기본: 시스템 임시 폴더/awake)
  OPENAI_API_KEY     OpenAI API 키 (코드나 저장소에 절대 넣지 말 것)
  AWAKE_LLM_MODEL    사용할 모델명                  (기본: gpt-4o-mini)
"""
import os
import tempfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

MAILDIR = Path(os.environ.get("AWAKE_MAILDIR", "/home/mail2/Maildir"))
INBOX_DIR = MAILDIR / "A-Awake"       # 분석 대기 메일
NEW_DIR = MAILDIR / "new"             # 정상 메일 전달 위치
MAL_DIR = MAILDIR / "mal"             # 악성 격리 위치
JSON_DIR = MAILDIR / "json"           # 분석 결과 JSON

GPT_RESULT_JSON = JSON_DIR / "GPT_result.json"
ML_RESULT_JSON = JSON_DIR / "ML_results.json"
SUMMARY_JSON = JSON_DIR / "result_summary.json"

MODEL_DIR = Path(os.environ.get("AWAKE_MODEL_DIR", BASE_DIR / "Model"))
DOCX_MODEL = MODEL_DIR / "docx_model.pkl"
PDF_MODEL = MODEL_DIR / "pdf_model.pkl"

PDFID_SCRIPT = BASE_DIR / "Module" / "pdfid.py"
WORK_DIR = Path(os.environ.get("AWAKE_WORK_DIR", Path(tempfile.gettempdir()) / "awake"))

LLM_MODEL = os.environ.get("AWAKE_LLM_MODEL", "gpt-4o-mini")
