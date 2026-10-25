"""첨부파일 정적 분석: PDF → ML 모델, DOCX → 규칙 검사. 모든 첨부를 각각 분석한다."""
from __future__ import annotations

from functools import lru_cache

import pandas as pd

from . import config, docx_rules, pdf_features
from .mailparse import Attachment

# PDF 모델이 '악성'이라고 보는 확률 기준. 모델 카드의 교차검증 결과를 보고 조정한다.
PDF_THRESHOLD = 0.5


@lru_cache(maxsize=1)
def _load_pdf_model():
    import joblib

    bundle = joblib.load(config.PDF_MODEL)
    if bundle["features"] != pdf_features.FEATURES:
        raise RuntimeError("모델의 피처 목록이 현재 추출기와 다릅니다. training/train_pdf.py로 다시 학습하세요.")
    return bundle["pipeline"]


def analyze_pdf(data: bytes) -> dict:
    try:
        feats = pdf_features.extract_from_bytes(data)
    except pdf_features.PdfFeatureError as e:
        return {"engine": "pdf_ml", "status": "error", "verdict": None, "detail": str(e)}
    proba = float(_load_pdf_model().predict_proba(pd.DataFrame([feats]))[0][1])
    return {
        "engine": "pdf_ml",
        "status": "ok",
        "verdict": int(proba >= PDF_THRESHOLD),
        "malicious_probability": round(proba, 4),
        "features": feats,
    }


def analyze_docx(data: bytes) -> dict:
    report = docx_rules.analyze(data)
    return {"engine": "docx_rules", "status": "ok", **report.to_dict()}


def analyze(att: Attachment) -> dict:
    base = {"filename": att.filename, "size": len(att.data)}
    if att.ext == ".pdf":
        return {**base, **analyze_pdf(att.data)}
    if att.ext == ".docx":
        return {**base, **analyze_docx(att.data)}
    return {**base, "engine": None, "status": "unsupported", "verdict": None}
