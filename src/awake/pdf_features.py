"""PDF 피처 추출 — 학습(training/train_pdf.py)과 추론(awake.ml)이 이 모듈 하나를 같이 쓴다.

피처 정의는 학습 데이터(training/data/result_*.csv)를 만든 원본 추출기
(training/notebooks_legacy/Ex_pdf_Feature.py)와 같게 맞췄다.
  - 일반 피처: PyMuPDF로 읽는 크기·메타데이터·페이지·암호화·임베디드 파일·텍스트 유무
  - 구조 피처: pdfid(Didier Stevens)가 세는 PDF 키워드 개수 (/JS, /OpenAction 등)

원본 CSV에서 상수였거나(xref length = 항상 -1) 학습 때 버린 컬럼(name, PDF 헤더, Not)은 쓰지 않는다.
"""
from __future__ import annotations

import os
import tempfile
import warnings

from .vendor import pdfid

GENERAL_FEATURES = [
    "pdfsize",
    "metadata size",
    "pages",
    "title characters",
    "isEncrypted",
    "embedded files",
    "contains text",
]

# pdfid 키워드. 출력 이름 '/Colors > 2^24'는 학습 CSV에서 '/Colors'로 저장돼 있었다.
PDFID_FEATURES = [
    "obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref",
    "/Page", "/Encrypt", "/ObjStm", "/JS", "/JavaScript", "/AA", "/OpenAction",
    "/AcroForm", "/JBIG2Decode", "/RichMedia", "/Launch", "/EmbeddedFile", "/XFA",
    "/Colors",
]

FEATURES = GENERAL_FEATURES + PDFID_FEATURES

# 원본 추출기는 텍스트가 100자를 넘으면 "Yes"였다.
_TEXT_THRESHOLD = 100

# 문자열 값 → 숫자 (학습 스크립트도 같은 매핑을 쓴다)
CONTAINS_TEXT_MAP = {"Yes": 1, "No": 0, "unclear": -1}
UNKNOWN = -1


class PdfFeatureError(Exception):
    """PDF가 아니거나 구조 분석에 실패한 경우."""


def _general_features(path: str) -> dict:
    import pymupdf  # 무거운 의존성이라 실제로 쓸 때만 불러온다

    try:
        doc = pymupdf.open(path)
    except Exception as e:  # 손상/비PDF
        raise PdfFeatureError(f"PyMuPDF로 열 수 없음: {e}") from e

    with doc:
        meta = doc.metadata or {}
        feats = {
            "pdfsize": os.path.getsize(path),
            "metadata size": len(str(meta).encode("utf-8")),
            "pages": doc.page_count,
            "title characters": len(meta.get("title") or ""),
            "isEncrypted": 1 if meta.get("encryption") else 0,
        }
        try:
            feats["embedded files"] = doc.embfile_count()
        except Exception:
            feats["embedded files"] = UNKNOWN

        text, has_text = "", "No"
        try:
            for page in doc:
                text += page.get_text()
                if len(text) > _TEXT_THRESHOLD:
                    has_text = "Yes"
                    break
        except Exception:
            has_text = "unclear"
        feats["contains text"] = CONTAINS_TEXT_MAP[has_text]
    return feats


def _pdfid_features(path: str) -> dict:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        xml = pdfid.PDFiD(path, allNames=False, extraData=False, disarm=False, force=False)
    root = xml.documentElement
    if root.getAttribute("IsPDF") != "True":
        raise PdfFeatureError(root.getAttribute("ErrorMessage") or "pdfid: PDF 헤더 없음")

    counts = {}
    for kw in xml.getElementsByTagName("Keyword"):
        name = kw.getAttribute("Name")
        if name.startswith("/Colors"):
            name = "/Colors"
        counts[name] = int(kw.getAttribute("Count") or 0)
    return {name: counts.get(name, 0) for name in PDFID_FEATURES}


def extract_from_path(path: str) -> dict:
    """PDF 파일 경로 → {피처명: 숫자}. 키 순서는 FEATURES와 같다."""
    feats = {**_general_features(path), **_pdfid_features(path)}
    return {name: feats[name] for name in FEATURES}


def extract_from_bytes(data: bytes) -> dict:
    """메일 첨부(bytes)용. 원본 파일명은 쓰지 않고 안전한 임시파일로 분석 후 지운다."""
    fd, path = tempfile.mkstemp(suffix=".pdf", prefix="awake-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return extract_from_path(path)
    finally:
        os.unlink(path)
