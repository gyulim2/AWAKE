import json

import joblib
import pytest

from awake import attachments, config, pdf_features, pipeline
from conftest import docx_with, make_email


def test_extractor_returns_every_feature_in_order(sample_pdf):
    feats = pdf_features.extract_from_bytes(sample_pdf)
    assert list(feats) == pdf_features.FEATURES
    assert all(isinstance(v, (int, float)) for v in feats.values())


def test_non_pdf_raises():
    with pytest.raises(pdf_features.PdfFeatureError):
        pdf_features.extract_from_bytes(b"not a pdf at all")


def test_saved_model_matches_extractor():
    bundle = joblib.load(config.PDF_MODEL)
    assert bundle["features"] == pdf_features.FEATURES


def test_pdf_analysis_gives_probability(sample_pdf):
    r = attachments.analyze_pdf(sample_pdf)
    assert r["status"] == "ok" and 0.0 <= r["malicious_probability"] <= 1.0


def test_broken_pdf_is_reported_not_crashed():
    r = attachments.analyze_pdf(b"%PDF-1.4 broken")
    assert r["status"] == "error" and r["verdict"] is None


def test_clean_email_is_normal(clean_docx):
    result = pipeline.analyze_bytes(make_email(attachments=[("a.docx", clean_docx)]), use_llm=False)
    assert result["final_decision"] == "normal"


def test_macro_docx_makes_email_malicious(clean_docx):
    evil = docx_with(clean_docx, {"word/vbaProject.bin": b"\x00"})
    result = pipeline.analyze_bytes(make_email(attachments=[("a.docx", evil)]), use_llm=False)
    assert result["final_decision"] == "malicious"
    assert "vba_macro" in result["reasons"][0]


def test_deliver_moves_and_records(tmp_path, monkeypatch, clean_docx):
    for name in ("MAL_DIR", "NEW_DIR", "RESULT_DIR"):
        monkeypatch.setattr(config, name, tmp_path / name)
    evil = docx_with(clean_docx, {"word/vbaProject.bin": b"\x00"})
    mail = tmp_path / "123.mail:2,"
    mail.write_bytes(make_email(subject="견적서", attachments=[("a.docx", evil)]))

    pipeline.deliver(mail, use_llm=False)

    assert not mail.exists()
    assert (config.MAL_DIR / mail.name).exists()
    saved = json.loads((config.RESULT_DIR / f"{mail.name}.json").read_text(encoding="utf-8"))
    assert saved["final_decision"] == "malicious"
    warnings = list(config.NEW_DIR.iterdir())
    assert len(warnings) == 1 and b"A-Awake" in warnings[0].read_bytes()
