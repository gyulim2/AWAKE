import io
import sys
import zipfile
from email.message import EmailMessage
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def clean_docx() -> bytes:
    return (FIXTURES / "sample.docx").read_bytes()


@pytest.fixture
def sample_pdf() -> bytes:
    return (FIXTURES / "sample.pdf").read_bytes()


def docx_with(base: bytes, extra: dict[str, bytes | str]) -> bytes:
    """정상 DOCX에 파일을 추가/교체한 변형을 만든다 (악성 기법 재현용)."""
    zin = zipfile.ZipFile(io.BytesIO(base))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename not in extra:
                zout.writestr(item, zin.read(item.filename))
        for name, data in extra.items():
            zout.writestr(name, data)
    return out.getvalue()


def make_email(subject="제목", body="본문", attachments=(), html=None) -> bytes:
    m = EmailMessage()
    m["Subject"] = subject
    m["From"] = "sender@example.com"
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    for filename, data in attachments:
        m.add_attachment(data, maintype="application", subtype="octet-stream", filename=filename)
    return bytes(m)
