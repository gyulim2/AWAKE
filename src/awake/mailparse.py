"""EML 파싱: 제목·본문·첨부·링크 추출, 첨부 텍스트 추출(LLM 문맥 분석용)."""
from __future__ import annotations

import io
import re
import zlib
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


@dataclass
class Attachment:
    filename: str
    content_type: str
    data: bytes

    @property
    def ext(self) -> str:
        name = self.filename.lower()
        return name[name.rfind("."):] if "." in name else ""


@dataclass
class ParsedEmail:
    subject: str
    sender: str
    body: str
    attachments: list[Attachment] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


def _decode(part) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:  # 알 수 없는 charset 이름
        return payload.decode("utf-8", errors="replace")


def parse_email(raw: bytes) -> ParsedEmail:
    from bs4 import BeautifulSoup

    msg = BytesParser(policy=policy.default).parsebytes(raw)
    body_parts, links, attachments = [], [], []

    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition == "attachment" or (filename and disposition != "inline"):
            attachments.append(Attachment(filename or "unnamed", part.get_content_type(),
                                          part.get_payload(decode=True) or b""))
            continue

        ctype = part.get_content_type()
        if ctype == "text/plain":
            text = _decode(part)
            body_parts.append(text)
            links += _URL_RE.findall(text)
        elif ctype == "text/html":
            soup = BeautifulSoup(_decode(part), "html.parser")
            links += [a["href"] for a in soup.find_all("a", href=True)]
            text = soup.get_text(" ", strip=True)
            body_parts.append(text)
            links += _URL_RE.findall(text)

    return ParsedEmail(
        subject=str(msg.get("subject", "")),
        sender=str(msg.get("from", "")),
        body="\n".join(p for p in body_parts if p).strip(),
        attachments=attachments,
        links=list(dict.fromkeys(l.strip() for l in links if l.strip())),  # 중복 제거, 순서 유지
    )


# ---------------------------------------------------------------- 첨부 텍스트 추출

def attachment_text(att: Attachment, limit: int) -> str:
    """LLM에 보낼 첨부 본문 앞부분. 지원하지 않는 형식이면 빈 문자열."""
    try:
        if att.ext == ".pdf":
            text = _pdf_text(att.data, limit)
        elif att.ext == ".docx":
            text = _docx_text(att.data)
        elif att.ext == ".hwp":
            text = _hwp_text(att.data)
        else:
            return ""
    except Exception:
        return ""
    return text[:limit]


def _pdf_text(data: bytes, limit: int) -> str:
    import pdfplumber

    out = ""
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        for page in pdf.pages:
            out += (page.extract_text() or "") + "\n"
            if len(out) >= limit:
                break
    return out


def _docx_text(data: bytes) -> str:
    from docx import Document

    return "\n".join(p.text for p in Document(io.BytesIO(data)).paragraphs)


def _hwp_text(data: bytes) -> str:
    """HWP 5.x 본문: BodyText/SectionN 스트림을 각각 zlib 해제한 뒤 UTF-16LE로 읽는다.
    (레코드 헤더 등 제어 문자가 섞이지만 LLM 문맥 분석용으로는 충분하다)"""
    import olefile

    ole = olefile.OleFileIO(io.BytesIO(data))
    sections = sorted((e for e in ole.listdir() if e[0] == "BodyText" and len(e) == 2),
                      key=lambda e: int(re.sub(r"\D", "", e[1]) or 0))
    texts = []
    for entry in sections:
        raw = ole.openstream(entry).read()
        try:
            raw = zlib.decompress(raw, -zlib.MAX_WBITS)
        except zlib.error:
            pass  # 압축되지 않은 문서
        texts.append(raw.decode("utf-16le", errors="replace"))
    return "\n".join(texts)
