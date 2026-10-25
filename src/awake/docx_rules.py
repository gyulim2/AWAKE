"""DOCX 정적 검사 — 알려진 악성 문서 기법이 있는지 규칙으로 확인한다.

예전에는 DOCX도 ML 모델로 판정했지만, 학습 데이터의 악성 샘플 940개 중 929개가 파싱에 실패한
상태(피처가 전부 결측)로 평균값 대체되어 학습됐고, 파일 생성 시각 하나로 96%가 구분되는 누수가
있었다. 그 데이터로는 신뢰할 수 있는 모델을 만들 수 없어, 근거를 설명할 수 있는 규칙 검사로 바꿨다.

검사 항목 (OOXML = ZIP 안의 XML)
  HIGH   외부 템플릿 인젝션      settings.xml.rels의 attachedTemplate가 외부 URL  (MITRE ATT&CK T1221)
  HIGH   원격 OLE/프레임 참조     External 대상인 oleObject·frame·subDocument 관계 (CVE-2017-0199 계열)
  HIGH   DDE 필드                본문 필드 코드에 DDE/DDEAUTO                   (T1559.002)
  HIGH   VBA 매크로              vbaProject.bin 존재                            (T1137 / T1204.002)
  MEDIUM 임베디드 OLE 객체        word/embeddings/ 안의 객체
  MEDIUM ActiveX 컨트롤          word/activeX/
  MEDIUM 확장자 위장              .docx인데 실제는 OLE(구형 .doc) 또는 ZIP이 아님
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field

HIGH, MEDIUM = "high", "medium"

# 압축 폭탄 방지: 검사하는 XML 하나당 읽는 최대 바이트, ZIP 항목 최대 개수
_MAX_XML_BYTES = 5 * 1024 * 1024
_MAX_ENTRIES = 5000

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_EXTERNAL_REL = re.compile(
    rb'<Relationship\b[^>]*\bType="[^"]*/(?P<type>\w+)"[^>]*\bTarget="(?P<target>[^"]*)"[^>]*\bTargetMode="External"'
    rb'|<Relationship\b[^>]*\bTargetMode="External"[^>]*\bType="[^"]*/(?P<type2>\w+)"[^>]*\bTarget="(?P<target2>[^"]*)"',
)
_DDE = re.compile(rb"\bDDE(AUTO)?\b", re.IGNORECASE)
_RISKY_EXTERNAL_TYPES = {b"oleObject", b"frame", b"subDocument", b"attachedTemplate"}


@dataclass
class Finding:
    level: str
    rule: str
    detail: str


@dataclass
class DocxReport:
    findings: list[Finding] = field(default_factory=list)

    @property
    def verdict(self) -> int:
        """HIGH 항목이 하나라도 있으면 1(악성), 아니면 0."""
        return 1 if any(f.level == HIGH for f in self.findings) else 0

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "findings": [vars(f) for f in self.findings],
        }


def _read_limited(z: zipfile.ZipFile, name: str) -> bytes:
    with z.open(name) as f:
        return f.read(_MAX_XML_BYTES)


def _iter_external_relationships(xml: bytes):
    for m in _EXTERNAL_REL.finditer(xml):
        rel_type = m.group("type") or m.group("type2")
        target = m.group("target") or m.group("target2")
        yield rel_type, target.decode("utf-8", "replace")


def analyze(data: bytes) -> DocxReport:
    report = DocxReport()
    add = report.findings.append

    if data.startswith(_OLE_MAGIC):
        add(Finding(MEDIUM, "extension_mismatch", ".docx 확장자지만 실제로는 OLE(구형 .doc) 형식"))
        return report

    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        add(Finding(MEDIUM, "extension_mismatch", ".docx 확장자지만 ZIP(OOXML) 형식이 아님"))
        return report

    with z:
        names = z.namelist()
        if len(names) > _MAX_ENTRIES:
            add(Finding(MEDIUM, "too_many_entries", f"ZIP 항목이 {len(names)}개로 비정상적으로 많음"))
            return report
        lower = [n.lower() for n in names]

        if any(n.endswith("vbaproject.bin") for n in lower):
            add(Finding(HIGH, "vba_macro", "VBA 프로젝트(vbaProject.bin) 포함"))

        embeddings = [n for n in names if n.lower().startswith("word/embeddings/")]
        if embeddings:
            add(Finding(MEDIUM, "embedded_object", f"임베디드 객체 {len(embeddings)}개: {', '.join(embeddings[:5])}"))

        if any(n.startswith("word/activex/") for n in lower):
            add(Finding(MEDIUM, "activex", "ActiveX 컨트롤 포함"))

        for name in names:
            if not name.endswith(".rels"):
                continue
            for rel_type, target in _iter_external_relationships(_read_limited(z, name)):
                if rel_type in _RISKY_EXTERNAL_TYPES:
                    rule = "template_injection" if rel_type == b"attachedTemplate" else "remote_object"
                    add(Finding(HIGH, rule, f"{name}: {rel_type.decode()} → {target}"))

        for name in ("word/document.xml", "word/footnotes.xml", "word/endnotes.xml"):
            if name in names:
                xml = _read_limited(z, name)
                # 필드 코드는 <w:instrText>나 w:fldSimple의 w:instr 속성에 들어 있다
                instr = b" ".join(re.findall(rb"<w:instrText[^>]*>([^<]*)</w:instrText>", xml)
                                  + re.findall(rb'w:instr="([^"]*)"', xml))
                if _DDE.search(instr):
                    add(Finding(HIGH, "dde_field", f"{name}에 DDE 필드 코드"))

    return report
