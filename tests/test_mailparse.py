from awake.mailparse import parse_email
from conftest import make_email


def test_body_links_and_attachments():
    raw = make_email(
        subject="결제 확인",
        body="아래 링크 확인 https://pay.example.test/login?id=1 감사합니다",
        html='<p>클릭 <a href="http://phish.test/x">여기</a></p>',
        attachments=[("a.pdf", b"%PDF-1.4"), ("b.docx", b"PK")],
    )
    mail = parse_email(raw)
    assert mail.subject == "결제 확인"
    assert "링크 확인" in mail.body
    assert mail.links == ["https://pay.example.test/login?id=1", "http://phish.test/x"]
    assert [a.filename for a in mail.attachments] == ["a.pdf", "b.docx"]
    assert [a.ext for a in mail.attachments] == [".pdf", ".docx"]


def test_links_are_found_even_with_attachments():
    # 예전 코드는 첨부가 있으면 링크를 아예 보지 않았다
    mail = parse_email(make_email(body="http://a.test", attachments=[("x.pdf", b"%PDF")]))
    assert mail.links == ["http://a.test"]


def test_duplicate_links_are_removed():
    mail = parse_email(make_email(body="http://a.test http://a.test"))
    assert mail.links == ["http://a.test"]
