"""메일 1통 분석 → 판정 통합 → (선택) 격리/전달.

    python -m awake.pipeline 메일.eml              # 분석 결과 JSON만 출력 (파일은 그대로)
    python -m awake.pipeline --deliver 메일파일     # 감시기가 쓰는 모드: 결과 저장 + 정상은 new/, 악성은 mal/로 이동

판정 규칙: 첨부 정적 분석(PDF 모델, DOCX 규칙) 중 하나라도 악성이면 악성.
판정을 못 낸 엔진(오류·미지원)은 결과에 이유와 함께 남기고 판정에서는 제외한다.
LLM은 판정 뒤에 호출되어 사람이 읽을 문맥 설명만 만든다 (판정에 영향 없음).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import sys
import time
import uuid
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path

from . import attachments, config, llm
from .mailparse import parse_email

MAX_EMAIL_BYTES = 30 * 1024 * 1024  # 이보다 큰 메일은 분석하지 않고 격리


def analyze_bytes(raw: bytes, use_llm: bool = True) -> dict:
    mail = parse_email(raw)
    att_results = [attachments.analyze(a) for a in mail.attachments]
    reasons = []
    for r in att_results:
        if r.get("verdict") != 1:
            continue
        if r["engine"] == "docx_rules":
            rules = ", ".join(sorted({f["rule"] for f in r["findings"] if f["level"] == "high"}))
            reasons.append(f"첨부 {r['filename']}: 악성 문서 기법 탐지 ({rules})")
        else:
            reasons.append(f"첨부 {r['filename']}: PDF 모델 악성 확률 {r['malicious_probability']:.2f}")
    decision = "malicious" if reasons else "normal"
    # 판정이 끝난 뒤 설명만 생성한다. LLM 출력은 decision/reasons를 바꾸지 않는다.
    explanation = (llm.explain(mail, decision, reasons) if use_llm
                   else {"status": "skipped", "explanation": "--no-llm"})

    return {
        "subject": mail.subject,
        "from": mail.sender,
        "links": mail.links,
        "attachments": att_results,
        "final_decision": decision,
        "reasons": reasons,
        "llm_explanation": explanation,
    }


def _warning_email(original_subject: str, result: dict) -> bytes:
    msg = EmailMessage()
    msg["From"] = "A-Awake <awake@localhost>"
    msg["To"] = "user@localhost"
    msg["Subject"] = f"[A-Awake 경고] 악성 의심 메일을 격리했습니다: {original_subject}"[:200]
    msg["Date"] = formatdate(localtime=True)
    lines = ["다음 메일이 악성으로 의심되어 격리되었습니다.", "",
             f"제목: {original_subject}", f"보낸 사람: {result['from']}", "", "판정 근거:"]
    lines += [f"  - {r}" for r in result["reasons"]]
    expl = result.get("llm_explanation") or {}
    if expl.get("status") == "ok":
        lines += ["", "문맥 설명 (LLM 생성, 참고용):", expl["explanation"]]
    msg.set_content("\n".join(lines))
    return bytes(msg)


def _maildir_name() -> str:
    """Maildir 규칙의 고유 파일명 (시각.고유값.호스트)."""
    return f"{int(time.time())}.{uuid.uuid4().hex}.{socket.gethostname().replace('/', '_')}"


def deliver(mail_path: Path, use_llm: bool = True) -> dict:
    raw_size = mail_path.stat().st_size
    if raw_size > MAX_EMAIL_BYTES:
        result = {"final_decision": "malicious", "reasons": [f"메일 크기 초과({raw_size} bytes): 분석하지 않고 격리"],
                  "subject": "", "from": ""}
    else:
        result = analyze_bytes(mail_path.read_bytes(), use_llm=use_llm)
    result["email_file"] = mail_path.name

    target = config.MAL_DIR if result["final_decision"] == "malicious" else config.NEW_DIR
    for d in (config.MAL_DIR, config.NEW_DIR, config.RESULT_DIR):
        d.mkdir(parents=True, exist_ok=True)

    (config.RESULT_DIR / f"{mail_path.name}.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    shutil.move(str(mail_path), str(target / mail_path.name))

    if target == config.MAL_DIR:
        # 다른 프로세스가 반쯤 쓴 파일을 읽지 않도록 임시 이름으로 쓴 뒤 rename (Maildir 관례)
        tmp = config.RESULT_DIR / f".{uuid.uuid4().hex}.tmp"
        tmp.write_bytes(_warning_email(result.get("subject", ""), result))
        os.replace(tmp, config.NEW_DIR / _maildir_name())
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="A-Awake 메일 1통 분석")
    ap.add_argument("mail", type=Path)
    ap.add_argument("--deliver", action="store_true", help="결과 저장 후 정상은 new/, 악성은 mal/로 이동")
    ap.add_argument("--no-llm", action="store_true", help="LLM 문맥 설명을 건너뜀 (오프라인 테스트용)")
    args = ap.parse_args(argv)

    if not args.mail.is_file():
        print(f"메일 파일이 없습니다: {args.mail}", file=sys.stderr)
        return 2
    if args.deliver:
        result = deliver(args.mail, use_llm=not args.no_llm)
    else:
        result = analyze_bytes(args.mail.read_bytes(), use_llm=not args.no_llm)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
