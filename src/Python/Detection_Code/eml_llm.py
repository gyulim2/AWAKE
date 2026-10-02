import os
import io
import pdfplumber
from docx import Document
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
import sys
import tempfile
from pathlib import Path
from openai import OpenAI

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config
import json
import re
import olefile
import zlib


_client = None


def ask_llm(prompt):
    """OpenAI 호출 (키는 OPENAI_API_KEY 환경변수에서 읽음)"""
    global _client
    if _client is None:
        if not os.environ.get("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY 환경변수가 설정되지 않았습니다.")
        _client = OpenAI()
    response = _client.chat.completions.create(
        model=config.LLM_MODEL,
        messages=[{"role": "system", "content": "You are an email security analyst."},
                  {"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content


VERDICT_INSTRUCTION = (
    "\nEnd your answer with exactly one final line: "
    "'VERDICT: MALICIOUS' or 'VERDICT: BENIGN'."
)


def parse_verdict(text):
    """LLM 답변 마지막의 VERDICT 줄을 1(악성)/0(정상)으로 변환. 판단 불가면 0."""
    m = re.findall(r"VERDICT:\s*(MALICIOUS|BENIGN)", text or "", re.IGNORECASE)
    return 1 if m and m[-1].upper() == "MALICIOUS" else 0


def get_latest_email_file(directory_path):
    """주어진 디렉토리에서 가장 최근에 생성된 파일을 찾음"""
    email_files = [os.path.join(directory_path, f) for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f))]
    
    # 파일이 존재하지 않으면 None 반환
    if not email_files:
        return None
    
    # 가장 최근 파일 선택 (수정 시간을 기준으로)
    latest_file = max(email_files, key=os.path.getmtime)
    return latest_file

def extract_email_body_recursive(part):
    """재귀적으로 파트를 탐색하여 본문 추출"""
    body = ""
    if part.is_multipart():
        for subpart in part.iter_parts():
            body += extract_email_body_recursive(subpart)  # 하위 파트를 재귀적으로 탐색
    else:
        # 인코딩이 없으면 기본값을 utf-8로 설정
        charset = part.get_content_charset() or 'utf-8'
        
        if part.get_content_type() == 'text/plain':
            body += part.get_payload(decode=True).decode(charset, errors="replace")
        elif part.get_content_type() == 'text/html':
            html_content = part.get_payload(decode=True).decode(charset, errors="replace")
            soup = BeautifulSoup(html_content, 'html.parser')
            body += soup.get_text()  # HTML을 텍스트로 변환
    return body

def extract_email_body(email_file_path):
    """이메일 파일에서 제목과 본문 추출"""
    try:
        with open(email_file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        # 이메일 제목 추출
        subject = msg['subject']

        # 이메일 본문 추출
        body = ""
        if msg.is_multipart():
            body = extract_email_body_recursive(msg)
        else:
            # 인코딩이 없을 경우 'utf-8' 기본값 사용
            charset = msg.get_content_charset() or 'utf-8'
            body = msg.get_payload(decode=True).decode(charset, errors="replace")

        return subject, body
    except Exception as e:
        print(f"이메일 파일 처리 중 오류 발생: {e}")
        return None, None

def extract_attachments(eml_file_path):
    """첨부파일을 추출하거나 본문에 있는 링크를 출력"""
    attachments = []
    links = []

    try:
        with open(eml_file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename() or "unnamed"
                    attachment_data = part.get_payload(decode=True)
                    
                    if filename.lower().endswith(".pdf"):
                        attachment_text = extract_pdf_with_pdfplumber(attachment_data)
                    elif filename.lower().endswith(".docx"):
                        attachment_text = extract_text_from_docx(attachment_data)
                    elif filename.lower().endswith(".hwp"):
                        attachment_text = extract_text_from_hwp(attachment_data)
                    else:
                        attachment_text = "(지원되지 않는 파일 형식)"

                    # 파일명과 텍스트를 딕셔너리로 저장
                    attachments.append({
                        'filename': filename,
                        'content': attachment_text
                    })

        if not attachments:
            print("첨부파일이 없습니다. 본문에서 링크를 검색합니다.")
            links = extract_links_from_email(msg)

    except Exception as e:
        print(f"첨부파일 처리 중 오류 발생: {e}")
    return attachments, links

def extract_pdf_with_pdfplumber(pdf_data):
    """pdfplumber를 사용해 PDF에서 텍스트를 추출"""
    try:
        with pdfplumber.open(io.BytesIO(pdf_data)) as pdf:
            text = ''
            for page in pdf.pages:
                text += (page.extract_text() or "") + "\n"
        return text
    except Exception as e:
        print(f"PDF 처리 중 오류 발생: {e}")
        return ""

def extract_text_from_docx(docx_data):
    """DOCX 파일에서 텍스트를 추출"""
    try:
        doc = Document(io.BytesIO(docx_data))
        doc_text = "\n".join([para.text for para in doc.paragraphs])
        
        return doc_text
    except Exception as e:
        print(f"DOCX 파일 처리 중 오류 발생: {e}")
        return ""

def extract_text_from_hwp(hwp_data):
    """HWP(5.x) 본문 텍스트 추출. BodyText/SectionN 스트림을 각각 zlib 해제한다."""
    try:
        ole = olefile.OleFileIO(io.BytesIO(hwp_data))
        sections = sorted(
            (e for e in ole.listdir() if e[0] == 'BodyText' and len(e) == 2),
            key=lambda e: int(re.sub(r'\D', '', e[1]) or 0))
        if not sections:
            return "HWP 파일에서 'BodyText' 데이터를 찾을 수 없습니다."
        texts = []
        for entry in sections:
            raw = ole.openstream(entry).read()
            try:
                raw = zlib.decompress(raw, -zlib.MAX_WBITS)
            except zlib.error:
                pass  # 압축되지 않은 문서
            texts.append(raw.decode('utf-16le', errors='replace'))
        return "\n".join(texts)
    except Exception as e:
        print(f"HWP 파일 처리 중 오류 발생: {e}")
        return ""


def extract_links_from_email(msg):
    """이메일 본문에서 링크 추출 (HTML의 href 우선, 없으면 평문의 URL 패턴)"""
    text_body = ""
    links = []

    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == 'attachment':
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        charset = part.get_content_charset() or 'utf-8'
        content = payload.decode(charset, errors="replace")
        if part.get_content_type() == 'text/html':
            soup = BeautifulSoup(content, 'html.parser')
            links += [a['href'] for a in soup.find_all('a', href=True)]
            text_body += soup.get_text()
        elif part.get_content_type() == 'text/plain':
            text_body += content

    if not links:
        links = re.findall(r'(https?://\S+)', text_body)

    return list(dict.fromkeys(links))  # 중복 제거(순서 유지)


# JSON 형식으로 반환
def generate_json_result(attachments, links):
    """첨부파일과 링크를 JSON 형식으로 변환"""
    result = {
        "attachments": [{"filename": att["filename"], "content": att["content"][:500]} for att in attachments],  # 첨부파일 요약
        "links_in_email": links if links else []
    }
    return json.dumps(result, ensure_ascii=False, indent=4)


# OpenAI API를 사용한 분석 함수
def analyze_email_content(email_title, email_body, attachments=None, links=None):
    """이메일 제목, 본문, 첨부파일을 분석하여 악성 여부를 판단"""
    
    if not attachments and not links:
        return [{"analysis": "이메일에 첨부파일과 링크가 없어 LLM 분석을 생략했습니다.", "verdict": 0}]
    
    results = []
    
    email_body_full = email_body  # 이메일 본문은 전체 길이로 전송
    
    if attachments:
        for attachment in attachments:
            # 첨부파일의 내용은 처음 500자까지만 전송
            attachment_body_limited = attachment['content'][:500]
            
            prompt = f"""
            Email Title: {email_title}
            Email Body (Full Text): {email_body_full}
            Attachment Filename: {attachment['filename']}
            Attachment Body (First 500 chars): {attachment_body_limited}
            
            Please analyze if the email title, the email body, and the attachment body are related. 
            Provide a brief summary of their relationship or similarity, and state if you think the email is malicious or suspicious.
            """
            
            # OpenAI API 호출
            result = ask_llm(prompt + VERDICT_INSTRUCTION)
            results.append({
                "filename": attachment['filename'],
                "analysis": result,
                "verdict": parse_verdict(result)
            })
    
    if links:
        prompt = f"""
        Email Title: {email_title}
        Email Body (Full Text): {email_body_full}
        Links: {", ".join(links)}
        
        Please analyze if the email title, the email body, and the links provided are related. 
        Provide a brief summary of their relationship or similarity, and if the links seem suspicious or malicious.
        """
        
        # OpenAI API 호출
        result = ask_llm(prompt + VERDICT_INSTRUCTION)
        results.append({
            "links": links,
            "analysis": result,
            "verdict": parse_verdict(result)
        })
    
    return results

def generate_json_summary(email_title, email_body, attachments, links, analysis_result, email_file_path):
    """결과를 간결한 JSON 형식으로 변환"""

    # 피처 요약
    attachments_summary = [{"filename": att["filename"], "content_summary": att["content"][:500]} for att in attachments]

    # 모든 분석 결과를 합치고, 하나라도 악성 판정이면 label=1
    malicious_assessment = "\n\n".join(r["analysis"] for r in analysis_result) \
        or "이메일의 제목, 본문 및 첨부파일 간의 연관성 분석 결과 없음."
    label = 1 if any(r.get("verdict") == 1 for r in analysis_result) else 0

    summary = {
        "email_title": email_title,
        "email_body_summary": email_body,  # 본문 전체
        "attachments": attachments_summary,  # 첨부파일 요약
        "links_in_email": links if links else ["링크 없음"],
        "malicious_assessment": malicious_assessment,  # GPT가 분석한 연관성 내용 반영
        "conclusion": "분석 결과를 바탕으로 이메일을 검토하세요.",
        "label": label,  # 1: LLM이 악성으로 판정, 0: 정상/판단 불가
        "email_file_path": email_file_path  # 이메일 파일 경로 추가
    }

    return json.dumps(summary, ensure_ascii=False, indent=4)


def display_email_and_analysis(subject, body, attachments, analysis_result):
    """이메일 제목, 본문, 첨부파일 제목 및 본문, 그리고 GPT 분석 결과를 출력"""
    print("\n=== 이메일 제목 ===")
    print(subject)
    
    print("\n=== 이메일 본문 ===")
    print(body)
    
    if attachments:
        for idx, attachment in enumerate(attachments):
            print(f"\n=== 첨부파일 {idx + 1} ===")
            print(f"제목: {attachment['filename']}")
            print(f"본문: {attachment['content'][:500]}")  # 첨부파일 본문 앞부분 500자 출력
    else:
        print("\n첨부파일이 없습니다.")
    
    print("\n=== GPT 분석 결과 ===")
    for result in analysis_result:
        print(result.get('analysis', result))

def analyze_latest_email(directory_path, output_json_path):
    """가장 최근의 이메일을 분석하고 OpenAI로 악성 여부 판단"""
    latest_email_file = get_latest_email_file(directory_path)
    if latest_email_file:
        subject, body = extract_email_body(latest_email_file)
        if body is None:
            print("이메일 본문을 읽지 못해 분석을 건너뜁니다.")
            return None
        attachments, links = extract_attachments(latest_email_file)
        
        # 분석 수행
        analysis_result = analyze_email_content(subject, body, attachments, links)
        
        # 이메일 제목, 본문, 첨부파일 본문 및 분석 결과 출력
        display_email_and_analysis(subject, body, attachments, analysis_result)
        
        # JSON 요약 저장
        json_summary = generate_json_summary(subject, body, attachments, links, analysis_result, latest_email_file)
        print(json_summary)

        with open(output_json_path, 'w', encoding='utf-8') as json_file:
            json_file.write(json_summary)
        
        return latest_email_file
    else:
        print("새로운 이메일 파일이 없습니다.")
        return None

def main():
    analyze_latest_email(str(config.INBOX_DIR), str(config.GPT_RESULT_JSON))

if __name__ == "__main__":
    main()
