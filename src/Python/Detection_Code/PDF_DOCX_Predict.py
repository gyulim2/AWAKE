import sys
import os
import re
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config
from docx import Document
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
import joblib
import fitz  # PyMuPDF 라이브러리
import subprocess
import matplotlib.pyplot as plt  # 시각화를 위한 라이브러리
import json

def extract_and_save_attachment(eml_file_path):
    """EML에서 첫 번째 PDF/DOCX 첨부를 찾아 작업 폴더에 저장하고 경로를 반환 (없으면 None)."""
    with open(eml_file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    config.WORK_DIR.mkdir(parents=True, exist_ok=True)
    for part in msg.walk():
        if part.get_content_disposition() != 'attachment':
            continue
        ext = os.path.splitext(part.get_filename() or "")[1].lower()
        if ext not in (".pdf", ".docx"):
            continue
        out_path = config.WORK_DIR / f"extracted_attachment{ext}"  # 원본 파일명은 경로로 쓰지 않는다
        out_path.write_bytes(part.get_payload(decode=True) or b"")
        print(f"Attachment saved as {out_path}")
        return str(out_path)

    print("PDF/DOCX 첨부파일이 없습니다.")
    return None

# --------------------------------- ML ---------------------------------------

# PDFID 사용하여 구조적 피처 추출
def extract_pdfid_features(pdf_file_path):
    """pdfid 출력(키 + 개수)을 {키: 숫자}로 변환. 셸을 거치지 않고 인자 리스트로 실행한다."""
    try:
        result = subprocess.check_output(
            [sys.executable, str(config.PDFID_SCRIPT), "-s", str(pdf_file_path)],
            text=True, encoding='utf-8', timeout=60)
        features = {}
        for line in result.splitlines():
            parts = line.split()
            if len(parts) >= 2 and re.fullmatch(r'\d+', parts[-1]):
                features[parts[0]] = int(parts[-1])
        return features
    except Exception as e:
        print(f"Error running pdfid on {pdf_file_path}: {e}")
        return None

# PDF 피처 추출 함수 (일반적 피처 + 선택된 pdfid 피처)
def extract_pdf_features(pdf_file_path):
    selected_features = ['stream', 'endstream', 'xref', 'trailer', 
                         '/OpenAction', '/AcroForm', '/Launch']
    features = {}
    try:
        # 일반적인 PDF 피처 추출
        doc = fitz.open(pdf_file_path)
        features['metadata_size'] = len(str(doc.metadata).encode('utf-8'))
        features['title_characters'] = len(doc.metadata.get('title', ''))
        features['contains_text'] = 1 if any(page.get_text() for page in doc) else 0

        # pdfid로부터 구조적 피처 추출
        pdfid_features = extract_pdfid_features(pdf_file_path)
        if pdfid_features:
            for feature in selected_features:
                if feature in pdfid_features:
                    features[feature] = pdfid_features[feature]
                else:
                    features[feature] = 0  # 해당 피처가 없을 경우 0으로 처리

        return features
    except Exception as e:
        print(f"Error extracting PDF features: {e}")
        return None
    
def count_images(docx_file_path):
    try:
        doc = Document(docx_file_path)
        image_count = 0
        for rel in doc.part.rels.values():
            if "image" in rel.target_ref:
                image_count += 1
        return image_count
    except Exception as e:
        print(f"Error counting images in DOCX: {e}")
        return 0

# 2. 임베디드 객체 개수 세기
def count_embedded_objects(docx_file_path):
    try:
        doc = Document(docx_file_path)
        embedded_count = 0
        for rel in doc.part.rels.values():
            if "oleObject" in rel.target_ref or "package" in rel.target_ref:
                embedded_count += 1
        return embedded_count
    except Exception as e:
        print(f"Error counting embedded objects in DOCX: {e}")
        return 0

# 3. 매크로 확인
def has_macros(docx_file_path):
    """OOXML 패키지 안에 VBA 프로젝트(vbaProject.bin)가 있는지 확인"""
    try:
        with zipfile.ZipFile(docx_file_path) as z:
            return any(n.lower().endswith("vbaproject.bin") for n in z.namelist())
    except zipfile.BadZipFile:
        return False

# 4. 특수 문자 개수 세기
def count_special_characters(doc):
    special_chars = "!@#$%^&*()_+-={}[]:\";'<>?,./"
    count = sum(p.text.count(char) for p in doc.paragraphs for char in special_chars)
    return count

# 5. 숫자 문자 개수 세기
def count_numeric_characters(doc):
    numeric_chars = "0123456789"
    count = sum(p.text.count(char) for p in doc.paragraphs for char in numeric_chars)
    return count

# 6. 대문자 문자 비율 계산
def count_uppercase_characters(doc):
    count = sum(1 for p in doc.paragraphs for char in p.text if char.isupper())
    return count

# DOCX 피처 추출 함수
def extract_docx_features(docx_file_path):
    features = {}
    try:
        doc = Document(docx_file_path)
        features['file_size'] = os.path.getsize(docx_file_path)
        features['num_paragraphs'] = len(doc.paragraphs)
        features['word_count'] = sum(len(p.text.split()) for p in doc.paragraphs)
        features['image_count'] = count_images(docx_file_path)
        features['embedded_object_count'] = count_embedded_objects(docx_file_path)
        features['num_tables'] = len(doc.tables)
        features['has_macros'] = has_macros(docx_file_path)
        features['special_char_count'] = count_special_characters(doc)
        features['numeric_char_ratio'] = count_numeric_characters(doc) / (sum(len(p.text) for p in doc.paragraphs) or 1)
        features['uppercase_char_ratio'] = count_uppercase_characters(doc) / (sum(len(p.text) for p in doc.paragraphs) or 1)
        return features
    except Exception as e:
        print(f"Error extracting DOCX features: {e}")
        return None

# 기타 유틸리티 함수들 (생략)

# 피처 전처리 및 스케일링 함수 (DOCX에만 적용)
def preprocess_features(features):
    df = pd.DataFrame([features])
    numeric_features = df.select_dtypes(include=[np.number])
    imputer = SimpleImputer(strategy='mean')
    X_imputed = imputer.fit_transform(numeric_features)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_imputed)
    return X_scaled

# 모델 로드 및 예측
def predict_maliciousness(model, features, is_pdf=False):
    if not is_pdf:
        X_scaled = preprocess_features(features)
    else:
        X_scaled = pd.DataFrame([features]).to_numpy()
    
    prediction_proba = model.predict_proba(X_scaled)[0]
    prediction_label = model.predict(X_scaled)[0]
    return prediction_label, prediction_proba[1]

# 파일 처리 함수
def process_file(file_path, docx_model, pdf_model):
    file_extension = os.path.splitext(file_path)[1].lower()
    
    if file_extension == ".docx":
        features = extract_docx_features(file_path)
        if features:
            label, proba = predict_maliciousness(docx_model, features)
            return label, proba, features
    elif file_extension == ".pdf":
        features = extract_pdf_features(file_path)
        if features:
            label, proba = predict_maliciousness(pdf_model, features, is_pdf=True)
            return label, proba, features
    else:
        print(f"Unsupported file type: {file_extension}")
    return None, None, None

def visualize_prediction(file_path, label, proba, features, output_path):
    # 확률 막대 그래프
    plt.figure(figsize=(10, 8))
    plt.subplot(2, 1, 1)
    plt.bar(['Normal', 'Malicious'], [1 - proba, proba], color=['green', 'red'])
    plt.title(f"Prediction Result for {os.path.basename(file_path)}")
    plt.xlabel('Classification')
    plt.ylabel('Probability')

    # 피처 값 그래프
    plt.subplot(2, 1, 2)
    feature_names = list(features.keys())
    feature_values = [float(v) for v in features.values()]  # 모든 값을 float로 변환
    plt.barh(feature_names, feature_values, color='blue')
    plt.title("Extracted Features")
    plt.xlabel('Value')
    plt.tight_layout()

    # 그래프를 이미지로 저장
    output_file = os.path.join(output_path, 'output_image.png')
    plt.savefig(output_file)
    plt.close()  # 메모리 해제 위해 close 호출
    
    print(f"Visualization saved to {output_file}")

def pdf_docx_pred(attachment_path):
    output_dir = str(config.JSON_DIR)
    os.makedirs(output_dir, exist_ok=True)

    docx_model = joblib.load(config.DOCX_MODEL)
    pdf_model = joblib.load(config.PDF_MODEL)

    label, proba, features = process_file(attachment_path, docx_model, pdf_model)

    if label is not None:
        json_file_path = str(config.ML_RESULT_JSON)
        print(f"파일 '{attachment_path}' 예측 결과: 악성 여부 (1: 악성, 0: 정상): {label}, 악성일 확률: {proba:.4f}")
        visualize_prediction(attachment_path, label, proba, features, output_dir)
        # 파일별 예측 결과를 딕셔너리 형태로 저장
        result_data = {
            "label": int(label),  # move_email.py가 읽는 최종 판정값 (1: 악성, 0: 정상)
            "파일": attachment_path,
            "예측": {
                "악성 여부": int(label),
                "악성 확률": float(proba)
            },
            "피처": features
        }
        # 결과 리스트에 추가
        with open(json_file_path, 'w', encoding='utf-8') as json_file:
            json.dump(result_data, json_file, indent=4, ensure_ascii=False)
    else:
        print(f"파일 '{attachment_path}'의 피처 추출에 실패했습니다.")

# --------------------------------- ML ---------------------------------------

if __name__ == "__main__":
    # 명령줄 인수로부터 파일 경로를 받아오지만 무시
    print("ML Start")
    if len(sys.argv) != 2:
        print("Usage: python3 PDF_DOCX_Predict.py <input_file_path>")
        sys.exit(1)

    mail_path = sys.argv[1]

    attachment_path = extract_and_save_attachment(mail_path)
    if attachment_path is None:
        sys.exit(0)  # 분석할 첨부가 없으면 ML 단계는 건너뜀 (ML_results.json 미생성)

    print("pdf_docx_pred")
    pdf_docx_pred(attachment_path)
    
