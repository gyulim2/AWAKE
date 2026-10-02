import json
import re
import shutil
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config

def process_email_result(analysis_json_path, predict_json_path, new_dir, mal_dir, output_json_path):
    """분석 결과(JSON)를 보고 해당 이메일 파일을 정상/악성 폴더로 이동하고, 악성이면 경고 메일 생성"""
    try:
        # 결과를 저장할 딕셔너리 생성
        result_data = {
            "analysis_label": None,
            "predict_label": None,
            "final_decision": None
        }

        # 두 개의 JSON 파일 읽기
        with open(analysis_json_path, 'r', encoding='utf-8') as analysis_file:
            analysis_result = json.load(analysis_file)
        
        predict_result = None  # predict_result 초기화
        if os.path.exists(predict_json_path):  # predict_json_path가 존재할 때만 열기
            with open(predict_json_path, 'r', encoding='utf-8') as predict_file:
                predict_result = json.load(predict_file)

        # predict_result는 dict(현재 형식) 또는 list(구형식)일 수 있다
        if isinstance(predict_result, list):
            predict_result = predict_result[0] if predict_result else None

        # 이동 대상은 분석 JSON에 기록된 "메일 파일"이다 (폴더 전체가 아님)
        email_file_path = analysis_result.get('email_file_path')
        if not email_file_path or not os.path.isfile(email_file_path):
            print(f"분석 대상 메일 파일을 찾을 수 없습니다: {email_file_path}")
            return

        # 두 파일에서 label 값을 확인 (predict_result가 없으면 analysis_result만 확인)
        analysis_label = analysis_result.get('label', 0)  # analysis_result는 딕셔너리로 바로 get 사용
        predict_label = predict_result.get('label', 0) if predict_result else 0  # predict_result가 없으면 0으로 설정

        # 결과를 딕셔너리에 저장
        result_data["analysis_label"] = analysis_label
        result_data["predict_label"] = predict_label

        # 하나라도 label이 1이면 악성으로 판단
        if analysis_label == 1 or predict_label == 1:
            print("악성으로 의심되는 메일입니다.")
            result_data["final_decision"] = "malicious"
            move_email_to_dir(email_file_path, mal_dir)  # 악성일 경우 mal 디렉토리로 이동
            create_warning_email(analysis_result.get('email_title', 'Unknown Title'), new_dir)  # 경고 메일 생성 및 new로 이동
        else:
            print("정상으로 판단되는 메일입니다.")
            result_data["final_decision"] = "normal"
            move_email_to_dir(email_file_path, new_dir)  # 정상일 경우 new 디렉토리로 이동

        # JSON 파일 삭제
        delete_json_files(analysis_json_path, predict_json_path)

        # 결과를 JSON 파일로 저장
        with open(output_json_path, 'w', encoding='utf-8') as json_file:
            json.dump(result_data, json_file, indent=4, ensure_ascii=False)
            print(f"처리 결과가 {output_json_path}에 저장되었습니다.")

    except Exception as e:
        print(f"이메일 결과 처리 중 오류 발생: {e}")

def move_email_to_dir(email_file_path, target_dir):
    """이메일을 지정된 디렉토리로 이동"""
    try:
        # target_dir 경로가 이미 존재하지 않으면 생성
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
        
        # 파일 이름을 유지하면서 이메일 파일을 target_dir로 이동
        shutil.move(email_file_path, os.path.join(target_dir, os.path.basename(email_file_path)))
        
        print(f"이메일이 {target_dir}로 이동되었습니다.")
    except Exception as e:
        print(f"이메일 이동 중 오류 발생: {e}")


def create_warning_email(malicious_email_subject, new_dir):
    """경고 메일을 생성하고 new 디렉토리로 이동"""
    try:
        safe_subject = re.sub(r'[^\w가-힣-]+', '_', str(malicious_email_subject))[:50]
        os.makedirs(new_dir, exist_ok=True)
        warning_email_path = os.path.join(new_dir, f"warning_email_{safe_subject}.eml")
        with open(warning_email_path, 'w', encoding='utf-8') as f:
            f.write(f"경고: 악성 이메일 감지\n이메일 제목: {malicious_email_subject}")
        print(f"경고 메일이 {new_dir} 디렉토리에 생성되었습니다.")
    except Exception as e:
        print(f"경고 메일 생성 중 오류 발생: {e}")

def delete_json_files(analysis_json_path, predict_json_path):
    """처리 완료된 후 JSON 파일을 삭제"""
    try:
        if os.path.exists(analysis_json_path):
            os.remove(analysis_json_path)
            print(f"{analysis_json_path} 파일이 삭제되었습니다.")
        
        if os.path.exists(predict_json_path):
            os.remove(predict_json_path)
            print(f"{predict_json_path} 파일이 삭제되었습니다.")
    except Exception as e:
        print(f"JSON 파일 삭제 중 오류 발생: {e}")

def main():
    process_email_result(
        str(config.GPT_RESULT_JSON), str(config.ML_RESULT_JSON),
        str(config.NEW_DIR), str(config.MAL_DIR), str(config.SUMMARY_JSON))

if __name__ == "__main__":
    main()
