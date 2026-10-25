import subprocess
import os
import hashlib
import fitz
import pandas as pd

pdfid_shell = "python pdfid.py -s"
source_dir = "C:/Malware/DocMal/contagio/CLEAN_PDF_9000_files"
target_dir = "C:/Malware/DocMal/contagio/Result"

index = 0

df = pd.DataFrame(columns=('name', 'pdfsize', 'metadata size', 'pages','xref length','title characters','isEncrypted','embedded files','images','contains text'))

def file_to_hash(filepath):
    f = open(filepath, 'rb')
    data = f.read()
    hash = hashlib.sha1(data).hexdigest()
    return hash

# Function of general feature extraction
def general_feature(filename, filepath):
    localFP = filepath
    print('\nExtracting general features...', end='  ')
    try:
        doc = fitz.open(localFP)
    except:
        return 0

    try:
        Data_pdfsize = os.path.getsize(localFP)
    except:
        Data_pdfsize = -1
    
    try:
        Data_metadata_size = len(str(doc.metadata).encode('utf-8'))
    except Exception as e:
        print(f"Error getting metadata size for {filename}: {e}")
        Data_metadata_size = -1

    try:
        Data_Pages = doc.page_count
    except:
        Data_Pages = -1

    Data_xref_length = -1
    try:
        Data_title_char = len(doc.metadata['title'])
    except:
        Data_title_char = "Except"

    try:
        isEncrypted = doc.metadata['encryption']
        if(not isEncrypted):
            isEncrypted = 0
        else:
            isEncrypted = 1
    except:
        isEncrypted = -1
    Data_isEncrypted = isEncrypted
    
    try:
        Data_embedcount = doc.embfile_count()
    except:
        Data_embedcount = -1

    imgcount = 0
    try:
        imgcount = sum(len(doc.getPageImageList(k)) for k in range(len(doc)))
    except:
        imgcount = -1  
    Data_imgcount = imgcount

    Data_text = "No"
    text = ""
    try:
        for page in doc:
            text += page.get_text()
            if (len(text) > 100):
                Data_text = "Yes"
                break
    except:
        Data_text = "unclear"
        pass

    filename = file_to_hash(localFP)
    temp_dict = {'name':filename, 'pdfsize':Data_pdfsize, 'metadata size':Data_metadata_size, 'pages':Data_Pages,'xref length':Data_xref_length,'title characters':Data_title_char,'isEncrypted':Data_isEncrypted,'embedded files':Data_embedcount,'images':Data_imgcount,'contains text':Data_text}
    return temp_dict

# Remove garbage value at the end
def remove_last_newline(result_dict):
    last_key = list(result_dict.keys())[-1]
    last_value = result_dict[last_key]
    last_value = last_value.replace('\n\n', '')

    result_dict[last_key] = last_value
    return result_dict

# Function of structural feature extraction
def feature_struct_extract(low_struct):
    lowS = low_struct
    if lowS == "ShellError":
        print(lowS)
        return 0

    result_json = lowS.split('\n ')

    result_dict = {}

    for num, line in enumerate(result_json):
        if num == 0:
            continue
        key = line.split(" ")[0]
        value = line.split(" ")[-1]
        result_dict[key] = value

    temp_dict = remove_last_newline(result_dict)
    return temp_dict

# Run shell
# output: shell result [str]
def run_shell(command):
    try:
        result = subprocess.check_output(command, shell=True, text=True, encoding='utf-8')
        return result
    except:
        return "ShellError"

# Start Function of structural feature
def structural_feature(malpath):
    print('structural features...')
    # shell_code = pdfid_shell + ' ' + str(malpath)
    command = f'{pdfid_shell} "{malpath}"'
    low_struct = run_shell(command)
    temp_Struct = feature_struct_extract(low_struct)
    return temp_Struct
    
# Main Routine
def main_routine():
    for i, filename in enumerate(os.listdir(source_dir)):
        # Check file path and progress
        print("count:",i, filename, end=' ')
        
        # Make a file path
        malpath = os.path.join(source_dir, filename)

        # General feature extraction
        temp_General = general_feature(filename, malpath)

        # Handle the case where general_feature returns 0
        if temp_General == 0:
            print(f"Skipping {filename} due to an error in general_feature.")
            continue

        # Structural feature extraction
        temp_Struct = structural_feature(malpath)

        # Handle the case where structural_feature returns 0
        if temp_Struct == 0:
            print(f"Skipping {filename} due to an error in structural_feature.")
            continue

        # Merge two dictionary
        feature_dict = dict(temp_General, **temp_Struct)

        if i == 0:
            df = pd.DataFrame([feature_dict])
        else:
            df = pd.concat([df, pd.DataFrame([feature_dict])])
    return df

if __name__ == "__main__":
    df = main_routine()

    final_dir = os.path.join(target_dir, "result_contagio_benign-0130.csv")
    df.to_csv(final_dir, index=False)
    