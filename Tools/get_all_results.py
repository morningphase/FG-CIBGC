import os
import pandas as pd
import re
from parse_args import args
def check_and_extract_content(file_path):

    keys = ["Cluster_Number:", "Precision:", "Accuracy:", "Recall:", "F1-score:"]
    found = {key: False for key in keys}
    content_to_write = []

    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            for key in keys:
                if line.startswith(key):
                    found[key] = True
                    content_to_write.append(line.strip())
                    break


    if all(found.values()):
        return '\n'.join(content_to_write) + '\n\n'
    else:
        return ''


folder_path = '../results'
output_file = 'all_results.txt'

with open(output_file, 'w') as outfile:
    for filename in os.listdir(folder_path):
        if filename.endswith('.txt'):
            file_path = os.path.join(folder_path, filename)
            extracted_content = check_and_extract_content(file_path)
            if extracted_content:
                if 'ImageMagick-2016' in filename:
                    filename = filename.replace('ImageMagick-2016', 'ImageMagick_2016')
                if 'tf-idf' in filename:
                    filename = filename.replace('tf-idf', 'tf_idf')
                outfile.write(f'--- {filename} ---\n')
                outfile.write(extracted_content)

print(f"Completed. Check the file {output_file} for the results.")

def is_numeric_param(part):

    return all(c.isdigit() or c == '-' for c in part)


def parse_header_pool(header):


    parts = header.replace('---', '').replace('.txt', '').split('-')

    def is_number(s):
        try:
            float(s)
            return True
        except ValueError:
            return False

    embedding_method = parts[0]
    dataset = parts[1]
    pooling = parts[2]

    for i in range(3, len(parts)):
        if not is_number(parts[i]):
            embedding_params = '-'.join(parts[3:i])
            clustering_method = parts[i]
            clustering_params = '-'.join(parts[i + 1:])
            break

    return {
        '数据集': dataset,
        '嵌入方法': embedding_method,
        '嵌入参数': embedding_params,
        '聚类方法': clustering_method,
        '聚类参数': clustering_params,
        '池化方法': pooling
    }

def parse_header(header):
    """ 解析标题并提取信息 """
    # 移除前后的 --- 和 .txt，然后分割
    parts = header.replace('---', '').replace('.txt', '').split('-')

    # 判断每个部分是否为数字或小数
    def is_number(s):
        try:
            float(s)
            return True
        except ValueError:
            return False

    # 嵌入方法和数据集是前两个部分
    embedding_method = parts[0]
    dataset = parts[1]

    # 分别寻找嵌入参数和聚类参数的分界点
    for i in range(2, len(parts)):
        if not is_number(parts[i]):
            embedding_params = '-'.join(parts[2:i])
            clustering_method = parts[i]
            clustering_params = '-'.join(parts[i + 1:])
            break

    return {
        '数据集': dataset,
        '嵌入方法': embedding_method,
        '嵌入参数': embedding_params,
        '聚类方法': clustering_method,
        '聚类参数': clustering_params,
    }

def parse_segment(segment):
    """ 解析每个段落的标题和内容 """
    # 按照第一行（标题）和剩余行（内容）分割
    parts = segment.split('\n', 1)
    pool = False
    if len(parts) == 2:
        header, content = parts
        if args.parsepool != 'True':
            data = parse_header(header)
        else:
            data = parse_header_pool(header)
        if data:
            data['性能'] = content.strip()
            return data
    return None

def read_file(file_path):
    """ 读取文件并解析内容 """
    with open(file_path, 'r') as file:
        content = file.read()
        # 使用正则表达式匹配每个段落
        segments = re.findall(r'--- (.+?) ---\n(.*?)\n(?=---|$)', content, re.DOTALL)
        data = [parse_segment('--- ' + segment[0] + ' ---\n' + segment[1]) for segment in segments]
        return [d for d in data if d]  # 过滤掉空值

def write_to_excel(data, excel_path):
    """ 将数据写入Excel文件 """
    df = pd.DataFrame(data)
    df.to_excel(excel_path, index=False)

# 示例使用
excel_path = 'all_results.xlsx'  # 替换为你想要保存的Excel文件路径

data = read_file(output_file)
write_to_excel(data, excel_path)