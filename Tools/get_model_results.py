import pandas as pd
import glob
import os

# 准备空的DataFrame来存储结果
columns = ['算法名', '数据集名称', '参数名称', 'forward transfer', 'backward transfer']
df = pd.DataFrame(columns=columns)

# 遍历results文件夹下所有的.txt文件
for filepath in glob.glob('../results/*.txt'):
    # 从文件名中提取算法名，数据集名称和参数
    filename = os.path.basename(filepath)
    if 'minibathkm' in filename or 'incdbscan' in filename or 'DenStream' in filename or 'sa-minibathkm' in filename:
        continue
    if 'ImageMagick-2016' in filename:
        filename = filename.replace('ImageMagick-2016', 'ImageMagick_2016')
    parts = filename.split('-')
    algorithm_name = parts[0]
    dataset_name = parts[1]
    parameters = '-'.join(parts[2:-1])

    # 读取文件内容，寻找Forward transfer和Backward transfer的值
    with open(filepath, 'r') as file:
        for line in file:
            if 'Forward transfer' in line and 'Backward transfer' in line:
                # 分割字符串提取数值
                forward_transfer = line.split('Forward transfer: ')[1].split()[0]
                backward_transfer = line.split('Backward transfer: ')[1].strip()
                break

        # 使用pd.concat来添加数据
        new_row = pd.DataFrame({
            '算法名': [algorithm_name],
            '数据集名称': [dataset_name],
            '参数名称': [parameters],
            'forward transfer': [forward_transfer],
            'backward transfer': [backward_transfer]
        })
        df = pd.concat([df, new_row], ignore_index=True)

# 写入Excel文件
df.to_excel('results_fwt_bwt.xlsx', index=False, engine='openpyxl')

print('Excel文件已生成。')