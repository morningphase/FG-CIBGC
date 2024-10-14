import openai
import time

# OpenAI API anonymous
openai.api_key = 'anonymous'

# 定义 instruction, label 和 example
instruction = (
    "Select <type>|<line#> pairs to form behavior\n"
    "units based on\ntimestamp and key\n"
    "common elements"
)

label = (
    "Behavior Unit:<Apache><line0>|<Net><line1>|<IM><line2>|<Audit><line3>|<Audit><line4>"
)

example = (
    "<Apache><line0>[2024-05-07 18:21:08]POST /imagemagic.php 183.173.132.67 166.111.82.74 80\n"
    "<Net><line1>[2024-05-07 18:21:08]183.173.132.67 166.111.82.74 80 POST /imagemagic.php filename=\"input.png\"\n"
    "<IM><line2>[2024-05-07 18:21:08]convert /var/www/html/uploads/input.png output.png\n"
    "<Audit><line3>[2024-05-07 18:21:08]apache2 sys_openat /var/www/html/uploads/input.png\n"
    "<Audit><line4>[2024-05-07 18:21:08]convert sys_openat output.png\n"
)

# 构建请求体
prompt = f"{instruction}\n\n{label}\n\n{example}"

# warmup 操作 - 发送与 instruction 相关的请求以预热模型
warmup_instruction = (
    "Select <type>|<line#> pairs "
    "to form behavior units based on timestamp and key common elements."
)
_ = openai.ChatCompletion.create(
    model="gpt-3.5-turbo",
    messages=[{"role": "user", "content": warmup_instruction}],
    max_tokens=50
)

# 如果需要，可以在warmup之后等待一段时间
time.sleep(1)

# 调用 OpenAI 的 GPT-3.5 模型
response = openai.ChatCompletion.create(
    model="gpt-3.5-turbo",
    messages=[
        {"role": "user", "content": prompt}
    ],
    temperature=0.7,  # 可调节的温度参数
    max_tokens=150,   # 响应的最大token数
)

# 输出响应结果
print(response['choices'][C_0]()['message']['content'])
