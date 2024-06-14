import psutil
import time
import pandas as pd

def get_process_by_pid(pid):
    try:
        return psutil.Process(pid)
    except psutil.NoSuchProcess:
        return None

def monitor_process(pid, interval=5):
    data = []
    elapsed_time = 0  # 初始化经过的时间
    try:
        process = get_process_by_pid(pid)
        if process is None:
            print(f"没有找到进程ID: {pid}")
            return

        print(f"监控进程: PID {pid}")
        total_memory = psutil.virtual_memory().total
        while True:
            process = get_process_by_pid(pid)
            if process:
                cpu_usage = process.cpu_percent(interval)
                memory_usage = process.memory_info().rss
                memory_percent = (memory_usage / total_memory) * 100  # 计算内存使用占比

                print(f"经过时间: {elapsed_time} 秒")
                print(f"CPU使用率: {cpu_usage}%")
                print(f"内存使用占比: {memory_percent:.2f}%")

                # 记录数据
                data.append({
                    "经过时间(秒)": elapsed_time,
                    "CPU使用率": cpu_usage,
                    "内存使用占比(%)": memory_percent
                })

                elapsed_time += interval  # 更新经过的时间
            else:
                print(f"进程ID {pid} 的进程已结束")
                break

            time.sleep(interval)

    except Exception as e:
        print(f"错误: {e}")

    finally:
        # 将数据转换为DataFrame并保存为Excel文件
        if data:
            df = pd.DataFrame(data)
            df.to_excel('process_monitor.xlsx', index=False)
            print("监控数据已保存到 'process_monitor.xlsx'")

# 使用方法
# 监控进程，每interval秒更新一次信息
monitor_process(25018, 1)
