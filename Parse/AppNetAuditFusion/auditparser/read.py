import re
import time
from io import TextIOWrapper
from typing import Generator

from Parse.AppNetAuditFusion.auditparser.utils import *


def extract_kv(s: str) -> dict[str, str]:
    """提取 k1=v1 k2=v2 ... 内容到字典"""
    pairs = s.split(" ")
    result = {}
    k=''
    v=''
    for p in pairs:
        if p.find("=") != -1:
            k, v = p.split("=", 1)
            result[k] = v.strip('"').strip(" ")  # 一些 value 前后会有这些额外字符
        elif k in result:
            # 有些值里面有空格，fuck it
            result[k] += ' ' + p
    return result


def readline(line: str) -> tuple[LineType, Line] | tuple[None, None]:
    """读取一行日志"""
    if line.find(": ") == -1:
        return None, None

    basics, params = line.split(": ", 1)  # type=xxx mxg=xxx, 剩余部分
    normal = params
    readable: str | None = None
    if params.find("") != -1:
        normal, readable = params.split("", 1)
    result = extract_kv(basics.strip())

    # msg=audit(*time*:*id*)
    msg_field = result["msg"]
    ts, _id = msg_field.split(":")
    result["timestamp"] = ts[6:]
    result["id"] = _id[:-1]
    del result["msg"]

    result.update(extract_kv(normal.strip()))

    # 可读参数部分
    if readable is not None:
        if result["type"] == "SOCKADDR":
            # SADDR={ saddr_fam=netlink nlnk-fam=16 nlnk-pid=0 }
            readable = readable.replace("SADDR={", "")
            readable = readable.replace("}", "")
            if readable.find("too short") == -1 and readable.find("unsupported") == -1:
                result.update(extract_kv(readable.strip()))
        else:
            result.update(extract_kv(readable.strip()))

    return result["type"], result  # type: ignore


def readline_ausearch(line: str) -> tuple[LineType, Line] | tuple[None, None]:
    """读取一行 ausearch 处理后的日志"""
    if line.find(": ") == -1:
        return None, None

    basics, params = line.split(": ", 1)  # type=xxx mxg=xxx, 剩余部分
    readable = params
    result = extract_kv(basics.strip())

    # msg=audit(*time*:*id*)
    msg_field = re.search(r"msg=(.*)", basics)
    if not msg_field:
        return None, None
    msg_field = msg_field[1]
    eid = msg_field.split(":")[-1].strip()[:-1]
    tm = ":".join(msg_field.split(":")[:-1])
    tm, ms = tm[6:].split(".")
    if '年' in tm:
        time_arr = time.strptime(tm, "%Y年%m月%d日 %H:%M:%S")
    else:
        try:
            time_arr = time.strptime(tm, "%m/%d/%Y %H:%M:%S")
        except:
            # tm 就是整数时间戳
            time_arr = None
    result["timestamp"] = f"{int(time.mktime(time_arr))}.{ms}" if time_arr else f"{tm}.{ms}"
    result["id"] = eid
    del result["msg"]

    # 可读参数部分
    if readable is not None:
        if result["type"] == "SOCKADDR":
            # SADDR={ saddr_fam=netlink nlnk-fam=16 nlnk-pid=0 }
            readable = readable.replace("SADDR={", "")
            readable = readable.replace("}", "")
            if readable.find("too short") == -1 and readable.find("unsupported") == -1:
                result.update(extract_kv(readable.strip()))
        else:
            result.update(extract_kv(readable.strip()))

    return result["type"], result  # type: ignore


def read(file: TextIOWrapper) -> Generator[Event, None, None]:
    """读取日志，生成包含几行的事件"""
    events = {}
    for l in file:
        tp, line = readline(l)
        if not tp or not line:
            continue
        eid = line["id"]
        if eid not in events:
            events[eid] = {}
        event = events[eid]
        if tp in event:
            event[tp].append(line)
        else:
            event[tp] = [line]
        # 不同 event 的行在一定范围内可能交错出现
        # 因此只能积攒一些 event 后再开始 yield
        if len(events) >= 1000:
            out_events = sorted(events.items())[:900]
            for eid, event in out_events:
                del events[eid]
                yield event
    for event in events.values():
        yield event


def read_ausearch(input: str) -> Generator[Event, None, None]:
    event = {}
    for l in input.splitlines():
        if l.startswith("--") and len(event):
            yield event
            event = {}
        tp, line = readline_ausearch(l)
        if tp not in event:
            event[tp] = []
        event[tp].append(line)
    if len(event):
        yield event
