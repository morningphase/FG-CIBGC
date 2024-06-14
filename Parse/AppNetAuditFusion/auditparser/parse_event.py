import binascii
import socket
import string
import struct
from datetime import datetime
import dataclasses
from typing_extensions import Self
from Parse.AppNetAuditFusion.auditparser.utils import *
import ipaddress



def parse_fd(result: ResultLine, file_man: FileMan, action: str, fd: int) -> None:
    """根据 fd 参数填写结果中文件 / 地址"""
    if action in {"sendto", "recvfrom"}:
        default = None
    elif action in ACTION_NET_FD_ARG:
        default = "addr"
    else:
        default = "file"
    path_or_addr = file_man.find(fd, default)

    if action in {"sendto", "recvfrom"} and not path_or_addr:
        # 使用的 fd 没有对应文件，应属于无连接 socket
        # 使用（先前找到的）SOCKADDR 中的地址
        return
        # 否则应采用 socket 本身已经 connect / bind 的地址
        # https://man7.org/linux/man-pages/man2/send.2.html
    if type(path_or_addr) is str:
        result["file"] = path_or_addr
    else:
        ip, port = path_or_addr
        result["ip"] = ip
        result["port"] = int(port)


def check_keep_apps(line: SyscallLine, keep_apps: set[str] | None) -> str | None:
    comm = line["comm"]
    if keep_apps is None or comm in keep_apps:
        return comm
    exe = line["exe"]
    for app in keep_apps:
        if app in exe:
            return app
    return None


@dataclasses.dataclass
class SockAddr:
    fam: str
    laddr: str
    lport: str
    path: str = ""


import ipaddress

# 定义内网IP地址的范围，包括10.0.0.0/8、172.16.0.0/12和192.168.0.0/16
private_networks = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]


def is_private_ip(ip: ipaddress.IPv4Address):
    # 判断输入的IP地址是否在任何一个内网范围内
    for network in private_networks:
        if ip in network:
            return True  # 如果在，返回True表示是内网地址

    return False  # 如果不在，返回False表示不是内网地址


def parse_sock_address(line: SockAddrLine) -> SockAddr:
    """从 SOCKADDR 行提取 SockAddr 参数"""

    def parse_saddr(saddr: str) -> SockAddr:
        """直接从 saddr 参数中提取所需内容"""

        if len(saddr) >= 16 and (
            saddr.startswith("0200")
            or saddr.startswith("0a00")
            or saddr.startswith("0A00")
        ):
            # raw struct, inet / inet6
            ip_ver = "inet" if saddr.startswith("0200") else "inet6"
            struct_saddr = binascii.unhexlify(saddr)
            port = struct.unpack(">H", struct_saddr[2:4])[0]
            match ip_ver:
                case "inet":
                    ip_addr = str(ipaddress.IPv4Address(struct_saddr[4:8]))
                case "inet6":
                    ip_addr = str(ipaddress.IPv6Address(struct_saddr[8:24]))
                    if ip_addr.startswith("::ffff:"):
                        # 尝试转换为 ipv4
                        try_v4_addr = ipaddress.IPv4Address(struct_saddr[20:24])
                        if is_private_ip(try_v4_addr):
                            ip_addr = f"::ffff:{try_v4_addr}"
            return SockAddr(ip_ver, ip_addr, str(port))

        elif " " in saddr:
            words = saddr.split(" ")
            fam = words[0]
            match fam:
                case "inet" | "inet6":
                    # inet host:{ip} serv:{port}
                    ip = words[1].split(":", 1)[-1]  # ipv6 有 :
                    port = words[2].split(":", 1)[-1]
                    return SockAddr(fam, ip, port)
                case "local":
                    # local path
                    return SockAddr(fam, "", "", words[1])
        return SockAddr("", "", "0")

    fam = line.get("fam", "")
    if not fam:
        fam = line.get("saddr_fam", "")
    sa = SockAddr(
        fam, line.get("laddr", ""), line.get("lport", ""), line.get("path", "")
    )
    if sa.laddr == "":
        sa = parse_saddr(line.get("saddr", ""))
    return sa


def parse_saddr_line(
    sa_line: SockAddrLine,
    file_man: FileMan,
    syscall_line: SyscallLine,
    action: str,
    ret: int,
    result: ResultLine,
) -> None:
    sa = parse_sock_address(sa_line)
    if sa.fam.startswith("inet"):
        # inet / inet6
        result["ip"] = sa.laddr
        result["port"] = int(sa.lport)
        path_or_addr = (sa.laddr, sa.lport)
    elif sa.fam == "local":
        result["file"] = sa.path
        path_or_addr = sa.path
    else:
        return

    # 对于成功的操作，绑定 fd 与地址
    if ret < 0:
        return
    if action in {"bind", "connect"}:
        # 参数 a0 的 fd 与地址绑定
        fd = int(syscall_line["a0"], 16)
        file_man.add(fd, path_or_addr)
    if action in {"accept", "accept4"}:
        # 返回与地址绑定的新 fd
        fd = ret
        file_man.add(fd, path_or_addr)


def decode_path_line_name(name: str) -> str:
    """检测 PATH 行中的 name 是否为 hex 编码，若是则解码"""
    if all(c in string.hexdigits for c in name):
        if len(name) % 2 != 0:
            name = "0" + name
        try:
            return bytes.fromhex(name).decode("utf8").strip()
        except:
            print(f"Failed to decode hex PATH name: {name}")
            return name
    return name


def parse_complex_path_lines(
    path_lines: list[PathLine],
    file_man: FileMan,
    event: Event,
    syscall_line: SyscallLine,
    action: str,
    result: ResultLine,
) -> str:
    # 获取 fd 与 path 映射
    p = ""
    for line in path_lines:
        nametype = line.get("nametype", "NORMAL")
        if action != "creat" and nametype == "CREATE":
            result["action"] = result["action"] + "_CREATE"
        name = decode_path_line_name(line["name"])
        if nametype == "PARENT":
            p = path_join(name, p)
        else:
            p = path_join(p, name)
    if not p.startswith("/"):
        # 没有在 PATH 行找到母路径，尝试从 CWD 获取
        if "CWD" in event:
            cwd = event["CWD"][0]["cwd"]
            p = path_join(cwd, p)
        if not p.startswith("/"):
            # 还没找到母路径，尝试从 dfd 获取
            dfd = int(syscall_line["a0"], 16)
            path_or_addr = file_man.find(dfd)
            if type(path_or_addr) is str:
                p = path_join(path_or_addr, p)
    result["file"] = p
    return p


def parse_path_lines_dual_paths(
    path_lines: list[PathLine], event: Event, result: ResultLine
) -> None:
    parent_path: str | None = None
    paths: list[tuple[str, str]] = []
    for line in path_lines:
        name = decode_path_line_name(line["name"])
        nametype = line.get("nametype", "NORMAL")
        if nametype == "PARENT":
            # 父路径，不直接写入日志
            parent_path = name
        else:
            paths.append((name, nametype))
    if parent_path is None and "CWD" in event:
        # 没有 nametype=PARENT，尝试从 CWD 行获取
        parent_path = event["CWD"][0]["cwd"]
    if parent_path is not None:
        # join 成绝对路径，已经是的不会受影响
        paths = [(path_join(parent_path, name), nametype) for name, nametype in paths]
    # 没有找到操作路径则跳过，留下没有 file 参数的日志
    if len(paths) > 0:
        results = []
        for name, nametype in paths:
            result_line = result.copy()
            result_line["file"] = name
            # 用 syscall_NAMETYPE 表示对 file 进行的实际操作
            result["action"] = result["action"] + f"_{nametype}"
            results.append(result_line)


@dataclasses.dataclass
class MmapFlags:
    prot_read: bool
    prot_write: bool
    map_shared: bool
    map_anonymous: bool

    @classmethod
    def parse(cls, prot: int, flags: int) -> Self:
        """
        解析 mmap 的 prot / flags 参数。
        - 返回 r, w, rw 代表可写或可读
        - 返回 None 表明不可读写
        """
        prot_read = bool(0x1 & prot)
        prot_write = bool(0x2 & prot)
        map_shared = bool(0x01 & flags)
        # map_private = bool(0x02 & flags)
        map_anonymous = bool(0x20 & flags)
        return cls(prot_read, prot_write, map_shared, map_anonymous)

    @classmethod
    def parse_ausearch(cls, prot: str, flags: str) -> Self:
        prot_read = "PROT_READ" in prot
        prot_write = "PROT_WRITE" in prot
        map_shared = "MAP_SHARED" in flags
        # map_private = bool(0x02 & flags)
        map_anonymous = "MAP_ANONYMOUS" in flags
        return cls(prot_read, prot_write, map_shared, map_anonymous)

    def mode(self) -> Literal["rw", "w", "r"] | None:
        if self.map_anonymous:
            # 不会落盘也对其他进程不可见
            return None
        writeable = self.prot_write and self.map_shared
        readable = self.prot_read
        if writeable and readable:
            return "rw"
        elif writeable:
            return "w"
        elif readable:
            return "r"
        return None


def parse_event(
    event: Event, keep_apps: set[str] | None, ausearch: bool = False
) -> list[ResultLine]:
    """处理一个事件"""
    results = as_type([{k: None for k in RESULT_KEYS}], list[ResultLine])
    result = results[0]

    # 读 SYSCALL 行
    if "SYSCALL" not in event:
        return []
    syscall_line = event["SYSCALL"][0]

    # 综合 comm 和 exe 参数检查程序名称
    # 对于要被过滤掉的事件，仍然通过下面的处理流程，因为可能获取文件相关信息
    process_name = check_keep_apps(syscall_line, keep_apps)
    filter_out = False
    if process_name is None:
        filter_out = True
        process_name = syscall_line["comm"]
    result["process_name"] = process_name

    # 读取一些很直接的字段
    time = datetime.fromtimestamp(float(syscall_line["timestamp"]))
    result["datetime"] = f"{time:%Y-%m-%d %H:%M:%S}.{time.microsecond // 1000:03d}000"
    result["timestamp"] = str(int(float(syscall_line["timestamp"]) * 1e6))
    ausearch = True
    action = syscall_line.get("SYSCALL", syscall_line["syscall"])
    if action.isdigit():
        action = SYSCALL_MAP.get(int(action), action)
    result["action"] = action

    result["user"] = syscall_line.get("UID", syscall_line["uid"])  # 用户名

    result["pid"] = int(syscall_line["pid"])
    pid = result["pid"]
    result["ppid"] = int(syscall_line["ppid"])
    ppid = result["ppid"]
    result["tid"] = int(syscall_line.get("tid", pid))
    raw_exit = syscall_line.get("exit", "0")
    try:
        ret = int(raw_exit)
        result["error"] = None
    except:
        # 被 ausearch 换成了错误码
        ret = -1
        result["error"] = raw_exit
    result["return"] = ret
    result["success"] = "no" if ret < 0 else "yes"

    # 如果是没有见过的进程，从父进程拷贝 fd 表
    # 应对 fork / clone 丢失
    fix_copy_file_table = False
    if not FileMan.has_pid(pid) and FileMan.has_pid(ppid):
        fix_copy_file_table = True
    file_man = FileMan(pid)
    if fix_copy_file_table:
        file_man.fd_map.update(FileMan(ppid).fd_map)

    # SOCKADDR 参数
    if "SOCKADDR" in event:
        parse_saddr_line(
            event["SOCKADDR"][0], file_man, syscall_line, action, ret, result
        )
    # PATH 参数
    elif "PATH" in event:
        path_lines: list[PathLine] = event["PATH"]
        if action in ACTION_DUAL_PATH_ARGS:
            parse_path_lines_dual_paths(path_lines, event, result)
        else:
            if action in ACTION_COMPLEX_PATH_ARG:
                name = parse_complex_path_lines(
                    path_lines, file_man, event, syscall_line, action, result
                )
                if action == "unlinkat" and int(syscall_line["a2"], 16) == 0x200:
                    # AT_REMOVEDIR
                    result["action"] = action + "_DIR"
            else:
                name = decode_path_line_name(path_lines[0]["name"])
                result["file"] = name
            if action in ACTION_FD_RET and ret >= 0:
                file_man.add(ret, name)
    else:
        match action:
            # （暂时）标识 unbind socket
            case "socket" if ret >= 0:
                file_man.add(ret, f"/proc/{pid}/socket/{ret}")
            # 标识 epoll instance
            case "epoll_create" | "epoll_create1" if ret >= 0:
                file_man.add(ret, f"/proc/{pid}/epoll/{ret}")
            # 标识内存临时文件
            case "memfd_create" if ret >= 0:
                file_man.add(ret, f"/proc/{pid}/memfd/{ret}")
            # 标识管道
            case "pipe" | "pipe2" if ret >= 0 and "FD_PAIR" in event:
                fd_pair_line = event["FD_PAIR"][0]
                fd0 = int(fd_pair_line["fd0"])
                fd1 = int(fd_pair_line["fd1"])
                file_man.add(fd0, f"/proc/{pid}/pipe/{fd0}")
                file_man.add(fd1, f"/proc/{pid}/pipe/{fd1}")

            # mmap
            case "mmap" | "mmap2" if "MMAP" in event:
                mmap_line = event["MMAP"][0]
                flags = mmap_line["flags"]
                prot = syscall_line["a2"]
                if ausearch:
                    mode = MmapFlags.parse_ausearch(prot, flags).mode()
                else:
                    mode = MmapFlags.parse(int(prot, 16), int(flags, 16)).mode()
                if mode:
                    fd = int(mmap_line["fd"])  # * 十进制 / 十六进制？
                    start = int(syscall_line["a0"], 16)
                    length = int(syscall_line["a1"], 16)
                    parse_fd(result, file_man, action, fd)
                    file_man.add_mmap(start, length, fd)
                    result["action"] += f"_{mode}"
            case "msync":
                start = int(syscall_line["a0"], 16)
                length = int(syscall_line["a1"], 16)
                if (fd := file_man.find_mmap(start, length)) is not None:
                    parse_fd(result, file_man, action, fd)
            case "munmap":
                start = int(syscall_line["a0"], 16)
                length = int(syscall_line["a1"], 16)
                if (fd := file_man.del_mmap(start, length)) is not None:
                    parse_fd(result, file_man, action, fd)

            # 0, 2 两个 fd
            case "splice" | "copy_file_range" | "epoll_ctl":
                fd0 = int(syscall_line["a0"], 16)
                fd1 = int(syscall_line["a2"], 16)
                results.append(result.copy())
                parse_fd(result, file_man, action, fd0)
                result = results[-1]
                parse_fd(result, file_man, action, fd1)

            # 0, 1 两个 fd
            case "tee" | "dup2" | "dup3" | "sendfile":
                fd0 = int(syscall_line["a0"], 16)
                fd1 = int(syscall_line["a1"], 16)
                results.append(result.copy())
                parse_fd(result, file_man, action, fd0)
                result = results[-1]
                parse_fd(result, file_man, action, fd1)
                if action.startswith("dup") and ret == fd1:
                    # 映射 fd1 到 fd0 对应的文件
                    file_man.add(fd1, file_man.find(fd0))
                elif action == "sendfile":
                    results[-2]["action"] = "sendfile_OUT"
                    result["action"] = "sendfile_IN"

            # fork/clone: auditd 记成父进程执行，返回子进程 pid
            #! 未处理 CLONE_FILES：https://man7.org/linux/man-pages/man2/clone.2.html
            case "fork" | "clone" | "clone3" if ret > 0:
                child_pid = ret
                child_file_man = FileMan(child_pid)
                # 子进程复制父进程的 fd
                child_file_man.fd_map.update(file_man.fd_map)

            # 1 个 fd 参数
            case _ if action in ACTION_FD_ARG:
                fd = int(syscall_line["a0"], 16)
                parse_fd(result, file_man, action, fd)
                if action in {"close"}:  # shutdown 似乎还能复用
                    file_man.close(fd)
                elif action == "dup" and ret >= 0:
                    # 映射 ret(新的 fd) 到 fd 对应的文件
                    file_man.add(ret, file_man.find(fd))

    # syscall 行中剩余参数
    for r in results:
        for key in RESULT_KEYS_FROM_SYSCALL:
            r[key] = syscall_line.get(key, "")  # type: ignore

    for r in results:
        r["action"] = f'sys_{r["action"]}'

    if filter_out:
        return []
    return results
