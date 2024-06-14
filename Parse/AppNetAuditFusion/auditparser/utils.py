import os
import sys
from typing import Any, Literal, TypedDict, TypeVar
from typing_extensions import NotRequired

T = TypeVar("T")


def as_type(value: Any, type: type[T]) -> T:
    """
    类型断言
    """
    return value


# 类型
# 行的类别
LineType = Literal["SYSCALL", "PATH", "EXECVE", "CWD", "SOCKADDR", "MMAP", "FD_PAIR"]

# 行中的参数键
LineKey = Literal["timestamp"] | str
SyscallLineKey = (
    LineKey
    | Literal[
        "syscall", "UID", "uid", "pid", "ppid", "exit", "a0", "a1", "a2", "a3", "comm"
    ]
)
PathLineKey = LineKey | Literal["name", "nametype"]
SockAddrLineKey = LineKey | Literal["fam", "laddr", "lport", "path", "saddr"]
MmapLineKey = LineKey | Literal["fd", "flags"]


# 日志行
class Line(TypedDict):
    timestamp: str
    id: str


class SyscallLine(Line):
    SYSCALL: str
    syscall: str
    UID: str
    uid: str
    pid: str
    ppid: str
    exit: str
    a0: str
    a1: str
    a2: str
    a3: str
    comm: str
    exe: str


class PathLine(Line):
    name: str
    nametype: str


class SockAddrLine(Line):
    fam: str
    laddr: str
    lport: str
    path: str
    saddr: str


class MmapLine(Line):
    fd: str
    flags: str


class FdPairLine(Line):
    fd0: str
    fd1: str


# 事件
class Event(TypedDict):
    SYSCALL: list[SyscallLine]
    PATH: NotRequired[list[PathLine]]
    SOCKADDR: NotRequired[list[SockAddrLine]]
    MMAP: NotRequired[list[MmapLine]]
    FD_PAIR: NotRequired[list[FdPairLine]]


# 结果行参数
ResultKey = Literal[
    "timestamp",
    "process_name",
    "action",
    "pid",
    "ppid",
    "tid",
    "ip",
    "port",
    "file",
    "user",
    "return",
    "trans_id",
    "unit_id",
    "uri",
    "tty",
    "ses",
    "comm",
    "exe",
    "datetime",
    "error",
    "success",
    "a0",
    "a1",
    "a2",
    "a3",
]

# 结果行
ResultLine = TypedDict(
    "ResultLine",
    {
        "timestamp": str,
        "process_name": str,
        "action": str,
        "pid": int,
        "ppid": int,
        "tid": int,
        "ip": str,
        "port": int,
        "file": str,
        "user": str,
        "return": int,  # return 是关键词，因此不能写 class 定义
        "trans_id": str,
        "unit_id": str,
        "uri": str,
        "tty": str,
        "ses": str,
        "comm": str,
        "exe": str,
        "datetime": str,
        "error": str | None,
        "success": str,
        "a0": str,
        "a1": str,
        "a2": str,
        "a3": str,
    },
)

# 常量
SYSCALL_MAP = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    15: "rt_sigreturn",
    16: "ioctl",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    24: "sched_yield",
    25: "mremap",
    26: "msync",
    27: "mincore",
    28: "madvise",
    29: "shmget",
    30: "shmat",
    31: "shmctl",
    32: "dup",
    33: "dup2",
    34: "pause",
    35: "nanosleep",
    36: "getitimer",
    37: "alarm",
    38: "setitimer",
    39: "getpid",
    40: "sendfile",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    48: "shutdown",
    49: "bind",
    50: "listen",
    51: "getsockname",
    52: "getpeername",
    53: "socketpair",
    54: "setsockopt",
    55: "getsockopt",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    63: "uname",
    64: "semget",
    65: "semop",
    66: "semctl",
    67: "shmdt",
    68: "msgget",
    69: "msgsnd",
    70: "msgrcv",
    71: "msgctl",
    72: "fcntl",
    73: "flock",
    74: "fsync",
    75: "fdatasync",
    76: "truncate",
    77: "ftruncate",
    78: "getdents",
    79: "getcwd",
    80: "chdir",
    81: "fchdir",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    89: "readlink",
    90: "chmod",
    91: "fchmod",
    92: "chown",
    93: "fchown",
    94: "lchown",
    95: "umask",
    96: "gettimeofday",
    97: "getrlimit",
    98: "getrusage",
    99: "sysinfo",
    100: "times",
    101: "ptrace",
    102: "getuid",
    103: "syslog",
    104: "getgid",
    105: "setuid",
    106: "setgid",
    107: "geteuid",
    108: "getegid",
    109: "setpgid",
    110: "getppid",
    111: "getpgrp",
    112: "setsid",
    113: "setreuid",
    114: "setregid",
    115: "getgroups",
    116: "setgroups",
    117: "setresuid",
    118: "getresuid",
    119: "setresgid",
    120: "getresgid",
    121: "getpgid",
    122: "setfsuid",
    123: "setfsgid",
    124: "getsid",
    125: "capget",
    126: "capset",
    127: "rt_sigpending",
    128: "rt_sigtimedwait",
    129: "rt_sigqueueinfo",
    130: "rt_sigsuspend",
    131: "sigaltstack",
    132: "utime",
    133: "mknod",
    134: "uselib",
    135: "personality",
    136: "ustat",
    137: "statfs",
    138: "fstatfs",
    139: "sysfs",
    140: "getpriority",
    141: "setpriority",
    142: "sched_setparam",
    143: "sched_getparam",
    144: "sched_setscheduler",
    145: "sched_getscheduler",
    146: "sched_get_priority_max",
    147: "sched_get_priority_min",
    148: "sched_rr_get_interval",
    149: "mlock",
    150: "munlock",
    151: "mlockall",
    152: "munlockall",
    153: "vhangup",
    154: "modify_ldt",
    155: "pivot_root",
    156: "_sysctl",
    157: "prctl",
    158: "arch_prctl",
    159: "adjtimex",
    160: "setrlimit",
    161: "chroot",
    162: "sync",
    163: "acct",
    164: "settimeofday",
    165: "mount",
    166: "umount2",
    167: "swapon",
    168: "swapoff",
    169: "reboot",
    170: "sethostname",
    171: "setdomainname",
    172: "iopl",
    173: "ioperm",
    174: "create_module",
    175: "init_module",
    176: "delete_module",
    177: "get_kernel_syms",
    178: "query_module",
    179: "quotactl",
    180: "nfsservctl",
    181: "getpmsg",
    182: "putpmsg",
    183: "afs_syscall",
    184: "tuxcall",
    185: "security",
    186: "gettid",
    187: "readahead",
    188: "setxattr",
    189: "lsetxattr",
    190: "fsetxattr",
    191: "getxattr",
    192: "lgetxattr",
    193: "fgetxattr",
    194: "listxattr",
    195: "llistxattr",
    196: "flistxattr",
    197: "removexattr",
    198: "lremovexattr",
    199: "fremovexattr",
    200: "tkill",
    201: "time",
    202: "futex",
    203: "sched_setaffinity",
    204: "sched_getaffinity",
    205: "set_thread_area",
    206: "io_setup",
    207: "io_destroy",
    208: "io_getevents",
    209: "io_submit",
    210: "io_cancel",
    211: "get_thread_area",
    212: "lookup_dcookie",
    213: "epoll_create",
    214: "epoll_ctl_old",
    215: "epoll_wait_old",
    216: "remap_file_pages",
    217: "getdents64",
    218: "set_tid_address",
    219: "restart_syscall",
    220: "semtimedop",
    221: "fadvise64",
    222: "timer_create",
    223: "timer_settime",
    224: "timer_gettime",
    225: "timer_getoverrun",
    226: "timer_delete",
    227: "clock_settime",
    228: "clock_gettime",
    229: "clock_getres",
    230: "clock_nanosleep",
    231: "exit_group",
    232: "epoll_wait",
    233: "epoll_ctl",
    234: "tgkill",
    235: "utimes",
    236: "vserver",
    237: "mbind",
    238: "set_mempolicy",
    239: "get_mempolicy",
    240: "mq_open",
    241: "mq_unlink",
    242: "mq_timedsend",
    243: "mq_timedreceive",
    244: "mq_notify",
    245: "mq_getsetattr",
    246: "kexec_load",
    247: "waitid",
    248: "add_key",
    249: "request_key",
    250: "keyctl",
    251: "ioprio_set",
    252: "ioprio_get",
    253: "inotify_init",
    254: "inotify_add_watch",
    255: "inotify_rm_watch",
    256: "migrate_pages",
    257: "openat",
    258: "mkdirat",
    259: "mknodat",
    260: "fchownat",
    261: "futimesat",
    262: "newfstatat",
    263: "unlinkat",
    264: "renameat",
    265: "linkat",
    266: "symlinkat",
    267: "readlinkat",
    268: "fchmodat",
    269: "faccessat",
    270: "pselect6",
    271: "ppoll",
    272: "unshare",
    273: "set_robust_list",
    274: "get_robust_list",
    275: "splice",
    276: "tee",
    277: "sync_file_range",
    278: "vmsplice",
    279: "move_pages",
    280: "utimensat",
    281: "epoll_pwait",
    282: "signalfd",
    283: "timerfd_create",
    284: "eventfd",
    285: "fallocate",
    286: "timerfd_settime",
    287: "timerfd_gettime",
    288: "accept4",
    289: "signalfd4",
    290: "eventfd2",
    291: "epoll_create1",
    292: "dup3",
    293: "pipe2",
    294: "inotify_init1",
    295: "preadv",
    296: "pwritev",
    297: "rt_tgsigqueueinfo",
    298: "perf_event_open",
    299: "recvmmsg",
    300: "fanotify_init",
    301: "fanotify_mark",
    302: "prlimit64",
    303: "name_to_handle_at",
    304: "open_by_handle_at",
    305: "clock_adjtime",
    306: "syncfs",
    307: "sendmmsg",
    308: "setns",
    309: "getcpu",
    310: "process_vm_readv",
    311: "process_vm_writev",
    312: "kcmp",
    313: "finit_module",
    314: "sched_setattr",
    315: "sched_getattr",
    316: "renameat2",
    317: "seccomp",
    318: "getrandom",
    319: "memfd_create",
    320: "kexec_file_load",
    321: "bpf",
    322: "execveat",
    323: "userfaultfd",
    324: "membarrier",
    325: "mlock2",
    326: "copy_file_range",
    327: "preadv2",
    328: "pwritev2",
    329: "pkey_mprotect",
    330: "pkey_alloc",
    331: "pkey_free",
    332: "statx",
}
RESULT_KEYS: list[ResultKey] = [
    "timestamp",
    "process_name",
    "action",
    "pid",
    "ppid",
    "tid",
    "ip",
    "port",
    "file",
    "user",
    "return",
    "trans_id",
    "unit_id",
    "uri",
    "datetime",
    "error",
    "success",
]

# 直接从 syscall 行中提取即可的键
RESULT_KEYS_FROM_SYSCALL: list[ResultKey] = [
    "tty",
    "ses",
    "comm",
    "exe",
    "a0",
    "a1",
    "a2",
    "a3",
]
RESULT_KEYS += RESULT_KEYS_FROM_SYSCALL

ACTION_PATH_ARG = {
    "open",
    "stat",
    "lstat",
    "access",
    "shmat",
    "execve",
    "shmdt",
    "truncate",
    "chdir",
    "mkdir",
    "rmdir",
    "creat",
    "unlink",
    "chmod",
    "chown",
    "lchown",
    "utime",
    "mknod",
    "statfs",
    "chroot",
    "acct",
    "umount2",
    "swapon",
    "swapoff",
    "setxattr",
    "lsetxattr",
    "getxattr",
    "lgetxattr",
    "listxattr",
    "llistxattr",
    "removexattr",
    "lremovexattr",
    "utimes",
    "inotify_add_watch",
    "openat",
    "mkdirat",
    "mknodat",
    "fchownat",
    "futimeat",
    "newfstatat",
    "unlinkat",
    "readlinkat",
    "fchmodat",
    "faccessat",
    "epoll_pwait",
    "execveat",
}
# 有两个 path 参数的调用
ACTION_DUAL_PATH_ARGS = {
    "rename",
    "link",
    "symlink",
    "renameat",
    "renameat2",
    "linkat",
    "symlinkat",
    "pivot_root",
    "mount",
}
ACTION_PATH_ARG |= ACTION_DUAL_PATH_ARGS
# 可能有多个 path 行的调用
ACTION_COMPLEX_PATH_ARG = {"openat", "creat", "unlinkat", "unlink", "open"}

ACTION_SOCK_ARG = {
    "connect",
    "accept",
    "sendto",
    "recvfrom",
    "getsockname",
    "getpeername",
    "accept4",
}

# 参数中只有 fd 没有路径 / 地址的调用
ACTION_FD_ARG = {
    "read",
    "write",
    "readv",
    "writev",
    "close",
    "lseek",
    "fstat",
    "ioctl",
    "pread",
    "pwrite",
    "pread64",
    "pwrite64",
    "fcntl",
    "flock",
    "fsync",
    "fdatasync",
    "ftruncate",
    "getdents",
    "fchdir",
    "fchmod",
    "fchown",
    "fstatfs",
    "readahead",
    "fsetxattr",
    "fgetxattr",
    "flistxattr",
    "fremovexattr",
    "getdents64",
    "fadvice64",
    "vmsplice",
    "finit_module",
}
# 区分操作文件的和操作 socket 的
ACTION_NET_FD_ARG = {
    "sendmsg",
    "send",
    "sendto",
    "recvmsg",
    "recvfrom",
    "recv",
    "shutdown",
    "listen",
    "connect",
    "bind",
}
ACTION_EPOLL_FD_ARG = {"epoll_wait", "epoll_pwait", "epoll_pwait2"}
ACTION_FD_ARG = ACTION_FD_ARG | ACTION_NET_FD_ARG | ACTION_EPOLL_FD_ARG

# 返回 fd 的调用
# socket 也返回，但是还没有绑定地址，不处理
ACTION_FD_RET = {"open", "openat", "creat"}


class FileMan:
    Addr = tuple[str, str]
    ValueType = str | Addr
    # pid -> (fd -> filename | (ip, port))
    global_fd_map: dict[int, dict[int, ValueType]] = {}
    # pid -> (start, length, fd)
    global_mmap_table: dict[int, list[tuple[int, int, int]]] = {}
    # 默认打开的标准流
    init_fd_map: dict[int, ValueType] = {0: "stdin", 1: "stdout", 2: "stderr"}

    fake_localhost_no = 0

    @classmethod
    def has_pid(cls, pid: int) -> bool:
        return pid in cls.global_fd_map

    def __init__(self, pid: int) -> None:
        self.fd_map = self.global_fd_map.setdefault(pid, self.init_fd_map.copy())
        self.mmap_table = self.global_mmap_table.setdefault(pid, [])
        self.pid = pid

    def fake_localhost_addr(self) -> str:
        """用于没有记录 bind 调用而出现了 connect / accept 的情况。
        生成一个占位符本地地址"""
        self.fake_localhost_no += 1
        return f"placeholder_localhost_{self.fake_localhost_no}"

    def add(self, fd: int, value: ValueType) -> None:
        self.fd_map[fd] = value

    def find(
        self, fd: int, default: None | Literal["file", "addr"] = "file"
    ) -> ValueType:
        """根据 fd 寻找实体"""
        if fd in self.fd_map:
            return self.fd_map[fd]
        if default:
            # 前面没有调用返回这个 fd，不知道路径，只能生成一个占位符
            default_value = (
                f"/proc/{self.pid}/fd/{fd}"
                if default == "file"
                else (self.fake_localhost_addr(), "0")
            )
            self.fd_map[fd] = default_value
            return default_value
        return ""

    def close(self, fd: int) -> None:
        """关闭 fd"""
        if fd not in self.fd_map:
            return
        del self.fd_map[fd]

    def add_mmap(self, start: int, length: int, fd: int) -> None:
        self.mmap_table.append((start, length, fd))

    def find_mmap(self, start: int, length: int) -> int | None:
        for existed_start, existed_length, fd in self.mmap_table:
            if start >= existed_start and length <= existed_length:
                return fd
        return None

    def del_mmap(self, start: int, length: int) -> int | None:
        to_remove_index = -1
        fd = -1
        # new_mmaps = []
        for i, (existed_start, existed_length, existed_fd) in enumerate(
            self.mmap_table
        ):
            if start >= existed_start and length <= existed_length:
                # * 可以只 unmap 中间一块内存吗？
                to_remove_index = i
                fd = existed_fd
                break
        if to_remove_index >= 0:
            self.mmap_table.pop(to_remove_index)
            return fd
        return None


if sys.platform.startswith("win"):

    def path_join(path: str, *paths: str) -> str:
        return os.path.join(path, *paths).replace("\\", "/")

else:

    def path_join(path: str, *paths: str) -> str:
        return os.path.join(path, *paths)
