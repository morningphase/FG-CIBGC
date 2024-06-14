import json
from typing import Literal

from lru import LRU

from AppNetAuditFusion.auditparser.parse_event import parse_event
from AppNetAuditFusion.auditparser.read import readline, readline_ausearch
from AppNetAuditFusion.auditparser.utils import Event


class AuditParserOnline:
    # 保留的事件数
    # 缓存一些事件，以防它的全部行还未全部输入时，就有其他事件插入
    EVENT_BUFFER_SIZE = 10000

    def __init__(
        self, mode: Literal["normal", "ausearch"], keep_apps: set[str] | None = None
    ) -> None:
        self.events_buffer: dict[str, Event] = {}
        self.keep_apps = keep_apps
        self.ausearch = True if mode == "ausearch" else False
        self.result_buffer: list[str] = []
        self.incomplete_buffer: dict[str, list[str]] = LRU(
            self.EVENT_BUFFER_SIZE, callback=self.pop_incomplete_callback
        )
        self.readline = readline if mode == "normal" else readline_ausearch

    def pop_incomplete_callback(self, eid: str, res: list[str]) -> None:
        self.result_buffer.extend(res)
        del self.events_buffer[eid]

    def _input(self, line: str) -> tuple[str, Event] | None:
        """读取日志，生成包含几行的事件"""
        tp, res = self.readline(line)
        if (
            not tp
            or not res
            or tp
            not in {"SYSCALL", "PATH", "EXECVE", "CWD", "SOCKADDR", "MMAP", "FD_PAIR"}
        ):
            return None
        eid = res["id"]
        event = self.events_buffer.setdefault(eid, {})
        if tp in event:
            event[tp].append(res)
        else:
            event[tp] = [res]
        return eid, event

    def process(self, line: str) -> None:
        res = self._input(line)
        if not res:
            return
        eid, event = res
        result_lines = parse_event(event, self.keep_apps, self.ausearch)
        if not result_lines:
            return
        jsons = [json.dumps({"id": eid, **r}) for r in result_lines]
        self.incomplete_buffer[eid] = jsons

    def get_results(self, include_incomplete: bool = False) -> list[str]:
        res = self.result_buffer
        if include_incomplete:
            for _, v in reversed(self.incomplete_buffer.items()):
                res.extend(v)
            self.incomplete_buffer.clear()
        self.result_buffer = []
        return res
