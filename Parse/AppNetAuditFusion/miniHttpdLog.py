from AppNetAuditFusion import baseLog
import re
import time
from datetime import datetime

class MiniHttpdLog(baseLog.BaseLog):
    def __init__(self, log):
        super(MiniHttpdLog, self).__init__()
        self.action = None
        self.UserAgent = None
        self.ContentLength = None
        self.Status = None
        self.Protocol = None
        self.Path = None
        self.Method = None
        self.Timestamp = None
        self.Host = None
        self.parseMiniHttpdLine(log)
        self.to_baselog()
        self.log = self.to__dict()

    def parseMiniHttpdLine(self,raw_line):
        # 正则表达式来匹配日志行的结构
        log_pattern = re.compile(
            r'(?P<remote_ip>\S+) - - \[(?P<datetime>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
            r'(?P<status_code>\d+) (?P<content_length>\S+) '
            r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )
        match = log_pattern.match(line)
        if match:
            log_parts = match.groupdict()
            self.Host = log_parts['remote_ip']
            timestamp = int(time.mktime(time.strptime(log_parts['datetime'], "%d/%b/%Y:%H:%M:%S %z")))
            self.Timestamp = timestamp
            self.Method = log_parts['method']
            self.Path = log_parts['path']
            self.Protocol = log_parts['protocol']
            self.Status = log_parts['status_code']
            self.UserAgent = log_parts['user_agent']
        else:
            raise ValueError("Invalid log line format")

    def to_baselog(self):
        self.action = self.Method
        if self.action == "GET":
            self.subject.entity_type = baseLog.ENTITYTYPE.SOCKET
            self.object.entity_type = baseLog.ENTITYTYPE.FILE
            self.subject.entity_name = self.Host
            self.object.entity_name = self.Path
        else:
            self.object.entity_type = baseLog.ENTITYTYPE.SOCKET
            self.subject.entity_type = baseLog.ENTITYTYPE.FILE
            self.object.entity_name = self.Path
            self.subject.entity_name = self.Host


if __name__ == '__main__':
    line = '192.168.48.143 - - [12/Apr/2023:15:24:24 +0800] "GET /192.168.48.141/ HTTP/1.1" 404 - "" "Wget/1.21.2"'
    parsed_log = MiniHttpdLog(line)
    print(parsed_log)
