import re
from AppNetAuditFusion import baseLog
import time
from datetime import datetime, timezone, timedelta



class NginxLog(baseLog.BaseLog):
    def __init__(self, log):
        super(NginxLog, self).__init__()
        parts = log.split()
        parts2 = re.split('["]', log)
        if len(parts) >= 10:
            self.Timestamp = self.get_nginx_stamp(log)
            self.Host = parts[0]
            self.Method = parts[5][1:]
            self.Url = parts[6]
            self.ResponseCode = parts[8]
            self.TransferSize = parts[9]
            self.Referer = parts[10].strip("\"")
            self.User_Agent=parts2[5]
        self.DstIp =None
        self.DstPort = None
        self.SrcIp = self.Host
        self.SrcPort = None
        self.to_baselog()
        self.log = self.to__dict()


    def get_nginx_stamp(self,line):
        reg = re.compile(r'\[.*\]')
        form = "[%d/%b/%Y:%H:%M:%S %z]"

        s = reg.search(line).group()
        try:
            t = datetime.strptime(s, form)
            # 调整时区为上海时区
            shanghai_tz = timezone(timedelta(hours=8))
            t = t.replace(tzinfo=shanghai_tz)  # Assuming the time is in UTC
            return int(t.timestamp())
        except ValueError as err:
            print(err)
        return None
        

    def to_baselog(self):
        self.action = self.Method
        if self.Method == "GET":
            self.object.entity_name = self.Url
            self.object.entity_type = baseLog.ENTITYTYPE.FILE
            self.subject.entity_name = self.Host
            self.subject.entity_type = baseLog.ENTITYTYPE.SOCKET
        else:
            self.subject.entity_name = self.Url
            self.subject.entity_type = baseLog.ENTITYTYPE.FILE
            self.object.entity_name = self.Host
            self.object.entity_type = baseLog.ENTITYTYPE.SOCKET
        self.payload = self.TransferSize


if __name__ == '__main__':
    line = '192.168.119.2 - - [26/Apr/2023:19:41:18 +0800] "GET /files../etc/passwd HTTP/1.1" 200 2948 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36" "-"'
    parsed_log = NginxLog(line)
    if parsed_log:
        print(f"Timestamp: {parsed_log.Timestamp}")
        print(f"Host: {parsed_log.Host}")
        print(f"Method: {parsed_log.Method}")
        print(f"Url: {parsed_log.Url}")
        print(f"ResponseCode: {parsed_log.ResponseCode}")
        print(f"TransferSize: {parsed_log.TransferSize}")
    else:
        print("Invalid log line")
