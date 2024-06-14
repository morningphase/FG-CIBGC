import re
from AppNetAuditFusion import baseLog
import time


class ApacheLog(baseLog.BaseLog):
    def __init__(self, log):
        super(ApacheLog, self).__init__()
        parts = log.split(' ')
        if len(parts) >= 10:
            self.Timestamp = self.get_apache_stamp(log)
            self.Host = parts[0]
            self.Method = parts[5][1:]
            self.Url = parts[6]
            self.Protocol = parts[7][0:-1]
            self.ResponseCode = parts[8]
            self.TransferSize = parts[9]
        if len(parts) >= 12:
            self.DstIP = parts[11]
        if len(parts) >= 13:
            self.DstPort = parts[12]
        if len(parts) >= 14:
            self.Pid = parts[13][0:-1]
        self.to_baselog()
        self.log = self.to__dict()


    def get_apache_stamp(self,log):
        match = re.search(r'\[([^]]+)\]', log)
        if match:
            timestamp_str = match.group(1)
            try:
                timestamp = int(time.mktime(time.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")))
                return timestamp
            except ValueError as e:
                print(f"Error parsing timestamp: {e}")
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
    line = '192.168.119.23 - - [26/Apr/2023:19:51:15 +0800] "POST /icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1" 200 2948'
    parsed_log = ApacheLog(line)
    if parsed_log:
        print(f"Timestamp: {parsed_log.Timestamp}")
        print(f"Host: {parsed_log.Host}")
        print(f"Method: {parsed_log.Method}")
        print(f"Url: {parsed_log.Url}")
        print(f"ResponseCode: {parsed_log.ResponseCode}")
        print(f"TransferSize: {parsed_log.TransferSize}")
    else:
        print("Invalid log line")
