import re
from datetime import datetime

from AppNetAuditFusion import baseLog
import time


class OpenSSHLog(baseLog.BaseLog):
    def __init__(self, log):
        super(OpenSSHLog, self).__init__()
        self.State = None
        self.Port = None
        self.Ip = None
        self.Pid = None
        self.UserName = None
        self.parse_openssh_line(log)
        self.to_baselog()
        self.log = self.to__dict()

    def get_openssh_stamp(self, log):
        match = re.search(r'.{3} \d+ \d+:\d+:\d+', log)
        if match:
            time_str = match[0] + " 2023"
            try:
                dt = datetime.strptime(time_str, "%b %d %H:%M:%S %Y")
                return int(dt.timestamp())
            except ValueError as e:
                print(f"Error parsing timestamp: {e}")
        return -1

    def parse_openssh_line(self, line):
        self.Timestamp = self.get_openssh_stamp(line)
        reg1 = re.compile(r"sshd\[(\d+)\]: Accepted password for (.*) from (.*) port (\d+)")
        reg2 = re.compile(r"sshd\[(\d+)\]: Disconnected from user (.*) (.*) port (\d+)")
        s1 = reg1.finditer(line)
        s2 = reg2.finditer(line)

        for match in s1:
            self.Pid, = match.group(1),
            self.Ip, = match.group(3),
            self.Port, = match.group(4),
            self.UserName, = match.group(2),
            self.State = "Connect"
            return

        for match in s2:
            self.Pid, = match.group(1),
            self.Ip, = match.group(3),
            self.Port, = match.group(4),
            self.UserName, = match.group(2),
            self.State = "Disconnect"
            return
        return None

    def to_baselog(self):
        self.action = self.State
        self.object.entity_type = baseLog.ENTITYTYPE.PROCESS
        self.object.entity_name = self.Pid
        self.object.entity_data = self.Pid
        self.subject.entity_type = baseLog.ENTITYTYPE.SOCKET
        # if IP is None？
        try:
            self.subject.entity_name = self.Ip + ":" + self.Port
            self.subject.entity_data = self.Ip + ":" + self.Port
        except:
            self.Timestamp = None
        self.payload = self.UserName


if __name__ == '__main__':
    line = 'May 22 10:12:01 test-vm sshd[16834]: Accepted password for test from 192.168.229.130 port 44346 ssh2'
    parsed_log = OpenSSHLog(line)
    if parsed_log:
        print(f"Timestamp: {parsed_log.Timestamp}")
        print(f"Pid: {parsed_log.Pid}")
        print(f"Ip: {parsed_log.Ip}")
        print(f"Port: {parsed_log.Port}")
        print(f"UserName: {parsed_log.UserName}")
        print(f"State: {parsed_log.State}")
        print(f"action: {parsed_log.action}")
        print(f"subject: {parsed_log.subject}")
        print(f"object: {parsed_log.object}")

    else:
        print("Invalid log line")
