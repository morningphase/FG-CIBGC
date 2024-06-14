import re
from AppNetAuditFusion import baseLog
import time

""""
class BaseLog:
    category = 0

    class Entity:
        def __init__(self):
            self.entity_type = ENTITYTYPE.FILE
            self.entity_name = None  # 一般是进程号
            self.entity_data = None  # 一般是进程名称

    def __init__(self):
        self.Timestamp = None
        self.object = self.Entity()
        self.subject = self.Entity()
        self.action = None
        self.payload = None
        self.label = None
        self.log = None

    def __lt__(self, other):
        return self.Timestamp <= other.Timestamp

    def to__dict(self):
        a = copy(self.__dict__)
        del a['object']
        del a['subject']
        del a['log']
        #return dumps(a)
        return a

    @property
    def _has_timestamp(self):
        if self.Timestamp is None:
            return False
        return True
"""


class ProftpdLog(baseLog.BaseLog):
    def __init__(self, log):
        super(ProftpdLog, self).__init__()
        parts = log.split()
        self.Timestamp = self.get_proftpd_stamp(log)
        self.TransferDuration = parts[5]
        self.Host = parts[6]
        self.TransferSize = parts[7]
        self.Filename = parts[8]
        self.TransferType = parts[9]
        self.TransferStatus = parts[10]
        self.OperationType = parts[11]
        self.AccessMode = parts[12]
        self.Username = parts[13]
        self.Protocol = parts[14]
        self.FileOffset = parts[15]
        self.FileHash = parts[16]
        self.FTPCommand = parts[17]
        self.to_baselog()
        self.log = self.to__dict()

    def get_proftpd_stamp(self, log):
        pattern = r'^(\w{3}\s\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})'
        result = re.match(pattern, log)
        if result:
            timestamp_str = result.group(1)
            try:
                from_format = '%a %b %d %H:%M:%S %Y'
                to_format = '%Y-%m-%d %H:%M:%S'
                time_struct = time.strptime(timestamp_str, from_format)
                times = time.strftime(to_format, time_struct)
                time_arr = time.strptime(times, "%Y-%m-%d %H:%M:%S")
                time_tmp = time.mktime(time_arr)
                return int(time_tmp) + 28800
            except ValueError as e:
                print(f"Error parsing timestamp: {e}")
        return -1

    def to_baselog(self):
        self.action = self.Protocol
        if self.Protocol == "ftp":
            self.object.entity_name = self.Filename
            self.object.entity_type = baseLog.ENTITYTYPE.FILE
            self.subject.entity_name = self.Host
            self.subject.entity_type = baseLog.ENTITYTYPE.SOCKET
        else:
            self.subject.entity_name = self.Filename
            self.subject.entity_type = baseLog.ENTITYTYPE.FILE
            self.object.entity_name = self.Host
            self.object.entity_type = baseLog.ENTITYTYPE.SOCKET
        self.payload = self.TransferSize

    def print_(self):
        print(f"Timestamp: {parsed_log.Timestamp}")
        print(f"TransferDuration: {parsed_log.TransferDuration}")
        print(f"Host: {parsed_log.Host}")
        print(f"TransferSize: {parsed_log.TransferSize}")
        print(f"Filename: {parsed_log.Filename}")
        print(f"TransferType: {parsed_log.TransferType}")
        print(f"TransferStatus: {parsed_log.TransferStatus}")
        print(f"OperationType: {parsed_log.OperationType}")
        print(f"AccessMode: {parsed_log.AccessMode}")
        print(f"Username: {parsed_log.Username}")
        print(f"Protocol: {parsed_log.Protocol}")
        print(f"FileOffset: {parsed_log.FileOffset}")
        print(f"FileHash: {parsed_log.FileHash}")
        print(f"FTPCommand: {parsed_log.FTPCommand}")


if __name__ == '__main__':
    line = 'Sat Apr 29 03:16:04 2023 0 192.168.229.132 14 /var/ftp/test.txt b _ o a anonymous ftp 0 * c'
    parsed_log = ProftpdLog(line)
    if parsed_log:
        parsed_log.print_()
    else:
        print("Invalid log line")

"""
Sat Apr 29 03:16:04 2023 - 这是日志条目的时间戳。它表示该事件发生在2023年4月29日星期六，时间是凌晨3点16分04秒。

0 - 这是传输时间，单位是秒。在这个例子中，它表明传输持续了0秒。

192.168.229.132 - 这是发起FTP连接的客户端（用户）的IP地址。

14 - 这是传输的文件大小，单位是字节。在此例中，传输的文件大小是14字节。

/var/ftp/test.txt - 这是被访问或传输的文件的路径和名称。

b - 这个字段指示了传输的类型。"b"代表二进制传输模式。另一个常见的选项是"text"，用字母"t"表示。

_ - 这个字段通常表示传输的状态。例如，“c”表示完成，“i”表示中断。在这里，“_”可能表示没有特定的状态信息。

o - 这表示操作类型。"o"代表下载（输出），而如果是上传（输入），则会显示为“i”。

a - 这个字段通常表示访问模式，"a"代表匿名访问。如果是经过身份验证的用户，则会显示用户名。

anonymous - 这是进行操作的FTP用户名。在这个例子中，用户以匿名（anonymous）身份登录。

ftp - 这表示服务名，通常是"ftp"。

0 - 这是传输的文件的偏移量。在文件传输中，它通常用于恢复中断的传输。这里的“0”表示从文件开始处传输。

*** - 这个字段通常是用于存储完成传输的文件的MD5哈希值，但在这个例子中，它是一个占位符，表示没有哈希值。

c - 这个字段表示FTP命令，如STOR（存储/上传文件）或RETR（检索/下载文件）。在这个例子中，“c”可能代表连接或关闭连接的命令。

请注意，不同版本的ProFTPD可能在日志格式上有所不同，这些解释是基于标准配置。要了解特定安装的确切日志格式，最好查阅该版本的ProFTPD文档。

"""
