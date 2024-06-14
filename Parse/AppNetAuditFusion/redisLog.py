from AppNetAuditFusion import baseLog
import re
# import baseLog


class RedisLog(baseLog.BaseLog):
    def __init__(self, log):
        super(RedisLog, self).__init__()
        self.Timestamp = None
        self.Ip = None
        self.Port = None
        self.Command = None
        self.Content = None
        self.LibPath = None
        self.Function = None
        self.CommandMode = None
        self.FileMode = None
        self.parseRedisLine(log)
        self.action = self.Command
        self.to_baselog()
        self.log = self.to__dict()

    def parseRedisLine(self, line):
        parts = line.split(" ")
        timestamp = float(parts[0])
        ip_port = parts[2].strip("]").split(":")
        content = " ".join(part.strip('"') for part in parts[4:]).replace("\n", "").replace("\"", "")

        self.Timestamp = timestamp
        self.Ip = ip_port[0]
        self.Port = ip_port[1]
        self.Command = parts[3].strip('"')
        self.Content = content
        if self.Command == "SCRIPT":
            for part in line.split(";"):
                for pattern in ["loadlib\\((.*),(.*)\\)", "io\\.popen\\((.*),(.*)\\)", "read\\((.*?)\\)"]:
                    match = re.search(pattern, part)
                    if match:
                        groups = match.groups()
                        if pattern == "loadlib\\((.*),(.*)\\)":
                            self.LibPath = groups[0].strip(' \\"')
                            self.Function = groups[1].strip(' \\"')
                        elif pattern == "io\\.popen\\((.*),(.*)\\)":
                            res = groups[0].split(" ")
                            self.Command = res[0].strip(' \\"')
                            self.Content = res[1].strip(' \\"')
                            self.CommandMode = groups[1].strip(' \\"')
                        elif pattern == "read\\((.*?)\\)":
                            self.FileMode = groups[0].strip(' \\"')

    def to_baselog(self):
        # TODO 终点类型不确定
        obj = self.Content.split(" ")[0]
        host_ip = self.Ip + ":" + self.Port
        if self.action == "SET":
            self.subject.entity_type = baseLog.ENTITYTYPE.SOCKET
            self.object.entity_type = baseLog.ENTITYTYPE.FILE
            self.subject.entity_name = host_ip
            self.object.entity_name = obj
        elif self.action == "GET":
            self.subject.entity_type = baseLog.ENTITYTYPE.FILE
            self.object.entity_type = baseLog.ENTITYTYPE.SOCKET
            self.subject.entity_name = obj
            self.object.entity_name = host_ip
        elif self.action == "stat":
            self.subject.entity_type = baseLog.ENTITYTYPE.FILE
            self.object.entity_type = baseLog.ENTITYTYPE.SOCKET
            self.subject.entity_name = obj
            self.object.entity_name = host_ip
        else:
            # TODO
            pass


if __name__ == '__main__':
    with open("redis.log") as f:
        lines = f.readlines()
        test_set = set()
        for line in lines:
            parsed_log = RedisLog(line)
            print(parsed_log.log)
            test_set.add(parsed_log.Command + " " + parsed_log.Content)
        print(test_set)
