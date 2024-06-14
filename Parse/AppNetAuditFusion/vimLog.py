from AppNetAuditFusion import baseLog


class VimLog(baseLog.BaseLog):
    def __init__(self, log):
        super(VimLog, self).__init__()
        parts = log.split('\t')
        self.Timestamp = parts[0]
        self.Pid = parts[2]
        self.action = parts[3]
        self.Path = parts[5]
        self.FileName = parts[6]
        self.payload = parts[7]
        self.to_baselog()
        self.log = self.to__dict()

    def to_baselog(self):
        if self.action == "BufRead":
            self.subject.entity_type = baseLog.ENTITYTYPE.PROCESS
            self.object.entity_type = baseLog.ENTITYTYPE.FILE
            self.subject.entity_name = self.Pid
            self.object.entity_name = self.FileName
        else:
            self.object.entity_type = baseLog.ENTITYTYPE.PROCESS
            self.subject.entity_type = baseLog.ENTITYTYPE.FILE
            self.object.entity_name = self.Pid
            self.subject.entity_name = self.FileName


if __name__ == '__main__':
    line = '1683722062	2023-05-10 20:34:22	11404	BufWinEnter		/home/victim/Desktop/vim/abc (11th copy).log	abc (11th copy).log	3'
    parsed_log = VimLog(line)
    print(parsed_log)
