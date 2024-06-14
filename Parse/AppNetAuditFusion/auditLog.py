from Parse.AppNetAuditFusion import baseLog
from Parse.AppNetAuditFusion.auditparser import auditd_log2default
from Parse.AppNetAuditFusion.utils import reverse_set


class AuditLog(baseLog.BaseLog):
    def __init__(self, log):
        super(AuditLog, self).__init__()
        for k, v in log.items():
            self.__setattr__(k, v)
        self.action = log["action"]
        self.Timestamp = str(log["timestamp"])
        self.object.entity_name = str(log["pid"])
        self.object.entity_data = str(log["process_name"])
        self.object.entity_type = baseLog.ENTITYTYPE.PROCESS
        if self.action == "sys_clone":
            self.subject.entity_name = str(log["return"])
            self.subject.entity_type = baseLog.ENTITYTYPE.PROCESS
            # print(self.subject.entity_name)
        else:
            self.subject.entity_name = log["file"]
            self.subject.entity_type = baseLog.ENTITYTYPE.FILE
            self.subject.entity_data = log["file"]
            if self.subject.entity_name == "":
                self.subject.entity_name = "/"
            if self.subject.entity_name is None:
                try:
                    ip = log.get('ip', None)
                    port = log.get('port', None)
                    if ip is not None:
                        ip = str(ip)
                    if port is not None:
                        port = str(port)
                    self.subject.entity_name = ip + "/" + port
                    self.subject.entity_data = self.subject.entity_name
                    self.subject.entity_type = baseLog.ENTITYTYPE.SOCKET
                except:
                    self.subject = self.object
        self.payload = None

        if self.action in reverse_set:
            self.object, self.subject = self.subject, self.object
        self.log = self.to__dict()


