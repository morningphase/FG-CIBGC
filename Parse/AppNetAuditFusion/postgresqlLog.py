import datetime
import json
import re
import time

from AppNetAuditFusion import baseLog
import csv
import py2neo


# csv version
class PostgresqlLog(baseLog.BaseLog):
    ports = {}
    def __init__(self, log):
        super(PostgresqlLog, self).__init__()
        self.Timestamp = None
        self.pid = None
        self.port = None
        self.statement = None
        if "connection received: host=ubuntu" in log[13]:
            port = log[13][-5:]
            PostgresqlLog.ports[log[3]] = port
        if "statement:" in log[13]:
            self.Timestamp = float(datetime.datetime.strptime(log[0][:-4] + " +0800", "%Y-%m-%d %H:%M:%S.%f %z").timestamp())
            self.statement = log[13][11:]
            self.port = PostgresqlLog.ports[log[3]]
            self.username = log[1]
            self.database = log[2]
            self.pid = log[3]
        self.to_baselog()
        self.log = self.to__dict()

    def to_baselog(self):
        self.object.entity_name = self.pid
        self.object.entity_type = baseLog.ENTITYTYPE.PROCESS
        self.subject.entity_name = self.port
        self.subject.entity_type = baseLog.ENTITYTYPE.SOCKET
        self.payload = self.statement


if __name__ == '__main__':
    ports = []
    ts = []
    ss = []
    pids = []
    with open("D:/Log-Fusion/Logs/scene_php_pgsql/pgsql.csv", "r", encoding="utf-8") as f:
        r = csv.reader(f)
        i = 0
        for row in r:
            if "connection received: host=ubuntu" in row[13]:
                port = row[13][-5:]
                ports.append(port)
            if "statement:" in row[13]:
                pids.append(row[3])
                time = str(datetime.datetime.strptime(row[0][:-4] + " +0800", "%Y-%m-%d %H:%M:%S.%f %z").timestamp())
                ts.append(time)
                ss.append(row[13][11:])
    pglogs = []
    for i in range(256):
        pglog = {}
        pglog['time'] = ts[i]
        pglog['statement'] = ss[i]
        pglog['port'] = ports[i]
        pglog['pid'] = pids[i]
        pglogs.append(pglog)
    print(pglogs[0])
