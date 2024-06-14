import re
from datetime import datetime

import pytz

from AppNetAuditFusion import baseLog
from AppNetAuditFusion.datasets import DataSet,DATASETCONFIG
import time


class NetworkLog(baseLog.BaseLog):
    def __init__(self, log):
        super(NetworkLog, self).__init__()
        self.method = None
        self.filename = None
        self.destPort = None
        self.srcPort = None
        self.protocolName = None
        self.destIp = None
        self.srcIp = None
        self.Timestamp = None
        self.http_data = None
        self.protocol = None
        self.parse_line(log)
        self.log = self.to__dict()

    def parse_line(self, log):
        res = [
            re.compile(r'(?P<sequenceNum>[\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>\w+)' +
                       r'\t(?P<srcPort>[\d]+),(?P<destPort>[\d]+)\t\t(?P<len>[\d]+)\t(?P<method>\w+) (' +
                       r'?P<filename>\S*) (?P<protocol>[^\\\"\s]*)'),
            re.compile(
                "(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>\\w+)" +
                "\t(?P<srcPort>[\\d]+),(?P<destPort>[\\d]+)\t\t" +
                "(?P<len>[\\d]+)\t(?P<protocol>[^\\\"\\s]*) (?P<retValue>[\\d]+) (?P<text>.*)"),
            re.compile(
                "(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>\\w+)" +
                "\t\t(?P<srcPort>[\\d]+),(?P<destPort>[\\d]+)\t([\\d]+)\t(?P<text>.*)"),
            re.compile(
                "(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>\\w+)" +
                "\t(?P<srcPort>[\\d]+),(?P<destPort>[\\d]+)\t\t([\\d]+)\t(?P<text>.*)"),
            re.compile(
                "(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>[-\\w]+)" +
                "\t(?P<srcPort>[\\d]+),(?P<destPort>[\\d]+)\t\t([\\d]+)\t(?P<text>.*)"),
            re.compile(
                "(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>.*)" +
                "\t(?P<srcPort>[\\d]+),(?P<destPort>[\\d]+)\t\t([\\d]+)\t(?P<text>.*)"),
            re.compile(
                "(?P<sequenceNum>[\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>.*)" +
                "\t\t\t\t(?P<text>.*)"),
            re.compile(
                "(?P<sequenceNum>[\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>.*)" +
                "\t(?P<srcPort>[\\d]+),(?P<destPort>[\\d]+)\t\t(?P<text>.*)"),
            re.compile(
                "(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>.*)" +
                "\t\t\t([\\d]+)\t(?P<text>.*)"),

            re.compile(
                "[\\s]*(?P<sequenceNum>[\\d]+)[\\s]+(?P<time>.*)[\\s]+(?P<srcIp>[0-9]+.[0-9]+.[0-9]+.[0-9]+) → (?P<destIp>[0-9]+.[0-9]+.[0-9]+.[0-9]+)[\\s]+" +
                "HTTP[\\s]*(?P<len>[\\d]+)[\\s]*(?P<method>\\w+)[\\s]*(?P<filename>.*)[\\s]*HTTP/1.1"),

            re.compile(
                "[\\s]*(?P<sequenceNum>[\\d]+)[\\s]+(?P<time>.*)[\\s]+(?P<srcIp>[0-9]+.[0-9]+.[0-9]+.[0-9]+) → (?P<destIp>[0-9]+.[0-9]+.[0-9]+.[0-9]+)[\\s]+" +
                "TCP[\\s]*(?P<len>[\\d]+)[\\s]*(?P<srcPort>[\\d]+) → (?P<destPort>[\\d]+)[\\s]*(?P<text>.*)"),

            re.compile(
                "[\\s]*(?P<sequenceNum>[\\d]+)[\\s]+(?P<time>.*)[\\s]+(?P<srcIp>[0-9]+.[0-9]+.[0-9]+.[0-9]+) → (?P<destIp>[0-9]+.[0-9]+.[0-9]+.[0-9]+)[\\s]+" +
                "(?P<text>.*)"),
        ]
        founds = []
        group_names = []
        for regex in res:
            founds.append(regex.findall(log))
            group_names.append(regex.groupindex)

        idx = -1
        for i in range(len(founds)):
            found = founds[i]
            if len(found) == 1:
                idx = i
                break
        if idx == -1:
            raise Exception
        m = {}
        find = founds[idx][0]
        for j, n in enumerate(group_names[idx]):
            if j != 0 and n != "":
                m[n] = find[j].strip()

        def to_timestamp(t):
            try:
                date_format = "%b %d, %Y %H:%M:%S.%f"
                # 提取前6位小数和后3位小数
                date_parts = t.split()
                date_parts[-2] = date_parts[-2][:15]  # 保留前3位小数部分
                date_string_fixed = " ".join(date_parts)[0:-4]
                date_obj = datetime.strptime(date_string_fixed, date_format)
                timestamp = date_obj.timestamp()
            except:
                timestamp = None
            return timestamp

        if DataSet.dataset == DATASETCONFIG.PROFTPD or DataSet.dataset == DATASETCONFIG.PHP or DataSet.dataset == DATASETCONFIG.APACHE_PROFTPD:
            self.Timestamp = to_timestamp(m.get("time", 0))
        elif DataSet.dataset == DATASETCONFIG.APACHE_PROFTPD:
            self.Timestamp = to_timestamp(m.get("time", 0))
        else:
            self.Timestamp = float(m.get("time", 0)[0:10])
        self.srcIp = m.get("srcIp")
        self.destIp = m.get("destIp")
        self.protocolName = m.get("protocolName", "")
        self.srcPort = m.get("srcPort")
        self.destPort = m.get("destPort")
        self.filename = m.get("filename", m.get("text"))
        self.method = m.get("method")
        self.protocol = m.get("protocol")

        self.object.entity_name = self.srcIp
        self.object.entity_type = baseLog.ENTITYTYPE.SOCKET
        self.subject.entity_name = self.destIp
        self.subject.entity_type = baseLog.ENTITYTYPE.SOCKET
        if self.protocolName == "TCP":
            self.action = self.protocolName
        else:
            self.action = self.method
        self.payload = self.filename


