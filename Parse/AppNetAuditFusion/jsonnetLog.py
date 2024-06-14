import re
from datetime import datetime

import pytz

from AppNetAuditFusion import baseLog
import time
from AppNetAuditFusion.datasets import DataSet, DATASETCONFIG


class JsonNetworkLog(baseLog.BaseLog):
    def __init__(self, log):
        super(JsonNetworkLog, self).__init__()
        self.method = None
        self.filename = None
        self.destPort = None
        self.srcPort = None
        self.protocolName = None
        self.destIp = None
        self.srcIp = None
        self.protocol = None
        self.Timestamp = None
        self.http_data = None
        self.uri = None
        self.ResponseCode = None
        self.parse_line(log)
        self.log = self.to__dict()

    def parse_line(self, log):
        layers = log["_source"]["layers"]
        try:
            self.Timestamp = layers["frame"]["frame.time_epoch"]
        except:
            self.Timestamp = None
        try:
            self.srcIp = layers["ip"]["ip.src"]
            self.destIp = layers["ip"]["ip.dst"]
        except:
            pass
        try:
            self.srcIp = layers["ipv6"]["ipv6.src"]
            self.destIp = layers["ipv6"]["ipv6.dst"]
            self.Timestamp = None
            return 
        except:
            pass
        try:
            self.srcPort = layers["tcp"]["tcp.srcport"]
            self.destPort = layers["tcp"]["tcp.dstport"]
        except:
            pass
        try:
            self.srcPort = layers["udp"]["udp.srcport"]
            self.destPort = layers["udp"]["udp.dstport"]
        except:
            pass
        try:
            http = layers["http"]
            key = list(http.keys())[0]
            self.method =  http[key].get("http.request.method",None)
            self.uri = http[key].get("http.request.uri",None)
            self.filename = http.get("http.file_data",None)
            self.ResponseCode = http[key].get("http.response.code",None)
        except:
            pass
        try:
            tmp = layers["urlencoded-form"]
            key = list(tmp.keys())[0]
            self.payload = tmp[key]["urlencoded-form.value"]
            self.http_data = self.payload
        except:
            pass
        if self.srcIp == '' or self.srcIp == None:
            self.Timestamp = None
            return
        try:
            self.object.entity_name = self.srcIp + ":" + self.srcPort
            self.object.entity_type = baseLog.ENTITYTYPE.SOCKET
            self.subject.entity_type = baseLog.ENTITYTYPE.SOCKET
            self.subject.entity_name = self.destIp + ":" + self.destPort
        except:
            pass
