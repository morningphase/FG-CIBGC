import queue
import string
from collections import OrderedDict
from AppNetAuditFusion import baseLog
from AppNetAuditFusion import apacheLog
from AppNetAuditFusion import netLog
from AppNetAuditFusion import jsonnetLog
from AppNetAuditFusion import openSSHLog
from AppNetAuditFusion import proftpdLog
from AppNetAuditFusion import miniHttpdLog
from AppNetAuditFusion import redisLog
from AppNetAuditFusion import imageMagickLog

from AppNetAuditFusion import postgresqlLog
from AppNetAuditFusion.datasets import DataSet
import re


def connect(appqueue: [apacheLog], netqueue: [netLog], dataset: string):
    # 不同的应用使用不同的规则
    if dataset == "ApacheLog":
        apache_connect(appqueue, netqueue)
    elif dataset == "OpenSSHLog":
        openssh_connect(appqueue, netqueue)
    elif dataset == "ProftpdLog":
        proftpd_connect(appqueue, netqueue)
    elif dataset == "ApacheLogoffline":
        apache_connect_offline(appqueue, netqueue)
    elif dataset == "PostgresqlLogoffline":
        pgsql_connect(appqueue, netqueue)
    elif dataset == "RedisLog":
        redis_connect(appqueue,netqueue)
    elif dataset == "NginxLog":
        nginx_connect(appqueue,netqueue)
    elif dataset == "PhpLog":
        php_connect(appqueue,netqueue)
    elif dataset == "VimLog":
        vim_connect(appqueue,netqueue)
    elif dataset == "ImageMagickLogoffline":
        imagemagick_connect(appqueue,netqueue)
    else:
        pass


def apache_connect(appqueue: [apacheLog], netqueue: [netLog]):
    # todo 修改关联的逻辑，保证不同的流量日志可以通过相同的应用日志关联到一起，也就是流量日志能关联到应用日志且应用日志已经有tag，应该吧流量日志也设置成相同的tag？
    for log in appqueue:
        if log.label is None:
            log.label = baseLog.BaseLog.category
            baseLog.BaseLog.category += 1
    for log in appqueue:
        for log2 in netqueue:
            if log2.label is None:
                if log2.protocolName == "TCP":
                    if log.Host == log2.srcIp or log.Host == log2.destIp:
                        log2.label = log.label
                else:
                    if log.Host == log2.srcIp or log.Host == log2.destIp or log.payload == log2.payload:
                        log2.label = log.label


def openssh_connect(appqueue: [openSSHLog], netqueue: [netLog]):
    for applog in appqueue:
        if applog.label is None:
            applog.label = baseLog.BaseLog.category
            baseLog.BaseLog.category += 1
        if applog.State == 'Connect':
            matched_logs = [netlog for netlog in netqueue if
                            (netlog.srcPort == applog.Port or netlog.destPort == applog.Port)][:3]
            for log in matched_logs:
                log.label = applog.label
        elif applog.State == 'Disconnect':
            matched_logs = [netlog for netlog in netqueue if
                            (netlog.srcPort == applog.Port or netlog.destPort == applog.Port)][-4:]
            for log in matched_logs:
                log.label = applog.label


def proftpd_connect(appqueue: [proftpdLog], netqueue: [netLog]):
    for log in appqueue:
        if log.label is None:
            log.label = baseLog.BaseLog.category
            baseLog.BaseLog.category += 1
    for log in appqueue:
        for log2 in netqueue:
            if log2.protocolName == "TCP":
                if log.Host == log2.srcIp or log.Host == log2.destIp:
                    log2.label = log.label
            else:
                if log.Host == log2.srcIp or log.Host == log2.destIp or log.payload == log2.payload:
                    log2.label = log.label


# def ...
# #todo More rules

def minihttpd_connect(appqueue: [miniHttpdLog.MiniHttpdLog], netqueue: [netLog]):
    # TODO:需要根据时间戳判断先后顺序？
    for log in appqueue:
        if log.label is None:
            log.label = baseLog.BaseLog.category
            baseLog.BaseLog.category += 1
        for log2 in netqueue:
            if log2.protocolName == "TCP":
                if log.Host == log2.srcIp or log.Host == log2.destIp:
                    log2.label = log.label
            else:
                if log.Host == log2.srcIp or log.Host == log2.destIp:
                    log2.label = log.label


def redis_connect(appqueue: [redisLog.RedisLog], netqueue: [netLog]):
    for log in appqueue:
        if log.label is None:
            log.label = baseLog.BaseLog.category
            baseLog.BaseLog.category += 1
    for log in appqueue:
        for log2 in netqueue:
            if log2.protocolName == "TCP":
                if (log.Ip == log2.srcIp or log.Ip == log2.destIp) and (
                        log.Port == log2.srcPort or log.Port == log2.destPort):
                    log2.label = log.label
            else:
                if log.Ip == log2.srcIp or log.Ip == log2.destIp:
                    log2.label = log.label

def nginx_connect(appqueue: [], netqueue: [netLog]):
    for log in appqueue:
        if log.label is None:
            log.label = baseLog.BaseLog.category
            baseLog.BaseLog.category += 1
    for log in appqueue:
        #根据url和srcip==host找到对应的http 记录下srcport，dstip，dstport
        for log2 in netqueue:
            if log.DstPort is None and log2.label is None :
                if log2.protocolName == "HTTP" and log2.payload == log.Url and log.Host==log2.srcIp:
                    log2.label = log.label
                    log.SrcPort = log2.srcPort
                    log.DstIp = log2.destIp
                    log.DstPort = log2.destPort
                    break

    #根据port对应所有记录
    for log in appqueue:
        for log2 in netqueue:
            if log2.label is None:
                if (log.Host,log.SrcPort,log.DstIp,log.DstPort) == (log2.srcIp,log2.srcPort,log2.destIp,log2.destPort)or (log.DstIp,log.DstPort,log.Host,log.SrcPort) == (log2.srcIp,log2.srcPort,log2.destIp,log2.destPort):
                    log2.label = log.label

    #强行对应
    for log in appqueue:
        for log2 in netqueue:
            if log.DstPort is None and log2.label is None :
                if log2.protocolName == "TCP" and log.Host==log2.srcIp:
                    log2.label = log.label
                    log.SrcPort = log2.srcPort
                    log.DstIp = log2.destIp
                    log.DstPort = log2.destPort
                    break
        for log2 in netqueue:
            if log2.label is None:
                if (log.Host,log.SrcPort,log.DstIp,log.DstPort) == (log2.srcIp,log2.srcPort,log2.destIp,log2.destPort)or (log.DstIp,log.DstPort,log.Host,log.SrcPort) == (log2.srcIp,log2.srcPort,log2.destIp,log2.destPort):
                    log2.label = log.label

                



def php_connect(appqueue: [], netqueue: [netLog]):
    for log in appqueue:
        if log.label is None:
            log.label = baseLog.BaseLog.category
            baseLog.BaseLog.category += 1
    for log in appqueue:
        #根据url和srcip==host找到对应的http 记录下srcport，dstip，dstport
        for log2 in netqueue:
            if log.DstPort is None and log2.label is None :
                if log2.protocolName == "HTTP" and log2.payload == log.Url and log.Host==log2.srcIp:
                    log2.label = log.label
                    log.SrcPort = log2.srcPort
                    log.DstIp = log2.destIp
                    log.DstPort = log2.destPort
                    break
        #根据port对应所有记录
    for log in appqueue:
        for log2 in netqueue:
            if log2.label is None:
                if (log.Host,log.SrcPort,log.DstIp,log.DstPort) == (log2.srcIp,log2.srcPort,log2.destIp,log2.destPort)or (log.DstIp,log.DstPort,log.Host,log.SrcPort) == (log2.srcIp,log2.srcPort,log2.destIp,log2.destPort):
                    log2.label = log.label
        
def vim_connect(appqueue: [], netqueue: []):
    for log in appqueue:
        if log.label is None:
            log.label = baseLog.BaseLog.category
            baseLog.BaseLog.category += 1


def apache_connect_offline(appqueue: [apacheLog.ApacheLog], netqueue: [jsonnetLog.JsonNetworkLog]):
    # 两套关联的逻辑，这套针对自己采集的数据集
    # apache_pqsql使用
    ports = []
    for log in appqueue:
        if log.label is None:
            log.label = baseLog.BaseLog.category
            baseLog.BaseLog.category += 1
    for netlog in netqueue:
        if netlog.uri:
            ports.append(netlog.srcPort)
    for netlog in netqueue:
        if netlog.srcPort not in ports and netlog.destPort not in ports:
            continue
        if netlog.srcPort in ports:
            netlog.label = ports.index(netlog.srcPort)
        else:
            netlog.label = ports.index(netlog.destPort)

    


def pgsql_connect(appqueue: [postgresqlLog], netqueue: [netLog]):
    # apache_pasql使用
    ports = []
    begin_category = baseLog.BaseLog.category

    ss = []
    ts = []
    for log in appqueue:
        ss.append(log.statement)
        ports.append(log.port)
        ts.append(float(log.Timestamp))

    for netlog in netqueue:
        if netlog.srcPort not in ports and netlog.destPort not in ports:
            for i, t in enumerate(ts):
                if t < float(netlog.Timestamp):
                    continue
                if ss[i] == netlog.http_data:
                    appqueue[i].label = netlog.label
                    #netlog.label = i + begin_category
                    break
            continue
        if netlog.srcPort in ports:
            netlog.label = appqueue[ports.index(netlog.srcPort)].label
            #appqueue[ports.index(netlog.srcPort)].label = netlog.label
        else:
            netlog.label = appqueue[ports.index(netlog.destPort)].label
            #appqueue[ports.index(netlog.destPort)].label = netlog.label


def imagemagick_connect(appqueue: [imageMagickLog], netqueue: [netLog]):
    delta_t = 1

    def extract_filename(data):
        match = re.search(r'filename="([^"]+)"', data)
        return match.group(1) if match else None
    
    for net in netqueue:
        if net.label is None or net.filename is None or net.uri is None:
            continue
        filename = extract_filename(net.filename)
        target_pid=None
        for app in appqueue:
            if app.label is not None:
                continue
            target_pid = app.Pid
            break

        app_tmp=list(filter(lambda x: x.Pid == target_pid, appqueue))
        for app_ in app_tmp:
            app_.label = net.label
            #time:
            #if net.filename and net.Timestamp - float(app.Timestamp) < delta_t:
            #if net.label is not None and net.filename and net.uri and int(float(net.Timestamp)) == float(app.Timestamp):
    for log in appqueue:
        if log.label is None:
            log.label = baseLog.BaseLog.category
            baseLog.BaseLog.category += 1