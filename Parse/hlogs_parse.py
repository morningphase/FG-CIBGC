import json
import csv
import datetime
import os
from AppNetAuditFusion.datasets import DataSet, DATASETCONFIG
from AppNetAuditFusion.timeWindow import TimeWindow
import argparse


def parse_net(logs_path):
    netlogs = []
    with open(logs_path, "r", encoding="utf-8") as f:
        netjsons = json.load(f)
        for netjson in netjsons:
            time = ""
            s_ip = ""
            d_ip = ""
            s_port = ""
            d_port = ""
            httpdata = ""
            layers = netjson["_source"]["layers"]
            try:
                time = layers["frame"]["frame.time_epoch"]
            except:
                pass
            try:
                s_ip = layers["ip"]["ip.src"]
                d_ip = layers["ip"]["ip.dst"]
            except:
                pass
            try:
                s_ip = layers["ipv6"]["ipv6.src"]
                d_ip = layers["ipv6"]["ipv6.dst"]
                continue
            except:
                pass
            try:
                s_port = layers["tcp"]["tcp.srcport"]
                d_port = layers["tcp"]["tcp.dstport"]
            except:
                pass
            try:
                s_port = layers["udp"]["udp.srcport"]
                d_port = layers["udp"]["udp.dstport"]
            except:
                pass
            try:
                tmp = layers["urlencoded-form"]
                key = list(tmp.keys())[0]
                httpdata = tmp[key]["urlencoded-form.value"]
            except:
                pass
            netlog = {}
            if s_ip == '':
                continue
            netlog["time"] = time
            netlog["s_ip"] = s_ip
            netlog["d_ip"] = d_ip
            netlog["s_port"] = s_port
            netlog["d_port"] = d_port
            netlog["httpdata"] = httpdata
            netlogs.append(netlog)
    return netlogs


def parse_apache(logs_path):
    apachelogs = []
    with open(logs_path, 'r') as f:
        for line in f:
            apachelog = {}
            ls = line.split(' ')
            apachelog['src_ip'] = ls[0]
            apachelog['timestamp'] = str(
                datetime.datetime.strptime(ls[3] + ' ' + ls[4], "[%d/%b/%Y:%H:%M:%S %z]").timestamp())
            apachelog['method'] = ls[5][1:]
            apachelog['file'] = ls[6]
            apachelog['protocol'] = ls[7][0:-1]
            apachelog['return_code'] = ls[8]
            apachelog['dst_ip'] = ls[11]
            apachelog['dst_port'] = ls[12]
            apachelog['pid'] = ls[13][0:-1]
            apachelogs.append(apachelog)
    return apachelogs


def parse_pgsql(logs_path):
    pglogs = []
    ports = {}
    with open(logs_path, "r", encoding="utf-8") as f:
        r = csv.reader(f)
        for row in r:
            if "connection received: host=ubuntu" in row[13]:
                port = row[13][-5:]
                ports[row[3]] = port
            if "statement:" in row[13]:
                pglog = {}
                pglog['time'] = str(
                    datetime.datetime.strptime(row[0][:-4] + " +0800", "%Y-%m-%d %H:%M:%S.%f %z").timestamp())
                pglog['statement'] = row[13][11:]
                pglog['port'] = ports[row[3]]
                pglog['pid'] = row[3]
                pglogs.append(pglog)
    return pglogs


def correlate_net_apache(netlogs, apachelogs):
    ports = []
    for netlog in netlogs:
        if netlog["httpdata"] != '':
            ports.append(netlog["s_port"])
    netnapache = []
    for netlog in netlogs:
        s_port = netlog["s_port"]
        d_port = netlog["d_port"]
        if s_port not in ports and d_port not in ports:
            netnapache.append(-1)
            continue
        if s_port in ports:
            netnapache.append(ports.index(s_port))
        else:
            netnapache.append(ports.index(d_port))
    return netnapache


def correlate_net_pgsql(netlogs, pglogs):
    ss = []
    ts = []
    ports = []
    for log in pglogs:
        ss.append(log['statement'])
        ports.append(log['port'])
        ts.append(float(log['time']))
    netnpgsql = []
    for netlog in netlogs:
        s_port = netlog["s_port"]
        d_port = netlog["d_port"]
        httpdata = netlog["httpdata"]
        time = float(netlog['time'])
        if s_port not in ports and d_port not in ports:
            f = 0
            for i, t in enumerate(ts):
                if t < time:
                    continue
                if ss[i] == httpdata:
                    netnpgsql.append(i)
                    f = 1
                    break
            if not f:
                netnpgsql.append(-1)
            continue
        if s_port in ports:
            netnpgsql.append(ports.index(s_port))
        else:
            netnpgsql.append(ports.index(d_port))
    return netnpgsql


def compress_netlogs(netlogs):
    graphs = {}
    for i, netlog in enumerate(netlogs):
        if netlog['ApacheLoglabel'] not in graphs:
            graphs[netlog['ApacheLoglabel']] = []
        graphs[netlog['ApacheLoglabel']].append(i)
    ids = []
    for graph in graphs:
        logids = graphs[graph]
        s = set()
        for id in logids:
            log = netlogs[id]
            if log['http_data'] != None:
                ids.append(id)
                continue
            sip, dip, sport, dport = log['srcIp'], log['destIp'], log['srcPort'], log['destPort']
            if (sip, dip, sport, dport) in s:
                continue
            else:
                ids.append(id)
                s.add((sip, dip, sport, dport))
    new_logs = []
    for i, netlog in enumerate(netlogs):
        if i in ids:
            new_logs.append(netlog)
    print(len(new_logs), len(netlogs))
    return new_logs

def get_match_list(sorted_app_list,net_list):
    match_list = [-1] * len(net_list)
    for i in range(len(net_list)):
        net_label = net_list[i]['label']
        if net_label != None:
            for j in range(len(sorted_app_list)):
                if net_label == sorted_app_list[j]['label']:
                    match_list[i] = j
                    break
    return match_list           

def get_correlate_json(netlog_list :[], applogs_list:[[]], compressed):
    netlogs = []
    for net in netlog_list:
        netlogs.append(net.to__dict())
    # len(applogs_list)个应用日志种类
    list_match_list=[]#list组成的list
    appname_list=[]
    applogs_dict_list=[]
    print(len(applogs_list))
    for applogs in applogs_list:
        print(applogs)
        appname_list.append(type(applogs[0]).__name__)
        appdict_list=[]
        for applog in applogs:
            appdict_list.append(applog.to__dict())
        netapp = get_match_list(appdict_list,netlogs)
        list_match_list.append(netapp)
        applogs_dict_list.append(appdict_list)
    
    for i,netlog in enumerate(netlogs):
        for index in range(len(appname_list)):
            netlog[appname_list[index] + 'label']=str(list_match_list[index][i])
    if compressed:
        netlogs = compress_netlogs(netlogs)
        tmp_list = []
        for index in range(len(appname_list)):
            tmp_list.append([])
        for i,netlog in enumerate(netlogs):
            for index in range(len(appname_list)):
                tmp_list[index].append(netlog[appname_list[index] + 'label'])
        list_match_list = tmp_list
    
    net_app_data={}
    net_app_data["netlogs"] = netlogs
    for index in range(len(appname_list)):
        appname_for_correlate = appname_list[index].lower().strip('log')
        net_app_data['netn'+ appname_for_correlate] = list_match_list[index]
        net_app_data[appname_for_correlate+'logs'] = applogs_dict_list[index]

    if not os.path.exists(f'../Data/{DataSet.dataset.name}'):
        os.mkdir(f'../Data/{DataSet.dataset.name}/')
    with open(f"../Data/{DataSet.dataset.name}/net_{DataSet.dataset.name.lower()}.json", "w") as f:
        json.dump(net_app_data, f, indent=4)


def standardize_logs(apps_res):
    standardize_res = [[]]
    if DataSet.dataset.name == 'Vim':
        last_log = None
        for applog in apps_res[0]:
            if last_log is None:
                if applog.action == 'BufRead' or applog.action == 'BufWrite':
                    last_log = applog
                else:
                    continue
            else:
                if applog.action != 'BufRead' and applog.action != 'BufWrite':
                    continue
                elif applog.Timestamp != last_log.Timestamp:
                    standardize_res[0].append(last_log)
                    last_log = applog
                    continue
                else:
                    if (applog.subject.entity_name == last_log.subject.entity_name and applog.object.entity_name == last_log.object.entity_name) or (applog.subject.entity_name == last_log.object.entity_name and applog.object.entity_name == last_log.subject.entity_name):
                        if applog.action == 'BufWrite':
                            last_log = applog
                    else:
                        standardize_res[0].append(last_log)
                        last_log = applog
        standardize_res[0].append(last_log)
        for idx, app_log in enumerate(standardize_res[0]):
            app_log.label = idx
        return standardize_res
    else:
        return apps_res


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parser For Arguments',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-datasetname', dest='datasetname', default='ImageMagick-2016', help='The name of the dataset')

    args = parser.parse_args()
    print(args.datasetname)
    if args.datasetname == 'Apache_Pgsql':
        DataSet.select_data_set(DATASETCONFIG.APACHE_PGSQL)
    elif args.datasetname == 'Apache':
        DataSet.select_data_set(DATASETCONFIG.APACHE)
    elif args.datasetname == 'Redis':
        DataSet.select_data_set(DATASETCONFIG.REDIS)
    elif args.datasetname == 'Vim':
        DataSet.select_data_set(DATASETCONFIG.VIM)
    elif args.datasetname == 'Proftpd':
        DataSet.select_data_set(DATASETCONFIG.PROFTPD)
    elif args.datasetname == 'Nginx':
        DataSet.select_data_set(DATASETCONFIG.NGINX)
    elif args.datasetname == 'Php':
        DataSet.select_data_set(DATASETCONFIG.PHP)
    elif args.datasetname == 'Apache_Proftpd':
        DataSet.select_data_set(DATASETCONFIG.APACHE_PROFTPD)
    elif args.datasetname == 'ImageMagick-2016':
        DataSet.select_data_set(DATASETCONFIG.IMAGEMAGICK2016)
    elif args.datasetname == 'ImageMagick':
        DataSet.select_data_set(DATASETCONFIG.IMAGEMAGICK)
    t = TimeWindow(window_size=5)

    apps_res, net_res = t.run()
    print(apps_res)
    apps_res = standardize_logs(apps_res)
    get_correlate_json(netlog_list=net_res,applogs_list=apps_res,compressed=0)

