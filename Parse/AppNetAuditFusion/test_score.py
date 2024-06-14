import json
import math
import time
from tqdm import tqdm
import sys
import json
from AppNetAuditFusion.auditLog import AuditLog
from AppNetAuditFusion.auditparser import auditd_log2default
import pickle
from utils import reverse_set, rule_set
import networkx as nx
import copy

# --------------------tools begin------------------------------
def OverheadStart():
    start = time.time()
    return start


def OverheadEnd(start, phase):
    end = time.time()
    overhead = end - start
    print(phase + " runtime overhead: {:.3f} seconds\n".format(overhead))
# -------------------tools end----------------------------------


def getSubgraphs() -> (dict(), [], [], []):
    # 读取JSON文件
    with open('../Logs/Apache_Pgsql/net_apache_pgsql.json', 'r') as f:
        # dict_keys(['netlogs', 'netnapache', 'apachelogs', 'netnpgsql', 'pglogs'])
        data = json.load(f)
        # 子图的集合，索引代表子图的id
        subgraphs = dict()
        for index, label in enumerate(data['netnapache']):
            if label == -1:
                continue
            if subgraphs.get(label) is not None:
                subgraphs[label].append(index)
            else:
                subgraphs[label] = []
                subgraphs[label].append(index)
        for index, label in enumerate(data['netnpgsql']):
            if label == -1:
                continue
            if subgraphs.get(label) is not None:
                subgraphs[label].append(index)
            else:
                subgraphs[label] = []
                subgraphs[label].append(index)

    return subgraphs, data['netlogs'], data['apchelogs'], data['pglogs']


def custom_ln(t1, t2):
    abs_diff = abs(t1 - t2) + 1e-9
    result = math.log(1 + 1 / abs_diff)
    return result


# 1、时间相关性
def score_func1(audit_log, label, nets, netlogs, apachelogs, pglogs, idx):
    t1 = float(audit_log.Timestamp) / 1000000
    t1 = t1* 1000 + idx
    t_score = -1.0

    # 先计算和对应的apache和pgsql应用日志的相关性分数
    t_score = max(t_score, custom_ln(t1, float(apachelogs[label]['timestamp'])*1000+ idx))
    t_score = max(t_score, custom_ln(t1, float(pglogs[label]['time']))*1000+ idx)
    for index, net in enumerate(nets):
        netlog = netlogs[net]
        t_score = max(custom_ln(t1, float(netlog['time'])*1000+ idx), t_score)

    return t_score


# 2、主客体相关性
def score_func2(audit_log, label, nets, netlogs, apachelogs, pglogs, records, idx):
    # 主体和客体
    subject = audit_log.subject.entity_name
    object = audit_log.object.entity_name
    if records.get(label) is None:
        # 统计
        dic = {}
        apache_log = apachelogs[label]
        pg_log = pglogs[label]
        dic[apache_log['src_ip']] = dic.get(apache_log['src_ip'], 0) + 1
        dic[apache_log['file']] = dic.get(apache_log['file'], 0) + 1
        dic[apache_log['dst_ip']] = dic.get(apache_log['dst_ip'], 0) + 1
        dic[apache_log['dst_port']] = dic.get(apache_log['dst_port'], 0) + 1
        dic[apache_log['pid']] = dic.get(apache_log['pid'], 0) + 1
        dic[pg_log['port']] = dic.get(pg_log['port'], 0) + 1
        dic[pg_log['pid']] = dic.get(pg_log['pid'], 0) + 1
        net_set = set()
        for i in nets:
            net_log = netlogs[i]
            net_set.add(net_log['s_ip'])
            net_set.add(net_log['d_ip'])
            net_set.add(net_log['s_port'])
            net_set.add(net_log['d_port'])

            # dic[net_log['s_ip']] = dic.get(net_log['s_ip'], 0) + 1
            # dic[net_log['d_ip']] = dic.get(net_log['d_ip'], 0) + 1
            # dic[net_log['s_port']] = dic.get(net_log['s_port'], 0) + 1
            # dic[net_log['d_port']] = dic.get(net_log['d_port'], 0) + 1
        for net in net_set:
            dic[net] = dic.get(net, 0) + 1
        records[label] = dic
    A = 0
    for k, v in records[label].items():
        A += v
    I = 1
    B1 = records[label].get(subject, 0)
    B2 = records[label].get(object, 0)
    if B1 == 0 and B2 == 0:
        I = 0
    elif B1 != 0 and B2 != 0:
        I = 1
    else:
        I = 0.5
    B = B1 + B2
    return I * math.exp(B / A)

def history_report(subgraph_dict):
    for key in subgraph_dict:
        cnt_history = dict()
        audit_list = subgraph_dict[key]['audit']
        for audit_record in audit_list:
            if (len(audit_record['score_history'])) >=2:
                print(f'Scoring History For Label {key}')
                overwrite = audit_record['score_history'][-2].keys()
                overwrite = list(overwrite)[0]
                if overwrite not in cnt_history:
                    cnt_history[overwrite] = 0
                cnt_history[overwrite] += 1

def pid_report(subgraph_dict):
    not_matched_pids = dict()
    for key in subgraph_dict:
        not_matched_pids[key] = list()

        apache_pid = subgraph_dict[key]['apache']['pid']
        audit_list = subgraph_dict[key]['audit']
        for audit_record in audit_list:
            if str(audit_record['pid']) != str(apache_pid):
                not_matched_pids[key].append(audit_record['pid'])

    # print(not_matched_pids)
    with open('not_matched_pids.json','w') as f:
        json.dump(not_matched_pids, f)


def manual_verify(auditlist, subgraphs, apachelogs, pglogs):
    subgraph_dict = dict()
    f_notin = open('not_mapped_subgraph.txt','w')
    print('Get Mapped Records')
    for audit_log in auditlist:
        if audit_log.label == '_1':
            continue
        if audit_log.label not in subgraph_dict:
            subgraph_dict[audit_log.label] = dict()
            subgraph_dict[audit_log.label]['audit'] = list()
            subgraph_dict[audit_log.label]['nets'] = list()
        log_record = audit_log.log
        log_record['s1_time'] = audit_log.s1
        log_record['s2_relevance'] = audit_log.s2
        log_record['score_history'] = audit_log.score_history
        log_record['label'] = audit_log.label
        subgraph_dict[audit_log.label]['audit'].append(log_record)
    print('Get High-level Logs')
    for label, nets in subgraphs.items():
        if label not in subgraph_dict:
            subgraph_dict[label] = dict()
            subgraph_dict[label]['audit'] = list()
            subgraph_dict[label]['nets'] = list()
            f_notin.writelines(str(label) + '\n')
            f_notin.writelines(str(apachelogs[label]) + '\n')
            f_notin.writelines(str(pglogs[label]) + '\n')
        subgraph_dict[label]['apache'] = apachelogs[label]
        subgraph_dict[label]['pgsql'] = pglogs[label]
        for index, net in enumerate(nets):
            netlog = netlogs[net]
            subgraph_dict[label]['nets'].append(netlog)
    for key in subgraph_dict:
        if 'apache' not in subgraph_dict[key]:
           print(key)

    print('Evaluation Report')
    history_report(subgraph_dict)
    pid_report(subgraph_dict)
    print('Overwrite History Done')
    pickle_list = list()
    non_cnt = 0
    for key in subgraph_dict:
        audit = subgraph_dict[key]['audit']
        print(f'Graph Of Label {key} Contains {len(audit)} Record')
        pickle_list.append(audit_to_graph(audit))
        if len(audit) == 0:
            non_cnt += 1
    print(f'Number Of Empty Graph Is {non_cnt}')

    with open("apache_postgresql.pickle", "wb") as f:
        pickle.dump(subgraph_dict, f)
    with open('apache_postgresql.json','w') as f:
        json.dump(subgraph_dict, f)
    with open("graph_list.pickle", "wb") as f:
        pickle.dump(pickle_list, f)


def test_divided_log(auditlist):
    cnt = 0
    with tqdm(total=len(auditlist)) as pbar:
        pbar.set_description('Processing:')
        for audit_log in auditlist:
            log_record  = audit_log.log
            if log_record['action'] == 'sys_getsockname' and log_record['port'] == 80:
                cnt += 1
    print(cnt)

def fit_rule(rule, audit):
    filed_to_be_fitted = dict()
    for key in rule.keys():
        filed_to_be_fitted[key] = audit[key]
    if filed_to_be_fitted == rule:
        return True
    else:
        return False

def fit_divided(audit_log, type):
    rules = rule_set[type]
    for idx, rule in rules.items():
        if fit_rule(rule, audit_log):
            return True
    return False


def evaluate_score(auditlist, subgraphs, netlogs, apachelogs, pglogs, divided_available):
    records = {}
    subgraph_starttime = []

    for label, nets in subgraphs.items():
        apache_time = float(apachelogs[label]['timestamp'])
        pgsql_time = float(pglogs[label]['time'])
        subgraph_starttime.append((max(apache_time, pgsql_time), min(apache_time, pgsql_time)))

    with tqdm(total=len(auditlist)) as pbar:
        pbar.set_description('Processing:')
        for audit_log in auditlist:
            max_score = -1.0
            max_label = -1
            s1_best = -1.0
            s2_best = -1.0
            score_history = []

            if audit_log.log['ip'] == '::ffff:a66f:522e':
                audit_log.log['ip'] = '166.111.82.46'

            for idx, items in enumerate(subgraphs.items()):
                label, nets = items
                current_time = float(audit_log.Timestamp) / 1000000
                if current_time< subgraph_starttime[label][1]-1 or current_time> subgraph_starttime[label][0]+1:
                    if label == 0:
                        pass

                    continue
                s1 = score_func1(audit_log, label, nets, netlogs, apachelogs, pglogs, idx)
                s2 = score_func2(audit_log, label, nets, netlogs, apachelogs, pglogs, records, idx)
                if s1 + s2 > max_score and s2 !=0:
                    max_score = s1 + s2
                    max_label = label
                    s1_best = s1
                    s2_best = s2
                    score_history.append({f'{label}': f'{max_score}'})
                    if max_label >= 0:
                        pass

            if max_label == -1:
                max_label = "_1"
            else:
                audit_log_record = audit_log.log
                apache_log_record = copy.deepcopy(apachelogs[max_label])
                del apache_log_record['timestamp']
                apache_log_record = str(apache_log_record)
                pgsql_log_record = copy.deepcopy(pglogs[max_label])
                del pgsql_log_record['time']
                pgsql_log_record = str(pgsql_log_record)

                if fit_divided(audit_log_record, 'apache'):

                    divided_available['apache'][apache_log_record] = divided_available['apache'][apache_log_record][1:]

                tmp_label = divided_available['apache'][apache_log_record][0]
                if tmp_label != -1:
                    max_label = tmp_label


            if max_label == -1:
                print(1)
                exit()
            audit_log.label = max_label
            audit_log.score_history = score_history
            audit_log.s1 = s1_best
            audit_log.s2 = s2_best
            pbar.update(1)
    return auditlist

def audit_to_graph(auditlist):
    G = nx.MultiDiGraph()
    for audit in auditlist:
        src = audit['process_name']
        src_type = 'Process'
        if audit['file'] != None:
            dst = audit['file']
            dst_type = 'File'
        elif audit['ip'] != None:
            dst = audit['ip'] + ':' + str(audit['port'])
            dst_type = 'Socket'
        else:
            continue
        relation = audit['action']
        if relation in reverse_set:
            src, dst = dst, src
            src_type, dst_type = dst_type, src_type

        G.add_node(src, name=src, entity_type=src_type)
        G.add_node(dst, name=dst, entity_type=dst_type)
        G.add_edge(src, dst, relation=relation, log_record=audit)

    return G


def subgraph_divided(subgraphs, apachelogs, pglogs):
    print(subgraphs)
    # 记录划分后的等价子图情况。
    divided_available = dict()
    divided_available['apache'] = dict()
    divided_available['postgresql'] = dict()
    for idx, items in enumerate(subgraphs.items()):
        label, nets = items
        apachelog = copy.deepcopy(apachelogs[label])
        pglog = copy.deepcopy(pglogs[label])
        del apachelog['timestamp']
        del pglog['time']
        apachelog = str(apachelog)
        pglog = str(pglog)
        if apachelog not in divided_available['apache']:
            divided_available['apache'][apachelog] = list()
            divided_available['apache'][apachelog].append(-1)
        divided_available['apache'][apachelog].append(label)
        if pglog not in divided_available['postgresql']:
            divided_available['postgresql'][pglog] = list()
            divided_available['apache'][apachelog].append(-1)
        divided_available['postgresql'][pglog].append(label)
    return divided_available

def save_all_graph(auditlist):
    all_graph_list = []
    audit_loglist = []
    for audit in auditlist:
        audit_loglist.append(audit.log)

    G = audit_to_graph(audit_loglist)
    all_graph_list.append(G)
    print(len(G.edges(keys=True, data=True)))

    with open("all_graph_list.pickle", "wb") as f:
        pickle.dump(all_graph_list, f)

def save_snapshots(auditlist):
    all_graph_list = []
    length = len(auditlist)
    print(f'Original Length:{length}')
    n = 5  # 平均 5 等份
    step = int(length/ n)  # 步长
    audits = [auditlist[i:i + step] for i in range(0, length-1, step)]
    audits.append(auditlist[4*step:])
    all_length = 0
    for i in range(n):
        all_length += len(audits[i])
    print(f'After Length:{all_length}')
    for auditlist in audits:
        audit_loglist = []
        for audit in auditlist:
            audit_loglist.append(audit.log)
            G = audit_to_graph(audit_loglist)
            all_graph_list.append(G)
            print(len(G.edges(keys=True, data=True)))

    with open("graph_snapshots.pickle", "wb") as f:
        pickle.dump(all_graph_list, f)

if __name__ == '__main__':
    subgraphs, netlogs, apachelogs, pglogs = getSubgraphs()
    divided_available = subgraph_divided(subgraphs, apachelogs, pglogs)


    lines = auditd_log2default(filepath="../Logs/Apache_Pgsql", filename="audit.log")
    auditlist = []
    for line in lines:
        auditlist.append(AuditLog(line))
    print(len(auditlist))

    save_all_graph(auditlist)

    start = OverheadStart()
    print("规则集进行测试")
    test_divided_log(auditlist)
    print("规则集完成测试")

    print('开始计算分数...')

    auditlist = evaluate_score(auditlist, subgraphs, netlogs, apachelogs, pglogs, divided_available)
    OverheadEnd(start, '计算分数结束...\n')
    manual_verify(auditlist, subgraphs, apachelogs, pglogs)
