import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
import math
import time
from tqdm import tqdm
import json
from Parse.AppNetAuditFusion.auditLog import AuditLog
from Parse.AppNetAuditFusion.auditparser import auditd_log2default
import pickle
from utils import *
import networkx as nx
import copy
from Parse.Compress.main import *
from parse_args import args
import re
def replace_last_occurrence(string, pattern, replacement):
    last_match = None
    for match in re.finditer(pattern, string):
        last_match = match
    if last_match:
        start, end = last_match.span()
        result = string[:start] + replacement + string[end:]
        return result
    else:
        return string

def getSubgraphs(datasetname) -> (dict(), [], [], []):
    if datasetname == 'Apache_Pgsql':
        lower_dataset_name = datasetname.lower()
        with open(f'../Data/{datasetname}/net_{lower_dataset_name}.json', 'r') as f:
            data = json.load(f)
            subgraphs = dict()
            data['netnapache'] = list(map(int, data['netnapache']))
            for index, label in enumerate(data['netnapache']):
                if label == -1:
                    continue
                if subgraphs.get(label) is not None:
                    subgraphs[label].append(index)
                else:
                    subgraphs[label] = []
                    subgraphs[label].append(index)
            data['netnpostgresq'] = list(map(int, data['netnpostgresq']))
            for index, label in enumerate(data['netnpostgresq']):
                if label == -1:
                    continue
                if subgraphs.get(label) is not None:
                    subgraphs[label].append(index)
                else:
                    subgraphs[label] = []
                    subgraphs[label].append(index)

        return subgraphs, data['netlogs'], data['apachelogs'], data['postgresqlogs']
    elif args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016':
        lower_dataset_name = datasetname.lower()
        with open(f'../Data/{datasetname}/net_{lower_dataset_name}.json', 'r') as f:
            data = json.load(f)
            subgraphs = dict()
            for apache_log in data[f'apachelogs']:
                label = int(apache_log['label'])
                subgraphs[label] = []
            for imagemagick_log in data[f'imagemagicklogs']:
                label = int(imagemagick_log['label'])
                subgraphs[label] = []

            data['netnapache'] = list(map(int, data['netnapache']))
            for index, label in enumerate(data['netnapache']):
                if label == -1:
                    continue
                if subgraphs.get(label) is not None:
                    subgraphs[label].append(index)
                else:
                    subgraphs[label] = []
                    subgraphs[label].append(index)
            data['netnimagemagick'] = list(map(int, data['netnimagemagick']))
            for index, label in enumerate(data['netnimagemagick']):
                if label == -1:
                    continue
                label = data['imagemagicklogs'][label]["label"]
                if subgraphs.get(label) is not None:
                    subgraphs[label].append(index)
                else:
                    subgraphs[label] = []
                    subgraphs[label].append(index)
        return subgraphs, data['netlogs'], data['apachelogs'], data['imagemagicklogs']
    elif args.dataset == 'Vim':
        lower_dataset_name = datasetname.lower()
        with open(f'../Data/{datasetname}/net_{lower_dataset_name}.json', 'r') as f:
            data = json.load(f)
            subgraphs = dict()
            for vim_log in data[f'{lower_dataset_name}logs']:
                label = int(vim_log['label'])
                subgraphs[label] = []
        return subgraphs, data['netlogs'], data[f'{lower_dataset_name}logs']
    else:
        lower_dataset_name = datasetname.lower()
        empty_list = []
        with open(f'../Data/{datasetname}/net_{lower_dataset_name}.json', 'r') as f:
            data = json.load(f)
            subgraphs = dict()
            data[f'netn{lower_dataset_name}'] = list(map(int, data[f'netn{lower_dataset_name}']))
            for index, label in enumerate(data[f'netn{lower_dataset_name}']):
                if label == -1:
                    continue
                if subgraphs.get(label) is not None:
                    subgraphs[label].append(index)
                else:
                    subgraphs[label] = []
                    subgraphs[label].append(index)
            for app_log in data[f'{lower_dataset_name}logs']:
                label = int(app_log['label'])
                if subgraphs.get(label) is None:
                    subgraphs[label] = []
                    empty_list.append(label)
        print(f'Empty List Equals {empty_list}')
        return subgraphs, data['netlogs'], data[f'{lower_dataset_name}logs']


def history_report(subgraph_dict):
    for key in subgraph_dict:
        cnt_history = dict()
        audit_list = subgraph_dict[key]['audit']
        for audit_record in audit_list:
            if (len(audit_record['score_history'])) >=2:
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

    with open(f'../Data/{args.dataset}/not_matched_pids.json','w') as f:
        json.dump(not_matched_pids, f)

def manual_verify(all_graph, subgraphs, apachelogs, pglogs, node_ids):
    if args.dataset == 'Apache_Pgsql':
        app1name = 'apache'
        app2name = 'pgsql'
    elif args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016':
        app1name = 'apache'
        app2name = 'imagemagick'
    subgraph_dict = dict()
    f_notin = open(f'../Data/{args.dataset}/not_mapped_subgraph.txt','w')
    if (args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016'):
        label_indices = get_indices_by_label(pglogs)
    lower_dataset_name = args.dataset.lower()
    for src, dst, key, attrs in all_graph.edges(data=True, keys=True):
        if attrs['label'] == '_1':
            continue
        if attrs['label'] not in subgraph_dict:
            subgraph_dict[attrs['label']] = dict()
            subgraph_dict[attrs['label']]['audit'] = list()
            subgraph_dict[attrs['label']]['nets'] = list()
        log_record = attrs['log_data']
        log_record['s1_time'] = attrs['log_data']['s1']
        log_record['s2_relevance'] = attrs['log_data']['s2']
        log_record['score_history'] = attrs['log_data']['score_history']
        log_record['label'] = attrs['label']
        subgraph_dict[attrs['label']]['audit'].append(log_record)
    for label, nets in subgraphs.items():
        if label not in subgraph_dict:
            subgraph_dict[label] = dict()
            subgraph_dict[label]['audit'] = list()
            subgraph_dict[label]['nets'] = list()
            f_notin.writelines(str(label) + '\n')
            f_notin.writelines(str(apachelogs[label]) + '\n')
            f_notin.writelines(str(pglogs[label]) + '\n')
        subgraph_dict[label][app1name] = apachelogs[label]
        if (args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016'):
            subgraph_dict[label][app2name] = []
            all_app2_log_list = label_indices[label]
            for app2_index in all_app2_log_list:
                app2_log = pglogs[app2_index]
                subgraph_dict[label][app2name].append(app2_log)
        else:
            subgraph_dict[label][app2name] = pglogs[label]
        for index, net in enumerate(nets):
            netlog = netlogs[net]
            subgraph_dict[label]['nets'].append(netlog)
    non_cnt = 0
    app_logs_dict = dict()
    equal_dict = dict()
    all_connect = list()
    pickle_list = [nx.MultiDiGraph() for _ in range(len(subgraphs))]
    all_cnt = 0
    all_node_cnt = 0
    for key in subgraph_dict:
        audit = subgraph_dict[key]['audit']
        label_edges = find_label_edges(all_graph, key)
        time_range = find_label_edges_time_range(label_edges)
        connected_graph, this_connect  = build_connected_graph(all_graph, label_edges, time_range,all_connect)
        if this_connect != None:
            all_connect.append(this_connect)
        if key not in app_logs_dict:
            app_logs_dict[key] = dict()
        app_logs_dict[key][app1name] = apachelogs[key]
        if (args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016'):
            app_logs_dict[key][app2name] = []
            all_app2_log_list = label_indices[key]
            for app2_index in all_app2_log_list:
                app2_log = pglogs[app2_index]
                app_logs_dict[key][app2name].append(app2_log)
        else:
            app_logs_dict[key][app2name] = pglogs[key]

        print(f'Graph Of Label {key} Contains {len(connected_graph.edges(data=True))} All Record')
        all_cnt += len(connected_graph.edges(data=True))
        all_node_cnt += len(connected_graph.nodes(data=True))
        pickle_list[key] = connected_graph
        if args.dataset != 'Apache' and args.dataset != 'Nginx' :
            dataset_equal_rule = equal_dataset[args.dataset]
            source, fields = get_source_fields(dataset_equal_rule)
            test_app_data = []
            if (args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016'):
                equal_app_log = app_logs_dict[key][source][0]
            else:
                equal_app_log = app_logs_dict[key][source]
            for field in fields:
                test_app_data.append(equal_app_log[field])

            for _, data in dataset_equal_rule.items():
                for rule_data in data:
                    rule_data_str = ''.join(str(x) + ' ' for x in rule_data)
                    if rule_data_str not in equal_dict:
                        equal_dict[rule_data_str] = []
                    if check_equal(rule_data, test_app_data):
                        equal_dict[rule_data_str].append(key)

        elif args.dataset == 'Apache':
            dataset_equal_rule = equal_dataset[args.dataset]
            for node_name, attributes in connected_graph.nodes(data=True):
                for _, data in dataset_equal_rule.items():
                    for rule_data in data:
                        rule_data_str = ''.join(str(x) + ' ' for x in rule_data)
                        if rule_data_str not in equal_dict:
                            equal_dict[rule_data_str] = []
                        if check_equal_apache(rule_data, node_name) and key not in equal_dict[rule_data_str]:
                            equal_dict[rule_data_str].append(key)
                            break

        elif args.dataset == 'Nginx':
            dataset_equal_rule = equal_dataset[args.dataset]
            for node_name, attributes in connected_graph.nodes(data=True):
                for _, data in dataset_equal_rule.items():
                    for rule_data in data:
                        rule_data_str = ''.join(str(x) + ' ' for x in rule_data)
                        if rule_data_str not in equal_dict:
                            equal_dict[rule_data_str] = []
                        if check_equal_apache(rule_data, node_name) and key not in equal_dict[rule_data_str]:
                            equal_dict[rule_data_str].append(key)
                            break


        if len(audit) == 0:
            non_cnt += 1
    sum_euql = 0
    for _, equal_data in equal_dict.items():
        sum_euql += len(equal_data)
    print(f'Number Of Empty Graph Is {non_cnt}')
    print(f'Number Of Graphs Is {len(pickle_list)}')
    print(f'Number Of Equal Graphs Is {sum_euql}')
    print(f'All Edge Count Numer Is {all_cnt}')
    print(f'All Node Count Numer Is {all_node_cnt}')

    with open(f"../Data/{args.dataset}/{lower_dataset_name}.pickle", "wb") as f:
        pickle.dump(subgraph_dict, f)
    with open(f'../Data/{args.dataset}/{lower_dataset_name}.json','w') as f:
        json.dump(subgraph_dict, f)
    with open(f"../Data/{args.dataset}/graph_list.pickle", "wb") as f:
        pickle.dump(pickle_list, f)

    test_node_existence(pickle_list)

    save_high_level_logs(app_logs_dict)

    save_equal_dict(equal_dict)


def manual_verify_single(all_graph, subgraphs, applogs, node_ids):
    subgraph_dict = dict()
    f_notin = open(f'../Data/{args.dataset}/not_mapped_subgraph.txt','w')
    lower_dataset_name = args.dataset.lower()
    pickle_list_range = 0

    for src, dst, key, attrs in all_graph.edges(data=True, keys=True):
        if attrs['label'] == '_1':
            continue
        if attrs['label'] not in subgraph_dict:
            subgraph_dict[attrs['label']] = dict()
            subgraph_dict[attrs['label']]['audit'] = list()
            subgraph_dict[attrs['label']]['nets'] = list()
        log_record = attrs['log_data']
        log_record['s1_time'] = attrs['log_data']['s1']
        log_record['s2_relevance'] = attrs['log_data']['s2']
        log_record['score_history'] = attrs['log_data']['score_history']
        log_record['label'] = attrs['label']
        subgraph_dict[attrs['label']]['audit'].append(log_record)

    for label, nets in subgraphs.items():
        pickle_list_range = max(pickle_list_range, label)
        if label not in subgraph_dict:
            subgraph_dict[label] = dict()
            subgraph_dict[label]['audit'] = list()
            subgraph_dict[label]['nets'] = list()
            f_notin.writelines(str(label) + '\n')
            f_notin.writelines(str(applogs[label]) + '\n')
        subgraph_dict[label][lower_dataset_name] = applogs[label]
        for index, net in enumerate(nets):
            netlog = netlogs[net]
            subgraph_dict[label]['nets'].append(netlog)

    non_cnt = 0

    app_logs_dict = dict()
    equal_dict = dict()
    dataset_equal_rule = equal_dataset[args.dataset]
    source, fields = get_source_fields(dataset_equal_rule)
    all_connect = list()
    all_cnt  = 0
    all_node_cnt = 0
    for _, data in dataset_equal_rule.items():
        for rule_data in data:
            rule_data_str = ''.join(str(x) + ' ' for x in rule_data)
            if rule_data_str not in equal_dict:
                equal_dict[rule_data_str] = []

    pickle_list = [nx.MultiDiGraph() for _ in range(pickle_list_range +1)]
    add_cnt = 20
    for key in subgraph_dict:
        audit = subgraph_dict[key]['audit']

        label_edges = find_label_edges(all_graph, key)
        time_range = find_label_edges_time_range(label_edges)


        connected_graph, this_connect = build_connected_graph(all_graph, label_edges, time_range, all_connect)
        if this_connect != None:
            all_connect.append(this_connect)


        if key not in app_logs_dict:
            app_logs_dict[key] = dict()
        app_logs_dict[key][lower_dataset_name] = applogs[key]

        print(f'Graph Of Label {key} Contains {len(connected_graph.edges(data=True))} All Record')
        all_cnt += len(connected_graph.edges(data=True))
        all_node_cnt += len(connected_graph.nodes(data=True))
        pickle_list[key] = connected_graph

        occur_set = set()
        if args.dataset != 'Apache' and args.dataset != 'Nginx':
            test_app_data = []
            equal_app_log = app_logs_dict[key][source]
            for field in fields:
                test_app_data.append(equal_app_log[field])

            for _, data in dataset_equal_rule.items():
                for rule_data in data:
                    rule_data_str = ''.join(str(x) + ' ' for x in rule_data)
                    if check_equal(rule_data, test_app_data):
                        equal_dict[rule_data_str].append(key)
        elif args.dataset == 'Apache':
            dataset_equal_rule = equal_dataset[args.dataset]
            for node_name, attributes in connected_graph.nodes(data=True):
                for _, data in dataset_equal_rule.items():
                    for rule_data in data:
                        rule_data_str = ''.join(str(x) + ' ' for x in rule_data)
                        if rule_data_str not in equal_dict:
                            equal_dict[rule_data_str] = []
                        if check_equal_apache(rule_data, attributes['name']) and key not in equal_dict[rule_data_str]:
                            equal_dict[rule_data_str].append(key)
        elif args.dataset == 'Nginx':
            dataset_equal_rule = equal_dataset[args.dataset]
            for _, data in dataset_equal_rule.items():
                for rule_data in data:
                    rule_data_str = ''.join(str(x) + ' ' for x in rule_data)
                    if rule_data_str not in equal_dict:
                        equal_dict[rule_data_str] = []
                    for node_name, attributes in connected_graph.nodes(data=True):
                        if check_equal_apache(rule_data, attributes['name']) and key not in equal_dict[rule_data_str] and key not in occur_set:
                            equal_dict[rule_data_str].append(key)
                            occur_set.add(key)

    if args.dataset == 'Nginx':
        all_assign = []
        missing = str()
        for k,v in equal_dict.items():
            if len(v) == 0:
                missing = k
            all_assign.extend(v)
        for key in subgraph_dict:
            if key not in all_assign:
                equal_dict[missing].append(key)


        if len(audit) == 0:
            non_cnt += 1

    if args.dataset in ['Apache', 'Redis', 'Proftpd', 'Nginx']:
        pattern = r'\b[A-Z]{3}:\s*\d+\b'
        if args.dataset == 'Apache':
            key_idxs= [402, 501]
            for key_idx in key_idxs:
                key_str = ''
                for k, v in equal_dict.items():
                    if key_idx in v:
                        key_str = k
                if key_idx == 402:
                    for cnt in range(10):
                        equal_dict[key_str].append(len(pickle_list))
                        subgraph_dict[len(pickle_list)] = subgraph_dict[key_idx]
                        app_logs_dict[len(pickle_list)] = app_logs_dict[key_idx]
                        graph = pickle_list[key_idx]
                        for node_name, attributes in graph.nodes(data=True):
                            attributes['name'] = replace_last_occurrence(attributes['name'], pattern, str(cnt))
                        pickle_list.append(graph)
                else:
                    for cnt in range(21, 31):
                        equal_dict[key_str].append(len(pickle_list))
                        subgraph_dict[len(pickle_list)] = subgraph_dict[key_idx]
                        app_logs_dict[len(pickle_list)] = app_logs_dict[key_idx]
                        graph = pickle_list[key_idx]
                        for node_name, attributes in graph.nodes(data=True):
                            attributes['name'] = replace_last_occurrence(attributes['name'], pattern, str(cnt))
                        pickle_list.append(graph)
        if args.dataset == 'Redis':
            key_idxs= [50]
            for key_idx in key_idxs:
                key_str = ''
                for k, v in equal_dict.items():
                    if key_idx in v:
                        key_str = k
                for cnt in range(10):
                    equal_dict[key_str].append(len(pickle_list))
                    subgraph_dict[len(pickle_list)] = subgraph_dict[key_idx]
                    app_logs_dict[len(pickle_list)] = app_logs_dict[key_idx]
                    graph = pickle_list[key_idx]
                    for node_name, attributes in graph.nodes(data=True):
                        attributes['name'] = replace_last_occurrence(attributes['name'], pattern, str(cnt))
                    pickle_list.append(graph)
        if args.dataset == 'Proftpd':
            key_idx = 500
            key_str = ''
            for k, v in equal_dict.items():
                if key_idx in v:
                    key_str = k
            for cnt in range(11):
                equal_dict[key_str].append(len(pickle_list))
                subgraph_dict[len(pickle_list)] = subgraph_dict[key_idx]
                app_logs_dict[len(pickle_list)] = app_logs_dict[key_idx]
                graph = pickle_list[key_idx]
                for node_name, attributes in graph.nodes(data=True):
                    attributes['name'] = replace_last_occurrence(attributes['name'], pattern, str(cnt))
                pickle_list.append(graph)
        if args.dataset == 'Nginx':
            key_idx = 998
            key_str = ''
            for k, v in equal_dict.items():
                if key_idx in v:
                    key_str = k
            for cnt in range(30):
                equal_dict[key_str].append(len(pickle_list))
                subgraph_dict[len(pickle_list)] = subgraph_dict[key_idx]
                app_logs_dict[len(pickle_list)] = app_logs_dict[key_idx]
                graph = pickle_list[key_idx]
                for node_name, attributes in graph.nodes(data=True):
                    attributes['name'] = replace_last_occurrence(attributes['name'], pattern, str(cnt))
                pickle_list.append(graph)
    sum_euql = 0
    for _, equal_data in equal_dict.items():
        sum_euql += len(equal_data)
    print(f'Number Of Empty Graph Is {non_cnt}')
    print(f'Number Of Graphs Is {len(pickle_list)}')
    print(f'Number Of Equal Graphs Is {sum_euql}')
    print(f'All Edge Count Numer Is {all_cnt}')
    print(f'All Node Numer Is {all_node_cnt}')


    with open(f"../Data/{args.dataset}/{lower_dataset_name}.pickle", "wb") as f:
        pickle.dump(subgraph_dict, f)
    with open(f'../Data/{args.dataset}/{lower_dataset_name}.json','w') as f:
        json.dump(subgraph_dict, f)
    with open(f"../Data/{args.dataset}/graph_list.pickle", "wb") as f:
        pickle.dump(pickle_list, f)

    test_node_existence(pickle_list)


    save_high_level_logs(app_logs_dict)


    save_equal_dict(equal_dict)

    check_triple(pickle_list)

def check_triple(pickle_list):
    triplet = set()
    for graph in pickle_list:
        for source, target, key, attributes in graph.edges(keys=True, data=True):
            src = attributes['src']
            dst = attributes['dst']
            relation = attributes['relation']
            triplet.add((src, dst, relation))



def test_divided_log(auditlist):
    cnt = 0
    with tqdm(total=len(auditlist)) as pbar:
        pbar.set_description('Processing:')
        for audit_log in auditlist:
            log_record  = audit_log.log
            if log_record['action'] == 'sys_getsockname' and log_record['port'] == 80:
                cnt += 1



def audit_to_graph(auditlist):
    G = nx.MultiDiGraph()
    for audit in auditlist:
        src = audit['src_name']
        dst = audit['dst_name']
        src_type = audit['src_type']
        dst_type = audit['dst_type']
        relation = audit['action']


        G.add_node(src, name=src, entity_type=src_type)
        G.add_node(dst, name=dst, entity_type=dst_type)
        G.add_edge(src, dst, relation=relation, log_record=audit)

    return G


def audit_to_graph_ids(auditlist, node_ids = None):
    G = nx.MultiDiGraph()
    return_node_ids = False


    if node_ids == None:
        return_node_ids = True
        node_ids = dict()
    for audit_log in auditlist:
        audit = audit_log.log
        src = audit['process_name']
        src_type = 'Process'

        if audit['file'] != None:
            dst = audit['file']
            dst_type = 'File'
        elif audit['ip'] != None:
            dst = audit['ip'] + ':' + str(audit['port'])
            dst_type = 'Socket'
        elif audit['action'] == 'sys_clone':
            dst = audit_log.subject.entity_data
            dst_type = 'Process'
        else:
            continue
        if src not in node_ids:
            node_ids[src] = len(node_ids)

        src_id = node_ids[src]
        if dst not in node_ids:
            node_ids[dst] = len(node_ids)
        dst_id = node_ids[dst]

        relation = audit['action']
        if relation in reverse_set:
            src, dst = dst, src
            src_id, dst_id = dst_id, src_id
            src_type, dst_type = dst_type, src_type

        G.add_node(src_id, name=src, entity_type=src_type)
        G.add_node(dst_id, name=dst, entity_type=dst_type)
        G.add_edge(src_id, dst_id, Timestamp=audit_log.Timestamp, src=src, dst=dst, label=audit_log.label, payload=audit_log.payload, type='audit', relation=relation, log_data=audit, log_type=relation)

    if return_node_ids:
        return G, node_ids 
    else:
        return G


def audit_to_graph_ids_dict(auditlist, node_ids = None):
    G = nx.MultiDiGraph()
    return_node_ids = False
    if node_ids == None:
        return_node_ids = True
        node_ids = dict()
    for audit_log in auditlist:
        audit = audit_log
        src = audit['process_name']
        src_type = 'Process'

        if audit['file'] != None:
            dst = audit['file']
            dst_type = 'File'
        elif audit['ip'] != None:
            dst = audit['ip'] + ':' + str(audit['port'])
            dst_type = 'Socket'
        elif audit['action'] == 'sys_clone':
            dst = audit_log.subject.entity_data
            dst_type = 'Process'
        else:
            continue
        if src not in node_ids:
            node_ids[src] = len(node_ids)

        src_id = node_ids[src]
        if dst not in node_ids:
            node_ids[dst] = len(node_ids)
        dst_id = node_ids[dst]

        relation = audit['action']
        if relation in reverse_set:
            src, dst = dst, src
            src_id, dst_id = dst_id, src_id
            src_type, dst_type = dst_type, src_type


        G.add_node(src_id, name=src, entity_type=src_type)
        G.add_node(dst_id, name=dst, entity_type=dst_type)
        G.add_edge(src_id, dst_id, Timestamp=audit['Timestamp'], label=audit['label'], payload=audit['payload'], type='audit', relation=relation, log_data=audit, log_type=relation)

    if return_node_ids:
        return G, node_ids
    else:
        return G


def subgraph_divided(subgraphs, applogs1, applogs2=None):

    if args.dataset == 'Apache_Pgsql':
        divided_available = dict()
        divided_available['apache'] = dict()
        divided_available['postgresql'] = dict()
        for idx, items in enumerate(subgraphs.items()):
            label, nets = items
            apachelog = copy.deepcopy(applogs1[label])
            pglog = copy.deepcopy(applogs2[label])
            del apachelog['Timestamp']
            del pglog['Timestamp']
            apachelog = str(apachelog)
            pglog = str(pglog)
            if apachelog not in divided_available['apache']:
                divided_available['apache'][apachelog] = list()
                divided_available['apache'][apachelog].append(-1)
            divided_available['apache'][apachelog].append(label)
            if pglog not in divided_available['postgresql']:
                divided_available['postgresql'][pglog] = list()
                divided_available['postgresql'][pglog].append(-1)
            divided_available['postgresql'][pglog].append(label)
    elif args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016':
        divided_available = dict()
        divided_available['apache'] = dict()
        divided_available['imagemagick'] = dict()
        for idx, items in enumerate(subgraphs.items()):
            label, nets = items

            print(label)
            applog1 = copy.deepcopy(applogs1[label])
            applog2 = copy.deepcopy(applogs2[label])
            del applog1['Timestamp']
            del applog1['label']
            del applog2['Timestamp']
            del applog2['label']
            applog1 = 'apache'
            applog2 = str(applog2)
            if applog1 not in divided_available['apache']:
                divided_available['apache'][applog1] = list()
                divided_available['apache'][applog1].append(-1)
            divided_available['apache'][applog1].append(label)
            if applog2 not in divided_available['imagemagick']:
                divided_available['imagemagick'][applog2] = list()
                divided_available['imagemagick'][applog2].append(-1)
            divided_available['imagemagick'][applog2].append(label)

    elif args.dataset == 'Apache':
        divided_available = dict()
        divided_available[args.dataset] = dict()
        for idx, items in enumerate(subgraphs.items()):
            label, nets = items
            applog = 'apache'
            if applog not in divided_available[args.dataset]:
                divided_available[args.dataset][applog] = list()
                divided_available[args.dataset][applog].append(-1)
            divided_available[args.dataset][applog].append(label)
    elif args.dataset == 'Php':
        divided_available = dict()
        divided_available[args.dataset] = dict()
        for idx, items in enumerate(subgraphs.items()):
            label, nets = items
            applog = 'php'
            if applog not in divided_available[args.dataset]:
                divided_available[args.dataset][applog] = list()
                divided_available[args.dataset][applog].append(-1)
            divided_available[args.dataset][applog].append(label)
    elif args.dataset == 'Nginx':
        divided_available = dict()
        divided_available[args.dataset] = dict()
        for idx, items in enumerate(subgraphs.items()):
            label, nets = items
            applog = 'nginx'
            if applog not in divided_available[args.dataset]:
                divided_available[args.dataset][applog] = list()
                divided_available[args.dataset][applog].append(-1)
            divided_available[args.dataset][applog].append(label)
    else:
        divided_available = dict()
        divided_available[args.dataset] = dict()
        for idx, items in enumerate(subgraphs.items()):
            label, nets = items
            applog = copy.deepcopy(applogs1[label])
            del applog['Timestamp']
            applog = normalize_field(applog)
            applog = str(applog)
            if applog not in divided_available[args.dataset]:
                divided_available[args.dataset][applog] = list()
                divided_available[args.dataset][applog].append(-1)
            divided_available[args.dataset][applog].append(label)

    return divided_available

def save_all_graph(auditlist):
    all_graph_list = []
    audit_loglist = []
    for audit in auditlist:
        audit_loglist.append(audit)

    G, node_ids = audit_to_graph_ids(audit_loglist)
    print(f'Edge Number Before Compressing:{len(G.edges(data=True))}')
    G, compressConfig = graph_compress(G)

    isolated_nodes = list(nx.isolates(G))

    G.remove_nodes_from(isolated_nodes)

    G, node_ids = relabel_nodes_and_edges(G)
    print(f'Edge Number After Compressing:{len(G.edges(data=True))}')
    all_graph_list.append(G)


    with open(f"../Data/{args.dataset}/all_graph_list.pickle", "wb") as f:
        pickle.dump(all_graph_list, f)
    return G, node_ids
def save_snapshots(auditlist):
    all_graph_list = []
    length = len(auditlist)
    relation_type_list = []

    real_snapshot = 5
    n = 4  
    step = int(length/ n) 
    audits = [auditlist[i:i + step] for i in range(0, 3*step, step)]
    audits.append(auditlist[3*step:])
    audits.append(auditlist) 
    all_length = 0
    for i in tqdm(range(real_snapshot)):
        all_length += len(audits[i])

    for auditlist in tqdm(audits):

        G = audit_to_graph(auditlist)
        all_graph_list.append(G)

    for subgraph in all_graph_list:
        edge_set = set()
        for src, dst, key, attributes in subgraph.edges(keys=True, data=True):
            edge_set.add(attributes['relation'])
        relation_type_list.append(len(edge_set))

    with open(f"../Data/{args.dataset}/graph_snapshots.pickle", "wb") as f:
        pickle.dump(all_graph_list, f)

def save_graph_schema(all_graph):
    all_graph_list = []
    audit_loglist = []

    for src, dst, key, data in all_graph.edges(data=True,keys=True):
        log_data = data['log_data']
        src_attributes = all_graph.nodes[src]
        dst_attributes = all_graph.nodes[dst]
        log_data['src_name'] = src_attributes['name']
        log_data['dst_name'] = dst_attributes['name']
        log_data['src_type'] = src_attributes['entity_type']
        log_data['dst_type'] = dst_attributes['entity_type']
        audit_loglist.append(log_data)
    G = audit_to_graph(audit_loglist)
    all_graph_list.append(G)


    with open(f"../Data/{args.dataset}/graph_schema.pickle", "wb") as f:
        pickle.dump(all_graph_list, f)
    return audit_loglist

def check_node_id(node_ids):
    max_value = -1
    min_value = sys.maxsize
    for key, value in node_ids.items():
        max_value = max(max_value, value)
        min_value = min(min_value, value)



def trans_name(auditlist):
    for audit_log in auditlist:

        if audit_log.log['ip'] == '::ffff:a66f:522e':
            audit_log.log['ip'] = '166.111.82.46'
        if audit_log.log['ip'] == '::ffff:127.0.0.1':
            audit_log.log['ip'] = '192.168.119.1'
        if audit_log.log['ip'] == '::ffff:192.168.119.133':
            audit_log.log['ip'] = '192.168.119.133'
        if audit_log.log['ip'] == '::ffff:192.168.119.23':
            audit_log.log['ip'] = '192.168.119.23'
    return auditlist

def graph_compress(G):
    compressConfig = CompressConfig()
    G, compressConfig = compress(G, compressConfig)

    if compressConfig.count_origin_application_edges != 0:
        print("===============================")
        print(f"number of origin application edges: {compressConfig.count_origin_application_edges}")
        print(f"number of cpr removed application edges: {compressConfig.count_removed_application_edges}")
        print(
            f"application compress rate: {compressConfig.count_removed_application_edges / compressConfig.count_origin_application_edges}")
    print("===============================")
    print(f"number of origin auditd edges: {compressConfig.count_origin_auditd_edges}")
    print(f"number of cpr removed auditd edges: {compressConfig.count_removed_auditd_edges}")
    print(
        f"auditd compress rate: {compressConfig.count_removed_auditd_edges / compressConfig.count_origin_auditd_edges}")
    print("===============================")

    print("===============================")
    print(
        f"total remained edges: {compressConfig.count_origin_auditd_edges + compressConfig.count_origin_application_edges + compressConfig.count_origin_net_edges - compressConfig.count_removed_auditd_edges - compressConfig.count_removed_application_edges - compressConfig.count_removed_net_edges}")
    print(
        f"remained application edges: {compressConfig.count_origin_application_edges - compressConfig.count_removed_application_edges}")
    print(
        f"remained auditd edges: {compressConfig.count_origin_auditd_edges - compressConfig.count_removed_auditd_edges}")
    print(f"remained net edges: {compressConfig.count_origin_net_edges - compressConfig.count_removed_net_edges}")
    return G, compressConfig

def save_high_level_logs(app_logs_dict):
    with open(f"../Data/{args.dataset}/app_graph_dict.pickle", "wb") as f:
        pickle.dump(app_logs_dict, f)
    with open(f'../Data/{args.dataset}/app_graph_dict.json','w') as f:
        json.dump(app_logs_dict, f)

def save_equal_dict(equal_dict):
    with open(f"../Data/{args.dataset}/equal_dict.pickle", "wb") as f:
        pickle.dump(equal_dict, f)
    with open(f'../Data/{args.dataset}/equal_dict.json','w') as f:
        json.dump(equal_dict, f)


def check_clone(auditlist):
    for audit in  auditlist:
        if audit.action == 'sys_clone':
            print(f"Object: {audit.object}")
            print(f"Subject: {audit.subject}")
            print(f"Action: {audit.action}")
            print(f"Payload: {audit.payload}")
            print(f"Label: {audit.label}")
            print(f"Log: {audit.log}")
            print(f"Action:{audit.action}")
            print(f"TimeStamp:{audit.Timestamp}")
            print(f"audit.object.entity_name:{audit.object.entity_name}")
            print(f"audit.object.entity_type:{audit.object.entity_type}")
            print(f"audit.object.entity_data:{audit.object.entity_data}")
            print(f"audit.subject.entity_name:{audit.subject.entity_name}")
            print(f"audit.subject.entity_type:{audit.subject.entity_type}")
            print(f"audit.subject.entity_data:{audit.subject.entity_data}")
            if audit.object.entity_data == 'postgres' and audit.subject.entity_data == 'cat':
                print('Successfully Get Anomaly Relation')

def handle_process_process_relation(auditlist):
    processed_auditlist = []
    clone_node_mapping = dict()
    clone_parent_mapping = dict()
    parent_child_relation = dict()

    for log in auditlist:
        nodelist = [log.subject, log.object]

        if log.action == 'sys_clone':

            parent_child_relation[log.subject.entity_name] = log.object.entity_name

            if log.subject.entity_name not in clone_node_mapping:
                clone_node_mapping[log.subject.entity_name] = None

            if log.object.entity_name not in clone_parent_mapping:
                clone_parent_mapping[str(log.object.entity_name)] = log.object.entity_data

        for _node in nodelist:
            if _node.entity_name in clone_node_mapping.keys():

                if clone_node_mapping[_node.entity_name] == None and  _node.entity_data != None and _node.entity_type !=1:

                    clone_node_mapping[_node.entity_name] = _node.entity_data

    for log in auditlist:
        if log.action == 'sys_execve':
            ppid = str(log.log['ppid'])

            if ppid not in clone_node_mapping:

                continue
            if clone_node_mapping[ppid] == None:

                gpid = parent_child_relation[ppid]
                clone_node_mapping[ppid] = clone_parent_mapping[gpid]

    for key in clone_node_mapping:
        if clone_node_mapping[key] == None and args.dataset != 'Vim':
            print('clone node mapping generateing failed!')


    for log in auditlist:
        simulate_log = None
        if log.action == 'sys_clone':
            log.subject.entity_data = clone_node_mapping[log.subject.entity_name]

            log.log['ppname'] = log.object.entity_data
            log.log['pname'] = log.subject.entity_data
        if log.action == 'sys_execve':
            ppid = str(log.log['ppid'])
            if ppid in clone_node_mapping:

                simulate_log = deepcopy(log)

                simulate_log.action = 'sys_clone'
                simulate_log.log['action'] = 'sys_clone'
                simulate_log.log['file'] = None
                simulate_log.object.entity_name = ppid
                simulate_log.subject.entity_name = log.object.entity_name

                simulate_log.object.entity_data = clone_node_mapping[ppid]
                simulate_log.subject.entity_data = log.object.entity_data

                simulate_log.log['ppname'] = simulate_log.object.entity_data
                simulate_log.log['pname'] = simulate_log.subject.entity_data

        if simulate_log != None:
            if simulate_log.log['ppname'] == 'id' and simulate_log.log['pname'] == 'id' and simulate_log.log['action'] == 'sys_clone':
                pass
            elif simulate_log.log['ppname'] == 'cat' and simulate_log.log['pname'] == 'cat' and simulate_log.log['action'] == 'sys_clone':
                pass
            else:
                processed_auditlist.append(simulate_log)

        if log.action == 'sys_stat' or log.action == 'sys_lstat':
            pass
        elif log.Timestamp == '1682738318831000' and log.action == 'sys_openat' and log.file == '/test.txt':
            pass
        elif args.dataset == 'Apache' and int(log.Timestamp) < 1682509618570000:
            pass
        elif args.dataset == 'Php' and int(log.Timestamp) < 1684325031922000:
            pass
        elif args.dataset == 'Redis' and int(log.Timestamp) < 1683209904246000:
            pass
        elif (args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016') and (check_delete(log) or check_delete_action(log)):
            pass
        else:
            processed_auditlist.append(log)
    return processed_auditlist


def compress_dict_list(dict_list):

    if not dict_list:
        return []


    fields = ['process_name', 'action', 'pid', 'ppid', 'ip', 'port', 'file']


    compressed_list = [dict_list[0]]

    for current_dict in tqdm(dict_list[1:]):
        last_dict = compressed_list[-1]

        if all(current_dict.get(key) == last_dict.get(key) for key in fields):
            continue
        compressed_list.append(current_dict)

    return compressed_list

if __name__ == '__main__':
    sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    if args.dataset == 'Apache_Pgsql' or args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016':
        subgraphs, netlogs, applogs1, applogs2 = getSubgraphs(args.dataset)
    else:
        subgraphs, netlogs, applogs = getSubgraphs(args.dataset)

    if args.dataset == 'Apache_Pgsql' or args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016':
        divided_available = subgraph_divided(subgraphs, applogs1, applogs2)
    else:
        divided_available = subgraph_divided(subgraphs, applogs)
    print('================================================================')
    print('Divided_Available Is')
    print(divided_available)

    lines = auditd_log2default(filepath=f"../Data/{args.dataset}", filename="audit.log")
    if args.dataset == 'ImageMagick' or args.dataset =='ImageMagick-2016':
        lines = compress_dict_list(lines)
    print('compress done')
    auditlist = []
    for line in lines:
        auditlist.append(AuditLog(line))

    auditlist = handle_process_process_relation(auditlist)

    if args.dataset != 'ImageMagick':
        auditlist = trans_name(auditlist)



    print('start...')
    start = OverheadStart()
    if args.dataset == 'Apache_Pgsql' or args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016':
        auditlist = evaluate_score(auditlist, subgraphs, netlogs, applogs1, applogs2, divided_available)
    else:
        auditlist = evaluate_score_single(auditlist, subgraphs, netlogs, applogs, divided_available)

    OverheadEnd(start, 'end...\n')

    all_graph, node_ids = save_all_graph(auditlist)
    audit_loglist = save_graph_schema(all_graph)
    save_snapshots(audit_loglist)
    check_node_id(node_ids)
    if args.dataset == 'Apache_Pgsql' or args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016':
        manual_verify(all_graph, subgraphs, applogs1, applogs2, node_ids)
    else:
        manual_verify_single(all_graph, subgraphs, applogs, node_ids)
    print(f'Dataset {args.dataset} Done!')
