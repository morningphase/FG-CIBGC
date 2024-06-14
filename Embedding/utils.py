import copy
import sys
sys.path.append("..")
import os
import pickle
import numpy as np
import matplotlib.pyplot as plt
import time
import torch
import math
import time
import random
import torch.nn as nn
from torch.nn.init import xavier_normal_
from torch.nn import Parameter
import numpy as np
from copy import deepcopy
import sys, os
import networkx as nx
from tqdm import tqdm
from parse_args import args

tsne_config ={
    'vim':{
        'entity':['abc (21st copy).log','abc (21st copy).log','abc (13th copy).log','abc (3rd copy).log', 'abc (12th copy).log',
                  '/home/victim/Desktop/vim/abc (14th copy).log', '/home/victim/Desktop/vim/abc (20th copy).log', '/home/victim/Desktop/vim/abc (16th copy).log', '/home/victim/Desktop/vim/abc (12th copy).log', '/home/victim/Desktop/vim/abc (13th copy).log',
                  'poc.txt', '/home/victim/Desktop/vim/poc.txt',
                  'abc (62nd copy).log', 'abc (78th copy).log',
                  '/home/victim/Desktop/vim/.abc (15th copy).log.swx', '/home/victim/Desktop/vim/.abc (17th copy).log.swx', '/home/victim/Desktop/vim/.abc (11th copy).log.swx',
                  '/usr/sbin/date',],
        'relation':[]
    },
    'apache_pgsql':{
        'entity':[],
        'relation':[]
    }

}

neo4j_url = 'neo4j://127.0.0.1:7687'
neo4j_passwd = "123456"

reverse_set = {'sys_read', 'sys_pread64', 'sys_readv', 'sys_getitimer', 'sys_getpid', 'sys_accept', 'sys_recvfrom',
               'sys_recvmsg', 'sys_getsockname', 'sys_getpeername', 'sys_getsockopt', 'sys_readlink', 'sys_getdents',
               'sys_getcwd', 'sys_gettimeofday', 'sys_getrlimit', 'sys_accept4', 'sys_getrusage', 'sys_getuid',
               'sys_getgid', 'sys_geteuid', 'sys_getegid', 'sys_getppid', 'sys_getpgrp', 'sys_getgroups',
               'sys_getresuid', 'sys_getresgid', 'sys_getpgid', 'sys_getsid', 'sys_getpriority', 'sys_getxattr',
               'sys_lgetxattr', 'sys_fgetxattr', 'sys_getdents64', 'sys_timer_gettime', 'sys_get_mempolicy',
               'sys_readlinkat'}

rule_set = {
    'apache': {
        1: {
        "process_name": 'apache2',
        "action": 'sys_getsockname',
        "port":80
        }
    },
    'imagemagick': {
            1: {
            "process_name": 'apache2',
            "action": 'sys_getsockname',
            "port":80
            }
        },
    'redis': {
            1: {
            "process_name": 'redis-server',
            "action": 'sys_accept',
            "ip": '192.168.229.132'
            },
            2: {
            "process_name": 'redis-server',
            "action": 'sys_accept',
            "ip": '192.168.229.131'
            },
        },
    'httpd':{
        1:{
        "process_name": 'httpd',
        "action": 'sys_getsockname',
        "port":80
        }
    },
    'nginx':{
            1:{
            "process_name": 'nginx',
            "action": 'sys_accept4',
            "ip": '127.0.0.1'
            },

        },
    'php':{
            1:{
            "process_name": 'apache2',
            "action": 'sys_getsockname',
            "port":80
            }
        },
    'proftpd':{
            1:{
            "process_name": 'proftpd',
            "action": 'sys_openat',
            "file": '/abc/test2.txt'
            },
            2:{
            "process_name": 'proftpd',
            "action": 'sys_openat',
            "file": '/test.txt'
            },

        }
}

equal_dataset = {

    'Apache_Pgsql':{ 
        'pgsql_statement':

        [

            ['INSERT INTO student (name, age, major) VALUES'],
            ['select * from student where name ='],
            ['COPY cmd_exec FROM PROGRAM \'id\';'],
            ['COPY cmd_exec FROM PROGRAM \'cat /etc/passwd\';'],
            ['SELECT * FROM cmd_exec'],
            ['TRUNCATE TABLE cmd_exec'],
            ['DROP TABLE IF EXISTS'],
            ['CREATE TABLE'],
        ]
    },
    'ImageMagick':{
        'imagemagick_payload':

        [

            ['/var/www/html/uploads/input'],
            ['/var/www/html/uploads/poc1'],
            ['/var/www/html/uploads/poc2'],
            ['/var/www/html/uploads/poc3'],
        ]
    },
    'ImageMagick-2016':{
        'imagemagick_payload':

        [
 
            ['/var/www/html/uploads/input'],
            ['/var/www/html/uploads/poc1'],
            ['/var/www/html/uploads/poc2'],
            ['/var/www/html/uploads/poc3'],
        ]
    },
    'Apache':{
        'apache_Url':[
            ['etc/passwd'],
            ['c.gif'],
            ['text.png'],
        ]
    },
    'Redis': {
        'redis_Command_Content': [
            ['GET', ''],

            ['stat', '/etc/passwd']
        ]
    },
    'Proftpd': {
        'proftpd_Filename': [
            ['/var/ftp/test.txt'],
            ['/var/ftp/abc/test2.txt'],
            ['/var/ftp/evil.txt'],
        ]
    },
    'Vim': {
        'vim_action_FileName': [
            ['BufRead','copy).log'],
            ['BufRead','poc.txt'],
            ['BufWrite','copy).log']
        ]
    },
    'Nginx':{
        'nginx_Url':[
            ['etc/passwd'],
            ['flag.txt'],
            ['/index.html'],
            ['/files../'],
        ]
    },
    'Php':{
        'php_Url':[
            ['/index.php'],
            ['/index.html'],
            ['/index.php?s=/index/index/name/$%7B$%7B@system(\'/bin/bash%20/opt/ftp/attackk.sh\')%7D%7D'],
            ['/index.php?s=/index/index/name/$%7B$%7B@system($_REQUEST%5B111%5D)%7D%7D'],
        ]
    },


}

def get_indices_by_label(dict_list):

    label_indices = {}
    for index, item in enumerate(dict_list):
        if 'label' in item:
            label = item['label']
            if label not in label_indices:
                label_indices[label] = []
            label_indices[label].append(index)
    return label_indices

def extract_ip(address):

    parts = address.split('/')

    ip_part = parts[0].split(':')

    ip_address = ip_part[-1]
    return ip_address

def check_equal(rule_data, test_app_data):
    for idx in range(len(rule_data)):
        rule = rule_data[idx]
        test_app = test_app_data[idx]
        if rule not in test_app:
            return False
    return True

def check_equal_apache(rule_data, node_name):
    for idx in range(len(rule_data)):
        rule = rule_data[idx]
        if rule != '/icons':
            if rule not in node_name:
                return False
        else:
            if not node_name.endswith(rule):
                return False
    return True


def get_source_fields(rule_dict):
    source_fields = list(rule_dict.keys())[0]
    source_fields = source_fields.split('_')
    source = source_fields[0]
    fields = source_fields[1:]
    return source, fields

def relabel_nodes_and_edges(graph):
    node_list = []
    id_mapping = dict()
    for node_name, attributes in graph.nodes(data=True):
        node_list.append(node_name)
    node_list.sort()
    for idx, node_id in enumerate(node_list):
        id_mapping[node_id] = idx

    relabeled_graph = nx.relabel_nodes(graph, id_mapping, copy=True)
    node_ids = dict()
    for node_name, attributes in relabeled_graph.nodes(data=True):
        node_ids[attributes['name']] = node_name

    return relabeled_graph, node_ids

def mapping_store(mapping, filename, dataset):

    base_directory = f'../Data/{args.dataset}/benchmark'


    subdirectory = dataset

    if not os.path.exists(base_directory):
        os.makedirs(base_directory)
    if not os.path.exists(os.path.join(base_directory, subdirectory)):
        os.makedirs(os.path.join(base_directory, subdirectory))

    output_file_path = os.path.join(base_directory, subdirectory, filename)
    with open(output_file_path, 'wb') as f:
        pickle.dump(mapping, f)


def re_generate_ids(node_name_set, edge_name_set, original_triple, graph_with_id_dir):
    edge_set = set()
    node_set = set()
    kg_set = set()
    node_mapping = dict()
    edge_mapping = dict()

    with open(graph_with_id_dir, 'rb') as f:
        graph_with_id = pickle.load(f)
    for subgraph in graph_with_id:
        for node_name, attributes in subgraph.nodes(data=True):
            node_set.add((attributes['name'], node_name))
            node_mapping[attributes['name']] = node_name


    for i, item in enumerate(edge_name_set):
        edge_set.add((item, i))
        edge_mapping[item] = i

    for item in original_triple:
        source_id = node_mapping[item[0]]
        target_id = node_mapping[item[1]]
        edge_id = edge_mapping[item[2]]
        kg_set.add((source_id, target_id, edge_id))
    return edge_set, node_set, kg_set, node_mapping, edge_mapping

def output_file(result_set, filename, dataset, first_line_reserved, snapshot=None):

    base_directory = f'../Data/{args.dataset}/benchmark'


    subdirectory = dataset

    if snapshot != None:
        subdirectory = subdirectory + f'/{snapshot}'

    if not os.path.exists(base_directory):
        os.makedirs(base_directory)
    if not os.path.exists(os.path.join(base_directory, subdirectory)):
        os.makedirs(os.path.join(base_directory, subdirectory))

    output_file_path = os.path.join(base_directory, subdirectory, filename)

    with open(output_file_path, 'w') as output_file:
        if first_line_reserved == True:
            max_id = 0
            for name_id in result_set:
                name = name_id[0]
                id = name_id[1]
                max_id = max(max_id, id)
            output_file.write(f'{max_id + 1}' + '\n')

        for item in result_set:
            line = ' '.join(map(str, item))  
            output_file.write(line + '\n')  

def tsne(ts, to_be_visualize, to_be_visualize_ids):
    node_save_path = f"../Data/Apache_Pgsql/benchmark/{args.dataset.lower()}/entity_embeddings.pickle"
    with open(node_save_path, 'rb') as f:
        entity_embeddings = pickle.load(f)
    print(type(entity_embeddings))

    edge_save_path = f"../Data/Apache_Pgsql/benchmark/{args.dataset.lower()}/relation_embeddings.pickle"
    with open(edge_save_path, 'rb') as f:
        relation_embeddings = pickle.load(f)

    data = list()
    print('numbers: ' + str(len(to_be_visualize_ids)))

    for tsne_entity_id in to_be_visualize_ids:

        data.append(entity_embeddings[tsne_entity_id])


    data = np.array(data)
    embedded_data = ts.fit_transform(data)

    fig = plt.figure(figsize=(8,6))
    ax = plt.subplot(1, 1, 1)  
    x_data = embedded_data[:, 0]
    y_data = embedded_data[:, 1]
    ax.scatter(embedded_data[:, 0], embedded_data[:, 1])  
    ax.set_title(f"{args.dataset} t-SNE Visualization")
    for i in range(len(x_data)):
        ax.text(x_data[i] * 1.01, y_data[i] * 1.01, to_be_visualize[i],
                fontsize=6, color="r", style="italic", weight="light",
                verticalalignment='center', horizontalalignment='right', rotation=0)
    plt.show()
def test_relation():
    new_relation = torch.Tensor([])
    with open(f'../Data/{args.dataset}/benchmark/{args.dataset.lower()}/relation_embeddings.pickle', 'rb') as f:
        relation = pickle.load(f)
    a = [1, 2, 3, 4, 5]
    for idx in a:
        if len(new_relation) == 0:
            new_relation = relation[idx].unsqueeze(0)
        else:
            new_relation = torch.cat((new_relation, relation[idx].unsqueeze(0)), dim=0)
    print(relation)
    print(new_relation)
    print(len(new_relation))
    exit()

def test_node_existence(graph_list):
    for graph in graph_list:
        if graph == 0 or graph == None:
            continue
        for node_name, attributes in graph.nodes(data=True):
            if attributes['name'] == '/etc/passwd':
                print('/etc/passwd exists in splitted graphs')
                return True
    print('/etc/passwd doesnt exist in splitted graphs')
    return False

def find_label_edges(graph, label):
    label_edges = [(u, v, key, data) for u, v, key, data in graph.edges(data=True, keys=True) if data['label'] == label]
    return label_edges

def find_label_edges_time_range(label_edges):
    timestamps = [data['Timestamp'] for _, _, _, data in label_edges]
    if len(timestamps) != 0:
        time_range = (min(timestamps), max(timestamps))
    else:
        time_range = None
    return time_range

def check_time(timestamp, time_range):
    if time_range == None:
        return True
    if timestamp >= time_range[0] and timestamp <= time_range[1]:
        return True
    return False

def check_edge_time(label,all_in_edges, edge_data_key):
    check_sum = 0
    all_sum = 0

    for u, v, key, data in all_in_edges:
        if data['label'] == label:
            all_sum += 1
            if data['Timestamp'] > edge_data_key['Timestamp']:
                check_sum += 1
    if check_sum == all_sum:
        return  False
    else:
        return True

def build_connected_graph(ori_graph, label_edges, time_range, all_connect):
    graph = ori_graph
    connected_graph = nx.MultiDiGraph()

    this_connect = set()
    if len(label_edges) == 0:
        return connected_graph, None
    label_edges = sorted(label_edges, key=lambda x: x[3]['Timestamp'])
    label = label_edges[0][3]['label']

    for u, v, key, data in label_edges:
        if not connected_graph.has_node(u):
            node_attributes = graph.nodes[u]
            connected_graph.add_node(u, name=node_attributes['name'], entity_type=node_attributes['entity_type'])
        if not connected_graph.has_node(v):
            node_attributes = graph.nodes[v]
            connected_graph.add_node(v, name=node_attributes['name'], entity_type=node_attributes['entity_type'])
        this_connect.add((u,v))
        connected_graph.add_edge(u, v, key=key, src=data['src'], dst=data['dst'], relation=data['relation'], Timestamp=data['Timestamp'], label=data['label'], log_data=data['log_data'], payload=data['payload'], type='audit', log_type=data['relation'])

    visited_src_dst = set()
    for u, v, key, data in tqdm(label_edges):
        if graph.has_edge(u, v) and (u, v) not in visited_src_dst:
            edge_data = graph[u][v]
            visited_src_dst.add((u, v))
            for key in edge_data:
                if check_time(edge_data[key]['Timestamp'], time_range) and edge_data[key]['label'] == None:
                    if not connected_graph.has_node(u):
                        node_attributes = graph.nodes[u]
                        connected_graph.add_node(u, name=node_attributes['name'],
                                                 entity_type=node_attributes['entity_type'])
                    if not connected_graph.has_node(v):
                        node_attributes = graph.nodes[v]
                        connected_graph.add_node(v, name=node_attributes['name'],
                                                 entity_type=node_attributes['entity_type'])
                    edge_data[key]['label'] = label
                    this_connect.add((u, v))
                    connected_graph.add_edge(u, v, key=key, Timestamp=edge_data[key]['Timestamp'], label=edge_data[key]['label'], log_data=edge_data[key]['log_data'], payload=edge_data[key]['payload'], type='audit', log_type=edge_data[key]['relation'])

    for connect in all_connect:
        if this_connect.issubset(connect):
            return connected_graph, None

    weakly_connected = nx.is_weakly_connected(connected_graph)

    if weakly_connected:

        return connected_graph, this_connect


    weakly_connected = list(nx.weakly_connected_components(connected_graph))
    for i in range(1, len(weakly_connected)):

        u = list(weakly_connected[i])[0]


        v = list(weakly_connected[0])[0]


        if graph.has_edge(u, v):
            edge_data = graph[u][v]
            for key in edge_data:

                all_in_edges = graph.in_edges(keys=True, data=True)

                if edge_data[key]['Timestamp'] >= connected_graph[u][v][key]['Timestamp'] and check_time(
                        edge_data[key]['Timestamp'], time_range) and edge_data[key]['label'] == None and check_edge_time(label, all_in_edges, edge_data[key]):
                    edge_data[key]['label'] = label
                    if not connected_graph.has_node(u):
                        node_attributes = graph.nodes[u]
                        connected_graph.add_node(u, name=node_attributes['name'],
                                                 entity_type=node_attributes['entity_type'])
                    if not connected_graph.has_node(v):
                        node_attributes = graph.nodes[v]
                        connected_graph.add_node(v, name=node_attributes['name'],
                                                 entity_type=node_attributes['entity_type'])
                    this_connect.add((u, v))
                    connected_graph.add_edge(u, v, key=key, Timestamp=edge_data[key]['Timestamp'], label=edge_data[key]['label'], log_data=edge_data[key]['log_data'], payload=edge_data[key]['payload'], type='audit', log_type=edge_data[key]['relation'])

    print("nodes connected.")
    return connected_graph, this_connect


# --------------------tools begin------------------------------
def OverheadStart():
    start = time.time()
    return start


def custom_ln(t1, t2):
    abs_diff = abs(t1 - t2) + 1e-9
    result = math.log(1 + 1 / abs_diff)
    return result



def score_func1(audit_log, label, nets, netlogs, applogs1, applogs2, idx):
    t1 = float(audit_log.Timestamp) / 1000000
    t1 = t1* 1000 + idx
    t_score = -1.0


    t_score = max(t_score, custom_ln(t1, float(applogs1[label]['Timestamp'])*1000+ idx))
    t_score = max(t_score, custom_ln(t1, float(applogs2[label]['Timestamp']))*1000+ idx)
    for index, net in enumerate(nets):
        netlog = netlogs[net]
        if (args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016') and netlog["filename"] != None:
            t_score = max(custom_ln(t1, float(netlog['Timestamp'])*1000+ idx), t_score)
            break

    return t_score


def score_func1_single(audit_log, label, nets, netlogs, applogs, idx):
    t1 = float(audit_log.Timestamp) / 1000000
    t1 = t1* 1000 + idx
    t_score = -1.0


    t_score = max(t_score, custom_ln(t1, float(applogs[label]['Timestamp'])*1000+ idx))
    for index, net in enumerate(nets):
        netlog = netlogs[net]
        t_score = max(custom_ln(t1, float(netlog['Timestamp'])*1000+ idx), t_score)

    return t_score

def payload_revelance(subject, payload):

    if '/usr/local/apache2/' in subject:
        subject = subject.strip('/usr/local/apache2/')
    if '/usr/local/apache2/htdocs/' in subject:
        subject = subject.strip('/usr/local/apache2/htdocs/')
    if subject in payload and len(subject)!= 0:

        return 1
    return 0


def score_func2(audit_log, label, nets, netlogs, applogs1, applogs2, records, idx):

    subject = audit_log.subject.entity_name
    object = audit_log.object.entity_name
    all_app2_log_list = None
    if records.get(label) is None:

        dic = {}
        app1_log = applogs1[label]
        if app1_log.get('s_ip'):
            dic[app1_log['s_ip']] = dic.get(app1_log['s_ip'], 0) + 1
        if app1_log.get('src_ip'):
            dic[app1_log['src_ip']] = dic.get(app1_log['src_ip'], 0) + 1
        if app1_log.get('file'):
            dic[app1_log['file']] = dic.get(app1_log['file'], 0) + 1
        if app1_log.get('dst_ip'):
            dic[app1_log['dst_ip']] = dic.get(app1_log['dst_ip'], 0) + 1
        if app1_log.get('dst_port'):
            dic[app1_log['dst_port']] = dic.get(app1_log['dst_port'], 0) + 1
        if app1_log.get('pid'):
            dic[app1_log['pid']] = dic.get(app1_log['pid'], 0) + 1
        if app1_log.get('Host'):
            dic[app1_log['Host']] = dic.get(app1_log['Host'], 0) + 1
        if (args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016'):
            label_indices = get_indices_by_label(applogs2)
            all_app2_log_list = label_indices[label]
            for app2_index in all_app2_log_list:
                app2_log = applogs2[app2_index]
                if app2_log.get('port'):
                    dic[app2_log['port']] = dic.get(app2_log['port'], 0) + 1
                if app2_log.get('pid'):
                    dic[app2_log['pid']] = dic.get(app2_log['pid'], 0) + 1
                if app2_log.get('Pid'):
                    dic[app2_log['Pid']] = dic.get(app2_log['Pid'], 0) + 1
                if app2_log.get('payload'):
                    dic[app2_log['payload']] = dic.get(app2_log['payload'], 0) + 1
                if app2_log.get('File'):
                    dic[app2_log['File']] = dic.get(app2_log['File'], 0) + 1
        else:
            app2_log = applogs2[label]
            if app2_log.get('port'):
                dic[app2_log['port']] = dic.get(app2_log['port'], 0) + 1
            if app2_log.get('pid'):
                dic[app2_log['pid']] = dic.get(app2_log['pid'], 0) + 1
            if app2_log.get('Pid'):
                dic[app2_log['Pid']] = dic.get(app2_log['Pid'], 0) + 1
            if app2_log.get('payload'):
                dic[app2_log['payload']] = dic.get(app2_log['payload'], 0) + 1
            if app2_log.get('File'):
                dic[app2_log['File']] = dic.get(app2_log['File'], 0) + 1
        net_set = set()
        for i in nets:
            net_log = netlogs[i]
            if (args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016') and net_log["filename"] != None:
                if net_log.get('s_ip'):
                    net_set.add(net_log['s_ip'])
                if net_log.get('d_ip'):
                    net_set.add(net_log['d_ip'])
                if net_log.get('s_port'):
                    net_set.add(net_log['s_port'])
                if net_log.get('d_port'):
                    net_set.add(net_log['d_port'])
                if net_log.get('destIp'):
                    net_set.add(net_log['destIp'])
                if net_log.get('srcIp'):
                    net_set.add(net_log['srcIp'])
                if net_log.get('destPort'):
                    net_set.add(net_log['destPort'])
                if net_log.get('srcPort'):
                    net_set.add(net_log['srcPort'])
                if net_log.get('uri'):
                    net_set.add(net_log['uri'])
                break

        for net in net_set:
            dic[net] = dic.get(net, 0) + 1
        records[label] = dic
    A = 0
    for k, v in records[label].items():
        A += v
    I = 1
    if (args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016'):
        if '::ffff:a66f:5236' in subject:
            subject = '166.111.82.54'
        if '::ffff:a66f:5236' in object:
            object = '166.111.82.54'
        if '::ffff:a66f:522e' in subject:
            subject = '166.111.82.46'
        if '::ffff:a66f:522e' in object:
            object = '166.111.82.46'
        if args.dataset == 'ImageMagick':
            if 'poc' in subject:
                subject = subject.rsplit('.', 1)[0] + '.png' if subject.endswith('.gif') else subject

            if 'poc' in object:
                object = object.rsplit('.', 1)[0] + '.png' if object.endswith('.gif') else object



    B1 = records[label].get(subject, 0)

    if applogs2[label].get("statement"):
        B1 = max(payload_revelance(audit_log.subject.entity_data, applogs2[label]["statement"]), B1)
    if applogs1[label].get("Url"):
        B1 = max(payload_revelance(subject, applogs1[label]["Url"]), B1)
    if all_app2_log_list != None:
        for app2_index in all_app2_log_list:
            app2_log = applogs2[app2_index]
            if app2_log.get("File"):
                B1 = max(payload_revelance(subject, app2_log["File"]), B1)
    else:
        if applogs2[label].get("File"):
            B1 = max(payload_revelance(subject, applogs2[label]["File"]), B1)


    B2 = records[label].get(object, 0)

    if applogs2[label].get("statement"):
        B2 = max(payload_revelance(audit_log.object.entity_data, applogs2[label]["statement"]), B2)
    if applogs1[label].get("Url"):
        B2 = max(payload_revelance(object, applogs1[label]["Url"]), B2)

    if all_app2_log_list != None:
        for app2_index in all_app2_log_list:
            app2_log = applogs2[app2_index]
            if app2_log.get("File"):
                B2 = max(payload_revelance(object, app2_log["File"]), B2)
    else:
        if applogs2[label].get("File"):
            B2 = max(payload_revelance(object, applogs2[label]["File"]), B2)

    if B1 == 0 and B2 == 0:
        I = 0
    elif B1 != 0 and B2 != 0:
        I = 1
    else:
        I = 0.5
    B = B1 + B2
    return I * math.exp(B / A)



def score_func2_single(audit_log, label, nets, netlogs, applogs, records, idx):

    subject = audit_log.subject.entity_name
    object = audit_log.object.entity_name
    if records.get(label) is None:

        dic = {}
        app_log = applogs[label]
        if app_log.get('Ip'):
            dic[app_log['Ip']] = dic.get(app_log['Ip'], 0) + 1
        if app_log.get('Port'):
            dic[app_log['Port']] = dic.get(app_log['Port'], 0) + 1
        if app_log.get('src_ip'):
            dic[app_log['src_ip']] = dic.get(app_log['src_ip'], 0) + 1
        if app_log.get('file'):
            dic[app_log['file']] = dic.get(app_log['file'], 0) + 1
        if app_log.get('dst_ip'):
            dic[app_log['dst_ip']] = dic.get(app_log['dst_ip'], 0) + 1
        if app_log.get('dst_port'):
            dic[app_log['dst_port']] = dic.get(app_log['dst_port'], 0) + 1
        if app_log.get('pid'):
            dic[app_log['pid']] = dic.get(app_log['pid'], 0) + 1
        if app_log.get('Pid'):
            dic[app_log['Pid']] = dic.get(app_log['Pid'], 0) + 1
        if app_log.get('Host'):
            dic[app_log['Host']] = dic.get(app_log['Host'], 0) + 1
        if app_log.get('FileName'):
            dic[app_log['FileName']] = dic.get(app_log['FileName'], 0) + 1


        net_set = set()
        for i in nets:
            net_log = netlogs[i]
            if net_log.get('s_ip'):
                net_set.add(net_log['s_ip'])
            if net_log.get('d_ip'):
                net_set.add(net_log['d_ip'])
            if net_log.get('s_port'):
                net_set.add(net_log['s_port'])
            if net_log.get('d_port'):
                net_set.add(net_log['d_port'])
            if net_log.get('destIp'):
                net_set.add(net_log['destIp'])
            if net_log.get('srcIp'):
                net_set.add(net_log['srcIp'])
            if net_log.get('destPort'):
                net_set.add(net_log['destPort'])
            if net_log.get('srcPort'):
                net_set.add(net_log['srcPort'])

        for net in net_set:
            dic[net] = dic.get(net, 0) + 1
        records[label] = dic
    A = 0
    for k, v in records[label].items():
        A += v
    I = 1
    if args.dataset == 'Apache':
        if '::ffff' in subject:
            subject = extract_ip(subject)
            if '127.0.0.1' in subject:
                subject = '192.168.119.1'
        if '::ffff' in object:
            object = extract_ip(object)
            if '127.0.0.1' in object:
                object = '192.168.119.1'
    if args.dataset == 'Proftpd':
        if '/abc/' in subject:
            subject = subject.strip('/abc/')
        if '/abc/' in object:
            object = object.strip('/abc/')
        if '192.168.229' in subject:
            subject = subject.strip('/0')
        if '192.168.229' in object:
            object = object.strip('/0')
    if args.dataset == 'Redis':
        if '/etc/passwd' in subject:
            pass
        if '/etc/passwd' in object:
            pass
        if '192.168.229' in subject:
            subject = extract_ip(subject)
        if '192.168.229' in object:
            object = extract_ip(object)


    if args.dataset == 'Vim':
        if '/etc/passwd' in subject:
            print(subject)
        if '/etc/passwd' in object:
            print(object)

    if args.dataset == 'Php':
        if '/var/www/html/' in subject:
            subject = subject.strip('/var/www/html/')
        if '/var/www/html/' in object:
            object = object.strip('/var/www/html/')

        if '::ffff' in subject:
            subject = extract_ip(subject)
            if '127.0.0.1' in subject:
                subject = '192.168.119.1'
        if '::ffff' in object:
            object = extract_ip(object)
            if '127.0.0.1' in object:
                object = '192.168.119.1'
        if applogs[label].get("Url"):
            if applogs[label]["Url"] == '/':
                applogs[label]["Url"] = '/index.html'

    if args.dataset == 'Nginx':
        if '127.0.0.1' in subject:
            subject = '127.0.0.1'

        if '127.0.0.1' in object:
            object = '127.0.0.1'

        if '192.168.119.1' in subject:
            subject = '192.168.119.1'

        if '192.168.119.1' in object:
            object = '192.168.119.1'

        if '192.168.119.2' in subject:
            subject = '192.168.119.2'

        if '192.168.119.2' in object:
            object = '192.168.119.2'

        if '/files../' in subject:
            subject = subject.strip('/files../')

        if '/files../' in object:
            object = object.strip('/files../')


        if '/home/..' == subject:
            subject = 'files..'

        if '/home/..' ==  object:
            object = 'files..'


        if '/home//ubuntu/' in subject:
            subject = subject.strip('/home//ubuntu/')

        if '/home//ubuntu/' in object:
            object = object.strip('/home//ubuntu/')

        if '/usr/share/nginx/html/' in subject:
            subject = subject.strip('/usr/share/nginx/html/')
        if '/usr/share/nginx/html/' in object:
            object = object.strip('/usr/share/nginx/html/')

        if '/home//' in subject:
            subject = subject.strip('/home//')
            # print(subject)
        if '/home//' in object:
            object = object.strip('/home//')
            # print(object)


    B1 = records[label].get(subject, 0)
    if applogs[label].get("Url"):
        B1 = max(payload_revelance(subject, applogs[label]["Url"]), B1)

    if applogs[label].get("FileName"):
        B1 = max(payload_revelance(subject, applogs[label]["FileName"]), B1)
    if applogs[label].get("Filename"):
        B1 = max(payload_revelance(subject, applogs[label]["Filename"]), B1)
    if applogs[label].get("Content"):
        B1 = max(payload_revelance(subject, applogs[label]["Content"]), B1)


    B2 = records[label].get(object, 0)
    if applogs[label].get("Url"):
        B2 = max(payload_revelance(object, applogs[label]["Url"]), B2)

    if applogs[label].get("FileName"):
        B2 = max(payload_revelance(object, applogs[label]["FileName"]), B2)
    if applogs[label].get("Filename"):
        B2 = max(payload_revelance(object, applogs[label]["Filename"]), B2)
    if applogs[label].get("Content"):
        B2 = max(payload_revelance(object, applogs[label]["Content"]), B2)


    if B1 == 0 and B2 == 0:
        I = 0
    elif B1 != 0 and B2 != 0:
        I = 1
    else:
        I = 0.5
    B = B1 + B2
    return I * math.exp(B / A)

def evaluate_score(auditlist, subgraphs, netlogs, apachelogs, pglogs, divided_available):
    records = {}
    subgraph_starttime = dict()

    for label, nets in subgraphs.items():
        apache_time = float(apachelogs[label]['Timestamp'])
        pgsql_time = float(pglogs[label]['Timestamp'])
        if label not in subgraph_starttime:
            subgraph_starttime[label] = None
        subgraph_starttime[label] = (max(apache_time, pgsql_time), min(apache_time, pgsql_time))

    with tqdm(total=len(auditlist)) as pbar:
        pbar.set_description('Processing:')
        for audit_log in auditlist:
            max_score = -1.0
            max_label = -1
            s1_best = -1.0
            s2_best = -1.0
            score_history = []
            time_interval = 1
            if args.dataset == 'Apache_Pgsql':
                time_interval = 1
            elif  args.dataset == 'ImageMagick':
                time_interval = 1.2
            elif  args.dataset == 'ImageMagick-2016':
                time_interval = 0.4

            if audit_log.log['ip'] == '::ffff:a66f:522e' and args.dataset =='Apache_Pgsql':
                audit_log.log['ip'] = '166.111.82.46'
            if audit_log.log['ip'] == '::ffff:a66f:522e' and (args.dataset == 'ImageMagick' or args.dataset == 'ImageMagick-2016'):
                audit_log.log['ip'] = '166.111.82.35'

            for idx, items in enumerate(subgraphs.items()):
                label, nets = items
                current_time = float(audit_log.Timestamp) / 1000000
                if current_time< subgraph_starttime[label][1]-time_interval or current_time> subgraph_starttime[label][0]+time_interval:
                    if label == 0:
                        pass
                    continue
                if args.dataset == 'ImageMagick':
                    continue

                s2 = score_func2(audit_log, label, nets, netlogs, apachelogs, pglogs, records, idx)

                if s2 == 0:
                    continue

                s1 = score_func1(audit_log, label, nets, netlogs, apachelogs, pglogs, idx)

                if s1 + s2 > max_score and s2 !=0:
                    max_score = s1 + s2
                    max_label = label
                    s1_best = s1
                    s2_best = s2
                    score_history.append({f'{label}': f'{max_score}'})
                    if max_label >= 0:
                        pass

            if args.dataset == 'ImageMagick-2016' or args.dataset == 'ImageMagick':
                audit_log_record = audit_log.log
                rule_type = 'imagemagick'
                apache_log_record = 'apache'
                if fit_divided(audit_log_record, rule_type):
                    divided_available['apache'][apache_log_record] = divided_available['apache'][apache_log_record][1:]

                tmp_label = divided_available['apache'][apache_log_record][0]
                if tmp_label != -1:
                    max_label = tmp_label
            if max_label == -1:
                max_label = "_1"
            else:
                audit_log_record = audit_log.log
                if args.dataset == 'Apache_Pgsql':
                    apache_log_record = {k: v for k, v in apachelogs[max_label].items() if
                                         k != 'Timestamp'}

                else:
                    apache_log_record = {k: v for k, v in apachelogs[max_label].items() if k != 'Timestamp' and k != 'label'}
                apache_log_record = str(apache_log_record)
                if args.dataset == 'Apache_Pgsql':
                    pgsql_log_record = {k: v for k, v in pglogs[max_label].items() if k != 'Timestamp' }
                else:
                    pgsql_log_record = {k: v for k, v in pglogs[max_label].items() if k != 'Timestamp' and k != 'label'}
                pgsql_log_record = str(pgsql_log_record)
                if args.dataset == 'Apache_Pgsql':
                    if fit_divided(audit_log_record, 'apache'):
                        divided_available['apache'][apache_log_record] = divided_available['apache'][apache_log_record][1:]
                    tmp_label = divided_available['apache'][apache_log_record][0]
                    if tmp_label != -1:
                        max_label = tmp_label


            if max_label == -1:
                print(1)
                exit()
            # print(max_label)
            audit_log.label = max_label
            audit_log.log['label'] = max_label
            audit_log.log['score_history'] = score_history
            audit_log.log['s1'] = s1_best
            audit_log.log['s2'] = s2_best
            pbar.update(1)
    return auditlist

def normalize_field(applog):
    if 'TransferDuration' in applog:
        del applog['TransferDuration']
    if 'TransferSize' in applog:
        del applog['TransferSize']
    if 'TransferStatus' in applog:
        del applog['TransferStatus']
    if 'FileOffset' in applog:
        del applog['FileOffset']
    if 'label' in applog:
        del applog['label']
    if 'payload' in applog:
        del applog['payload']
    if 'User_Agent' in applog:
        del applog['User_Agent']
    if 'Referer' in applog:
        del applog['Referer']
    return applog

def evaluate_score_single(auditlist, subgraphs, netlogs, applogs, divided_available):
    records = {}
    subgraph_starttime = dict()

    for label, nets in subgraphs.items():
        app_time = float(applogs[label]['Timestamp'])
        if label not in subgraph_starttime:
            subgraph_starttime[label] = None
        subgraph_starttime[label] = app_time

    with tqdm(total=len(auditlist)) as pbar:
        pbar.set_description('Processing:')
        cnt = 0
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
                if current_time< subgraph_starttime[label]-1 or current_time> subgraph_starttime[label]+1:
                    if label == 0:
                        pass
                    continue
                s1 = score_func1_single(audit_log, label, nets, netlogs, applogs, idx)
                s2 = score_func2_single(audit_log, label, nets, netlogs, applogs, records, idx)
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
                app_log_record = copy.deepcopy(applogs[max_label])
                del app_log_record['Timestamp']
                app_log_record = normalize_field(app_log_record)
                app_log_record = str(app_log_record)
                rule_type = None
                if args.dataset == 'Apache':
                    rule_type = 'httpd'
                    app_log_record = 'apache'
                if args.dataset == 'Proftpd':
                    rule_type = 'proftpd'
                if args.dataset == 'Php':
                    rule_type = 'php'
                    app_log_record = 'php'
                if args.dataset == 'Nginx':
                    rule_type = 'nginx'
                    app_log_record = 'nginx'
                if args.dataset == 'imagemagick':
                    rule_type = 'imagemagick'
                if rule_type != None:
                    if fit_divided(audit_log_record, rule_type):
                        divided_available[args.dataset][app_log_record] = divided_available[args.dataset][app_log_record][1:]

                        cnt+= 1

                    tmp_label = divided_available[args.dataset][app_log_record][0]
                    if tmp_label != -1:
                        max_label = tmp_label

            if max_label == -1:
                print(1)
                exit()
            audit_log.label = max_label
            audit_log.log['label'] = max_label
            audit_log.log['score_history'] = score_history
            audit_log.log['s1'] = s1_best
            audit_log.log['s2'] = s2_best
            pbar.update(1)
    return auditlist



def fit_divided(audit_log, type):
    rules = rule_set[type]
    for idx, rule in rules.items():
        if fit_rule(rule, audit_log):
            return True
    return False


def fit_rule(rule, audit):
    filed_to_be_fitted = dict()
    for key in rule.keys():
        filed_to_be_fitted[key] = audit[key]
    if filed_to_be_fitted == rule:
        return True
    else:
        return False

def check_delete(log):
    for name in deleteable_names:
        if log.object.entity_data == None and args.dataset == 'ImageMagick-2016':
            return True
        if name in log.object.entity_data:
            return True
        if log.subject.entity_data == None and args.dataset == 'ImageMagick-2016':
            return True
        if name in log.subject.entity_data:
            return True
    return False

def check_delete_action(log):
    if log.action == 'sys_rt_sigprocmask':
        return True
    if log.action == 'sys_rt_sigaction':
        return True
    if log.action == 'sys_mmap':
        return True
    if log.action == 'sys_times':
        return True
    if log.action == 'sys_mprotect':
        return True
    if log.action == 'sys_stat':
        return True
    if log.action == 'sys_getpid':
        return True
    if log.action == 'sys_brk':
        return True
    if log.action == 'sys_prlimit64':
        return True
    if log.action == 'sys_futex':
        return True
    if log.action == 'sys_arch_prctl':
        return True
    if log.action == 'sys_munmap':
        return True
    if log.action == 'sys_set_tid_address':
        return True
    if log.action == 'sys_set_robust_list':
        return True
    if log.action == 'sys_sysinfo':
        return True
    if log.action == 'sys_sched_getaffinity':
        return True
    if log.action == 'sys_getcwd':
        return True

    return False


deleteable_names = [
        '/tmp/',  
        '.so', 
        '/lib/x86_64-linux-gnu/',
        'vim.mo',
        '.ro', 
        '.readonly',
        '.dll',  
        '.dylib',
        '.conf',
        '.config',
        '/etc/localtime',
        '/usr/lib/locale/',
        '/usr/share/X11/locale/en_US.UTF-8/XLC_LOCALE',
        '/home/victim/en_US.UTF-8',
        '/usr/share/X11/locale/',
        '/usr/local/share/vim/vim80/',
        '/usr/local/pgsql/data/log/',  
        '/var/log/proftpd/',
        '/var/log/redis/',
        '/usr/share/zoneinfo/',
        '/etc/audit/rules.d/'
        '/usr/share/locale/',
        '/usr/share/locale-langpack/',
        '/home/victim/.viminfo',
        '/usr/lib/locale/locale-archive',
        '/etc/ld.so.cache',
        '/usr/local/share/vim/vim80/lang/',
        '/usr/share/locale-langpack/',
        '/usr/share/X11/locale/',
        '/etc/X11/en_US.UTF-8/',
        '/usr/share/X11/',
        '/lib/x86_64-linux-gnu/',
        '/dev/urandom',
        'ciscodump', 
        'dumpcap',
        'auditd',
        'auditctl',
        'lsof',
        'polkitd',
        ' ', 
        '/lib/systemd/',
        'wireshark',
        '127.0.0.53' 
        '/tmp/',
        '/usr/local/lib/libMagickCore'
    ]

def OverheadEnd(start, phase):
    end = time.time()
    overhead = end - start
    print(phase + " runtime overhead: {:.3f} seconds\n".format(overhead))
# -------------------tools end----------------------------------


# -------------------lkge utils begin----------------------------------
def get_param(shape):
    '''create learnable parameters'''
    param = Parameter(torch.Tensor(*shape)).double()
    xavier_normal_(param.data)
    return param


def same_seeds(seed):
    '''Set seed for reproduction'''
    os.environ['PYTHONHASHSEED'] = str(seed)
    random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
    np.random.seed(seed)
    torch.backends.cudnn.benchmark = False
    torch.backends.cudnn.deterministic = True

def load_fact(path):
    '''
    Load (sub, rel, obj) from file 'path'.
    :param path: xxx.txt
    :return: fact list: [(s, r, o)]
    '''
    facts = []
    with open(path, 'r') as f:
        for line in f:
            line = line.split()
            s, r, o = line[0], line[1], line[2]
            facts.append((s, r, o))
    return facts


def build_edge_index(s, o):
    '''build edge_index using subject and object entity'''
    index = [s + o, o + s]
    return torch.LongTensor(index)
# -------------------lkge utils end----------------------------------
