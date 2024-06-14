from neo4j import GraphDatabase
import networkx as nx

import argparse
import os
import pickle
import shutil
import sqlite3
from datetime import datetime
import json
import traceback


class CompressConfig:
    def __init__(self):
        # 重要参数，按需配置
        self.UNIFIED_DURATION = 10  # 默认一个事件的持续时间，为毫秒级
        self.INTERVAL_TIME_THRESHOLD = 10  # 两个相同的三元组 (u,v,event_type)的默认间隔时间，为毫秒级
        self.SIMILARITY_THRESHOLD = 0.95  # 默认jaccard similarity的阈值
        # 一些临时数组
        self.REMOVED_EDGES = []
        self.TEMP_REMOVED_EDGES = []
        self.REMOVED_NODES = []
        self.TEMP_REMOVED_NODES = []
        self.DATASET_NAME = ''
        # 计数器，计算图中各类型边的原数量和删除的数量
        self.count_origin_application_edges = 0
        self.count_removed_application_edges = 0
        self.count_origin_auditd_edges = 0
        self.count_removed_auditd_edges = 0
        self.count_origin_net_edges = 0
        self.count_removed_net_edges = 0


def create_graph_from_neo4j(dataset):
    """
    # 将neo4j数据库中的图读成networkx格式，并保存为pkl
    :return: networkx格式的图
    """
    # 连接Neo4j数据库
    uri = "bolt://10.0.0.162:7687"  # 用你neo4j地址替代
    # uri = "bolt://localhost:7687"
    driver = GraphDatabase.driver(uri, auth=("neo4j", "123456"))  # 用你的用户名和密码替代

    # 初始化NetworkX图为多重有向图
    G = nx.MultiDiGraph()

    # 从Neo4j数据库中获取节点和边的信息
    with driver.session() as session:
        # 获取节点信息
        nodes_query = "MATCH (n) RETURN n"
        nodes_result = session.run(nodes_query)
        for record in nodes_result:
            node = record["n"]
            G.add_node(node.id, **node, type=node.labels)

        # 获取边信息
        edges_query = "MATCH ()-[r]->() RETURN r"
        edges_result = session.run(edges_query)
        for record in edges_result:
            edge = record["r"]
            start_node_id = edge.start_node.id
            end_node_id = edge.end_node.id
            G.add_edge(start_node_id, end_node_id, key=edge.id, **edge, type=edge.type)

    # 关闭Neo4j连接
    driver.close()
    # 指定要保存的文件名（包括路径）
    file_name = f"./Neo4jGraphs/{dataset}.pkl"

    # 使用 pickle.dump() 将图保存为.pkl文件
    with open(file_name, "wb") as f:
        pickle.dump(G, f)

    return G


def parse_attribute_to_G(G: nx.Graph, compressConfig: CompressConfig):
    """
    将neo4j中一条边的属性进行拆分，将时间戳标准化为毫秒级。同时计数图中各类型边的数量
    :param G:
    :return:
    """

    for u, v, key, attrs in G.edges(data=True, keys=True):
        timestamp = attrs.get('Timestamp')
        try:
            if "audit" in attrs.get('type'):
                timestamp = int(timestamp[:-3])

            elif "Apache_app" == attrs.get('type'):
                # 秒级转换成毫秒级
                timestamp = int(timestamp) * 1000
            elif "net" in attrs.get('type'):
                timestamp = float(timestamp) * 1000
                timestamp = int(timestamp)
            else:
                timestamp = int(timestamp)
        except Exception as e:
            traceback.print_exc()
            print(attrs)
            exit()
        attributes = dict()
        attributes['timestamp_start'] = timestamp
        attributes['timestamp_end'] = timestamp + compressConfig.UNIFIED_DURATION
        attributes['data_source'] = attrs.get('type')
        if "audit" in attributes["data_source"]:
            compressConfig.count_origin_auditd_edges += 1
        elif "net" in attributes["data_source"]:
            compressConfig.count_origin_net_edges += 1
        else:
            compressConfig.count_origin_application_edges += 1

        # add attribute to origin graph
        for K, V in attributes.items():
            G[u][v][key][K] = V


def judge_deleteable(node):
    if node == None:
        return True
    """
    根据节点名判断该节点是否可以删除
    """
    deleteable_names = [
        '/tmp/',  # 临时文件
        '.so',  # 库文件
        '/lib/x86_64-linux-gnu/',
        'vim.mo',
        '.ro',  # 只读文件
        '.readonly',
        '.dll',  # 动态链接
        '.dylib',
        '.conf',
        '.config',
        '/etc/localtime',
        '/usr/lib/locale/',
        '/usr/share/X11/locale/en_US.UTF-8/XLC_LOCALE',
        '/home/victim/en_US.UTF-8',
        '/usr/share/X11/locale/',
        '/usr/local/share/vim/vim80/',
        '/usr/local/pgsql/data/log/',  # 日志文件
        '/var/log/proftpd/',
        '/var/log/redis/',
        '/usr/share/zoneinfo/',
        '/etc/audit/rules.d/' # audit输入
        '/usr/share/locale/', # 设置语言
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
        'ciscodump', # 进程名
        'dumpcap',
        'auditd',
        'auditctl',
        'lsof',
        'polkitd',
        ' ', # 节点名为空
        '/lib/systemd/',
        'wireshark',
        '127.0.0.53' # 广播IP
    ]
    for name in deleteable_names:
        if name in node:
            return True
    if node == '': # 下面是一些普遍的特殊字符
        return True
    if node == '/':
        return True
    if node == '.':
        return True

    return False


def nodemerge_aggregate(G: nx.Graph, compressConfig: CompressConfig):
    """
    使用NodeMerge方法压缩
    :param G:
    :param dataset:
    :return:
    """

    for node in G.nodes():
        node_attributes = G.nodes[node]
        node_name = node_attributes.get('name')
        if judge_deleteable(node_name):

            compressConfig.REMOVED_NODES.append(node)
            compressConfig.TEMP_REMOVED_NODES.append(node)
            outgoing_edges = G.out_edges(node, data=True, keys=True)
            incoming_edges = G.in_edges(node, data=True, keys=True)

            # delete outgoing edges of node
            for u, v, key, attrs in outgoing_edges:
                # e represents the current edge
                e = (u, v, key, attrs)
                data_source = attrs.get("data_source")
                if "audit" in data_source:
                    compressConfig.count_removed_auditd_edges += 1
                elif "app" in data_source:
                    compressConfig.count_removed_application_edges += 1
                elif "net" in data_source:
                    compressConfig.count_removed_net_edges += 1

                compressConfig.TEMP_REMOVED_EDGES.append(e)
                compressConfig.REMOVED_EDGES.append(e)
            # delete incoming edges of node
            for u, v, key, attrs in incoming_edges:
                # e represents the current edge
                e = (u, v, key, attrs)
                data_source = attrs.get("type")
                if "audit" in data_source:
                    compressConfig.count_removed_auditd_edges += 1
                elif "app" in data_source:
                    compressConfig.count_removed_application_edges += 1
                elif "net" in data_source:
                    compressConfig.count_removed_net_edges += 1

                compressConfig.TEMP_REMOVED_EDGES.append(e)
                compressConfig.REMOVED_EDGES.append(e)

    remove_edges(G, compressConfig)

    # delete the node
    for node in compressConfig.TEMP_REMOVED_NODES:
        G.remove_node(node)

    compressConfig.TEMP_REMOVED_NODES.clear()


def cpr_aggregate(G: nx.Graph, compressConfig: CompressConfig):
    """
    使用CPR方法压缩
    :param G:
    :param dataset:
    :return:
    """
    # Sort edges by 'data_source' and then 'timestamp'
    sorted_edges = sorted(G.edges(keys=True, data=True),
                          key=lambda x: (x[3].get('data_source', ''), x[3].get('timestamp_start', '')))

    stacks = {}  # Dictionary to store the stacks
    # sorted_edges = sorted_edges[:3000]
    for u, v, key, attrs in sorted_edges:

        # e represents the current edge
        e = (u, v, key, attrs)

        # print(f"{key}:key, {attrs.get('timestamp','')}")
        data_source = attrs.get("data_source")
        # if data_source != dataset:
        #     continue

        # if data_source == "Redis":
        #     # count_origin_application_edges += 1
        #     event_type = attrs.get("ncmd", '')
        # elif data_source == "Proftpd":
        #     # count_origin_application_edges += 1
        #     event_type = attrs.get("direction", '')
        #     if event_type == '':
        #         event_type = attrs.get("protocolName", '')
        # elif data_source == "PostgreSql":
        #     # count_origin_application_edges += 1
        #     event_type = attrs.get("protocolName", '')
        # elif data_source == "php":
        #     # count_origin_application_edges += 1
        #     event_type = attrs.get("method", '')
        #     if event_type == '':
        #         event_type = attrs.get("protocolName", '')
        # elif data_source == "Apache":
        #     # count_origin_application_edges += 1
        #     event_type = attrs.get("method", '')
        # elif data_source == "Openssh":
        #     # count_origin_application_edges += 1
        #     event_type = attrs.get("protocolName", '')
        # elif data_source == "MiniHttpd":
        #     # count_origin_application_edges += 1
        #     event_type = attrs.get("method", '')
        #     if event_type == '':
        #         event_type = attrs.get("protocolName", '')
        # elif data_source == "Nginx":
        #     # count_origin_application_edges += 1
        #     event_type = attrs.get("method", '')
        # elif data_source == "auditd":
        #     # count_origin_auditd_edges += 1
        #     event_type = attrs.get("action", '')
        # elif data_source == "Vim":
        #     # count_origin_application_edges += 1
        #     event_type = attrs.get("action", '')
        # elif data_source == "APT/S1":
        #     # count_origin_application_edges += 1
        #     event_type = attrs.get("method", '')
        #     if event_type == '':
        #         event_type = attrs.get("protocolName", '')
        # elif data_source == "APT/S2":
        #     # count_origin_application_edges += 1
        #     event_type = attrs.get("method", '')
        #     if event_type == '':
        #         event_type = attrs.get("protocolName", '')
        # elif data_source == "ImageMagick":
        #     # count_origin_application_edges += 1
        #     event_type = ''

        event_type = attrs.get('log_type')

        # Initialize the stack for the (u, v, action) combination
        # Let S(u,v,R(e)) be a stack of events from u to v that are aggregable
        if (u, v, event_type) not in stacks:
            stacks[(u, v, event_type)] = []

        if len(stacks[(u, v, event_type)]) == 0:
            stacks[(u, v, event_type)].append(e)
        else:
            e_p = stacks[(u, v, event_type)].pop()
            if forward_check(G, e_p, e, v) and backward_check(G, e_p, e, u):
                e_p = merge(e_p, e, compressConfig)

                if "audit" in data_source:
                    compressConfig.count_removed_auditd_edges += 1
                elif "app" in data_source:
                    compressConfig.count_removed_application_edges += 1
                elif "net" in data_source:
                    compressConfig.count_removed_net_edges += 1

                stacks[(u, v, event_type)].append(e_p)
            else:
                stacks[(u, v, event_type)].append(e)

    remove_edges(G, compressConfig)


def merge(e_p, e_l, compressConfig: CompressConfig):
    e_p[3]['timestamp_end'] = e_l[3]['timestamp_end']
    # remove the edge e_l
    compressConfig.REMOVED_EDGES.append(e_l)
    compressConfig.TEMP_REMOVED_EDGES.append(e_l)

    return e_p


def overlap(ts_e, te_e, t_ep, t_el):
    """
    judge whether time window of current event e overlap with time window of [t_ep ,t_el]
    :param ts_e:
    :param te_e:
    :param t_ep:
    :param t_el:
    :return:
    """
    if te_e < t_ep or ts_e > t_el:
        return False
    else:
        return True


def backward_check(G, e_p, e_l, u):
    """
    describes the procedure to check the backward trackability.
    For two events e1 and e2 from entity u to entity v, they have the same backward trackability
    if all the time windows of incoming events of u do not overlap with the time window of [te(e1),te(e2)].
    :param e_p:
    :param e_l:
    :param u:
    :return:
    """
    incoming_edges = G.in_edges(u, data=True, keys=True)
    for src, dst, key, attrs in incoming_edges:
        ts_e = attrs.get('timestamp_start', '')
        te_e = attrs.get('timestamp_end', '')
        te_ep = e_p[3]['timestamp_end']
        te_el = e_l[3]['timestamp_end']
        if overlap(ts_e, te_e, te_ep, te_el):
            return False
    return True


def forward_check(G, e_p, e_l, v):
    """
    describes the procedure to check the forward-trackability.
    For two events e1 and e2 from entity u to entity v, they have the same forward trackability
    if none of outgoing events of v has an end time between the start times of e1 and e2.
    :param e_p:
    :param e_l:
    :param v:
    :return:
    """
    outgoing_edges = G.out_edges(v, data=True, keys=True)
    for src, dst, key, attrs in outgoing_edges:
        ts_e = attrs.get('timestamp_start', '')
        te_e = attrs.get('timestamp_end', '')
        ts_ep = e_p[3]['timestamp_start']
        ts_el = e_l[3]['timestamp_start']
        if overlap(ts_e, te_e, ts_ep, ts_el):
            return False
    return True


def jaccard_aggregate(G: nx.Graph, compressConfig: CompressConfig):
    """
    使用jaccard进行压缩
    :param G:
    :param dataset:
    :return:
    """

    # Sort edges by 'data_source' and then 'timestamp'
    sorted_edges = sorted(G.edges(keys=True, data=True),
                          key=lambda x: (x[3].get('data_source', ''), x[3].get('timestamp_start', '')))

    stacks = {}  # Dictionary to store the stacks
    for u, v, key, attrs in sorted_edges:

        # e represents the current edge
        e = (u, v, key, attrs)
        data_source = attrs.get("data_source")

        # if data_source == "Redis":
        #     event_type = attrs.get("ncmd", '')
        # elif data_source == "Proftpd":
        #     event_type = attrs.get("direction", '')
        #     if event_type == '':
        #         event_type = attrs.get("protocolName", '')
        # elif data_source == "PostgreSql":
        #     event_type = attrs.get("protocolName", '')
        # elif data_source == "php":
        #     event_type = attrs.get("method", '')
        #     if event_type == '':
        #         event_type = attrs.get("protocolName", '')
        # elif data_source == "Apache":
        #     event_type = attrs.get("method", '')
        # elif data_source == "Openssh":
        #     event_type = attrs.get("protocolName", '')
        # elif data_source == "MiniHttpd":
        #     event_type = attrs.get("method", '')
        #     if event_type == '':
        #         event_type = attrs.get("protocolName", '')
        # elif data_source == "Nginx":
        #     event_type = attrs.get("method", '')
        # elif data_source == "auditd":
        #     event_type = attrs.get("action", '')
        # elif data_source == "Vim":
        #     event_type = attrs.get("action", '')
        # elif data_source == "APT/S1":
        #     event_type = attrs.get("method", '')
        #     if event_type == '':
        #         event_type = attrs.get("protocolName", '')
        # elif data_source == "APT/S2":
        #     event_type = attrs.get("method", '')
        #     if event_type == '':
        #         event_type = attrs.get("protocolName", '')
        # elif data_source == "ImageMagick":
        #     event_type = ''

        event_type = attrs.get('log_type')
        # Initialize the stack for the (u, v, action) combination
        # Let S(u,v,R(e)) be a stack of events from u to v that are aggregable
        if (u, v, event_type) not in stacks:
            stacks[(u, v, event_type)] = []

        if len(stacks[(u, v, event_type)]) == 0:
            stacks[(u, v, event_type)].append(e)
        else:
            e_p = stacks[(u, v, event_type)].pop()
            # start time of current edge
            e_start_time = attrs.get('timestamp_start', '')
            ep_start_time = e_p[3]['timestamp_start']

            if e_start_time - ep_start_time > compressConfig.INTERVAL_TIME_THRESHOLD:
                stacks[(u, v, event_type)].append(e)
            else:
                e_log = attrs.get('log_data', '')
                ep_log = e_p[3]['log_data']
                similarity = jaccard_similarity(e_log, ep_log)
                if similarity > compressConfig.SIMILARITY_THRESHOLD:
                    compressConfig.REMOVED_EDGES.append(e)
                    compressConfig.TEMP_REMOVED_EDGES.append(e)
                    if "audit" in data_source:
                        compressConfig.count_removed_auditd_edges += 1
                    elif "app" in data_source:
                        compressConfig.count_removed_application_edges += 1
                    elif "net" in data_source:
                        compressConfig.count_removed_net_edges += 1
                    stacks[(u, v, event_type)].append(e_p)

                else:
                    stacks[(u, v, event_type)].append(e)

    remove_edges(G, compressConfig)


def jaccard_similarity(str1, str2):
    try:
        # Split the label into key-value pairs
        # 将换行符替换为有效的字符串（例如空格）
        str1 = str1.replace('\n', ' ')
        str2 = str2.replace('\n', ' ')
        str1 = str1.replace('\x13', ' ')
        str2 = str2.replace('\x13', ' ')
        str1 = str1.replace('\'', '\"')
        str2 = str2.replace('\'', '\"')
        str1 = str1.replace('None', 'null')
        str2 = str2.replace('None', 'null')

        key_value_pairs_str1 = json.loads(str1)
        set1 = set()

        for K, V in key_value_pairs_str1.items():
            if K == "Timestamp" or K == "log_id" or K == "datetime" or K == "data_source" or K == "sequenceNum" or K == "len" or K == "label" or K == "time":
                continue
            if V is None:
                continue

            set1.add(V)

        # Split the label into key-value pairs
        key_value_pairs_str2 = json.loads(str2)
        set2 = set()

        for K, V in key_value_pairs_str2.items():
            if K == "Timestamp" or K == "log_id" or K == "datetime" or K == "data_source" or K == "sequenceNum" or K == "len" or K == "label" or K == "time":
                continue
            if V is None:
                continue

            set2.add(V)

        intersection = len(set1.intersection(set2))
        union = len(set1) + len(set2) - intersection
        similarity = intersection / union
        # if similarity < 0.95:
        #     print(111)
        if similarity is None:
            print(111)

        return similarity
    except Exception:
        # print(str1)
        # print(str2)
        if str1 == str2:
            return 1

        return 0


def remove_edges(G, compressConfig: CompressConfig):
    """
    remove edges from G
    :param G:
    :return:
    """
    origin_edge_ids = []
    for edge in compressConfig.TEMP_REMOVED_EDGES:
        u = edge[0]
        v = edge[1]
        key = edge[2]
        origin_edge_ids.append(key)
        if G.get_edge_data(u, v, key) is not None:
            G.remove_edge(u, v, key=key)

    compressConfig.TEMP_REMOVED_EDGES.clear()


def net_filter(G, compressConfig: CompressConfig):
    try:
        net_edges = [edge for edge in G.edges(keys=True, data=True) if 'net' in edge[3].get('data_source', '')]
        for u, v, key, attrs in net_edges:

            # e represents the current edge
            e = (u, v, key, attrs)
            data_source = attrs.get("data_source")
            log_data = attrs.get("log_data")
            log_data = log_data.replace('\n', ' ')
            log_data = log_data.replace('\x13', ' ')
            log_data = json.loads(log_data)
            if log_data['srcPort'] is None or log_data['destPort'] is None or log_data['protocolName'] == "DNS" or \
                    log_data['protocolName'] == "TCP" or log_data['srcIp'] == "192.168.1.255" or log_data[
                'destIp'] == "192.168.1.255":
                compressConfig.count_removed_net_edges += 1
                compressConfig.TEMP_REMOVED_EDGES.append(e)
                compressConfig.REMOVED_EDGES.append(e)

        remove_edges(G, compressConfig)
    except Exception:
        traceback.print_exc()
        print(log_data)
        exit()


def compress(G: nx.Graph, compressConfig: CompressConfig):
    """
    压缩直接调用该函数即可，注意需要传入一个存储配置信息和压缩结果的CompressConfig
    @param G:
    @param compressConfig:
    @return: 压缩后的networkx图，以及存储了压缩结果的CompressConfig
    """
    # 解析图中属性
    parse_attribute_to_G(G, compressConfig)

    # nodemerge去重
    nodemerge_aggregate(G, compressConfig)

    # cpr去重
    cpr_aggregate(G, compressConfig)

    # jacard去重,这里会出现一些exception
    jaccard_aggregate(G, compressConfig)

    # net log专属去重
    net_filter(G, compressConfig)
    return G, compressConfig


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A simple command-line argument parser.")
    parser.add_argument("--dataset", help="select dataset to compress", default="vim")
    args = parser.parse_args()
    DATASET_NAME = args.dataset
    # save pkl from neo4j
    # create_graph_from_neo4j(DATASET_NAME)
    file_name = f"Neo4jGraphs/{DATASET_NAME}.pkl"
    with open(file_name, "rb") as f:
        G = pickle.load(f)
    compressConfig = CompressConfig()
    compress(G, compressConfig)

    # 将需要删除的边反回数据库
    # delete_edges_in_neo4j(compressConfig.REMOVED_EDGES)

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
    if DATASET_NAME != "vim":
        print(f"number of origin net edges: {compressConfig.count_origin_net_edges}")
        print(f"number of cpr removed auditd edges: {compressConfig.count_removed_net_edges}")
        print(f"net compress rate: {compressConfig.count_removed_net_edges / compressConfig.count_origin_net_edges}")
    print("===============================")
    print(
        f"total remained edges: {compressConfig.count_origin_auditd_edges + compressConfig.count_origin_application_edges + compressConfig.count_origin_net_edges - compressConfig.count_removed_auditd_edges - compressConfig.count_removed_application_edges - compressConfig.count_removed_net_edges}")
    print(
        f"remained application edges: {compressConfig.count_origin_application_edges - compressConfig.count_removed_application_edges}")
    print(
        f"remained auditd edges: {compressConfig.count_origin_auditd_edges - compressConfig.count_removed_auditd_edges}")
    print(f"remained net edges: {compressConfig.count_origin_net_edges - compressConfig.count_removed_net_edges}")
