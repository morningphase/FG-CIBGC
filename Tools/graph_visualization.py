import networkx as nx
import os
import matplotlib.pyplot as plt
import pickle

data_path = '../Data/Apache_Pgsql/'

graph_file = os.path.join(data_path, 'visualization/graph.pickle')
cluster_centers_file = os.path.join(data_path, 'visualization/cluster_centers.pickle')
with open(graph_file, "rb") as f:
    g = pickle.load(f)
# 聚类中心索引
with open(cluster_centers_file, "rb") as f:
    cluster_centers = pickle.load(f)


# 可视化图

def nxtoDot(graph: nx.MultiDiGraph):
    import networkx as nx
    import pygraphviz
    # 将NetworkX图转换为DOT格式的代码
    agraph = nx.nx_agraph.to_agraph(graph)
    # 设置边标签为 key 属性的值
    for edge in graph.edges(keys=True):
        source, target, key = edge
        agraph.get_edge(source, target, key).attr['label'] = str(key)
    return agraph


agraph = nxtoDot(g[cluster_centers[3]])
agraph.write("graph.dot")
