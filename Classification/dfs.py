import networkx as nx
import pickle

def load_pkl(filename):
    with open(filename, "rb") as f:
        g = pickle.load(f)
    return g



def filter_function(g):
    File_list = []
    Socket_list = []
    for node, attr in g._node.items():
        if attr['entity_type'] == 'File':
            File_list.append(node)
        elif attr['entity_type'] == 'Socket':
            Socket_list.append(node)
    return File_list, Socket_list


def check_type(id, g):
    if g._node[id]['entity_type'] == 'File' or g._node[id]['entity_type'] == 'Socket':
        return True
    else:
        return False


def check_dependency_explosion(node, g, size=500):

    if g.out_degree[node] > size:
        return True
    return False


def dfs_time(G, source=None, depth_limit=None):
    def checkTime(p, c, cur_time):

        edge = None
        _time = 0
        for k, v in G[p][c].items():

            if int(v["log_data"]["Timestamp"]) > int(cur_time):

                edge = v["relation"]
                _time = v["log_data"]["Timestamp"]
                break
        return edge, _time

    if source is None:

        nodes = G
    else:

        nodes = [source]
    visited = set()
    if depth_limit is None:
        depth_limit = len(G)
    for start in nodes:

        unique_nodes_and_edges = set(
            (predecessor, _, edge_data['relation']) for predecessor, _, edge_data in G.in_edges(start, data=True))
        for pre, _, edge_data in unique_nodes_and_edges:
            yield pre, edge_data, start


        if start in visited:
            continue
        visited.add(start)
        stack = [(start, depth_limit, iter(G[start]), -1)]
        while stack:
            parent, depth_now, children, cur_time = stack[-1]
            try:
                child = next(children)
                e, tmp_time = checkTime(parent, child, cur_time)
                if child not in visited and e is not None:
                    yield G._node[parent]["name"], e, G._node[child]["name"]
                    visited.add(child)
                    if depth_now > 1 and not check_dependency_explosion(child, G):
                        stack.append((child, depth_now - 1, iter(G[child]), tmp_time))
            except StopIteration:
                stack.pop()


def dfs(file_list, socket_list, g):
    ans = []
    for node in file_list:
        ans.append(list(dfs_time(g, node)))
    for node in socket_list:
        ans.append(list(dfs_time(g, node)))
    return ans


def get_subgraph(filename, node_map):
    g = load_pkl(filename=filename)
    g_relabel = []
    big_multidigraph = g[0]

    map_node = {v: k for k, v in node_map.items()}
    big_multidigraph = nx.relabel_nodes(big_multidigraph, map_node)
    file_list, socket_list = filter_function(big_multidigraph)
    g_relabel = [big_multidigraph]
    return dfs(file_list, socket_list, big_multidigraph), g_relabel


def get_subgraph_not_dfs(filename, node_map):
    g = load_pkl(filename=filename)
    g_relabel = []

    map_node = {v: k for k, v in node_map.items()}
    result_list = []
    check_triplet = set()  
    for graph in g:
        graph = nx.relabel_nodes(graph, map_node)

        new_graph = nx.MultiDiGraph()
        for source, target, data in graph.edges(data=True):
            new_key = data['log_type']
            new_graph.add_edge(source, target, key=new_key, **data)
        g_relabel.append(new_graph)
        graph_tuples = [(source, data['log_type'], target) for source, target, data in graph.edges(data=True)]
        for source, target, data in graph.edges(data=True):
            check_triplet.add((source, target, data['log_type']))
        result_list.append(graph_tuples)
    return result_list, g_relabel, check_triplet


if __name__ == '__main__':
    print(get_subgraph('vim.pkl'))
