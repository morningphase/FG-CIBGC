import pickle
from py2neo import Graph
import networkx as nx

file_name = "vim.pkl"
neo4j_url = ""
neo4j_passwd = ""

def create_graph_from_neo4j():


    graph = Graph(neo4j_url, auth=("neo4j", neo4j_passwd))


    G = nx.MultiDiGraph()

    nodes_query = "MATCH (n) RETURN n"
    nodes_result = graph.run(nodes_query)
    for record in nodes_result:
        node = record["n"]
        G.add_node(node.identity, **node)


    edges_query = "MATCH ()-[r]->() RETURN r"
    edges_result = graph.run(edges_query)
    for record in edges_result:
        edge = record["r"]
        start_node_id = edge.start_node.identity
        end_node_id = edge.end_node.identity
        G.add_edge(start_node_id, end_node_id,key=edge.identity, **edge)

    with open(file_name, "wb") as f:
        pickle.dump(G, f)


def load_pkl(filename):
    with open(filename, "rb") as f:
        g = pickle.load(f)
    return g


if __name__ == '__main__':
    create_graph_from_neo4j()
    with open("vim.pkl", "rb") as f:
        a = pickle.load(f)
        print(a)
