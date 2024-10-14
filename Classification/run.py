import os.path
from typing import Tuple

import numpy
import pandas as pd
import numpy as np
from matplotlib import pyplot as plt
from scipy.cluster.hierarchy import dendrogram
from sklearn import metrics
from sklearn.cluster import AgglomerativeClustering
from dfs import get_subgraph, get_subgraph_not_dfs
import pickle
from idf import get_idf, get_tf_idf, get_mean
from tf import get_tf
from sklearn.decomposition import PCA
import sys
import networkx as nx
import argparse
from sklearn.manifold import TSNE

def extract(file1, file2):
    entity_data, relation_data = [], []
    with open(file1, "r") as f:
        for line in f.readlines():
            line = line.strip('\n').split('\t')[1]
            cur = list(map(float, line.split(' ')))
            entity_data.append(cur)

    with open(file2, "r") as f:
        for line in f.readlines():
            line = line.strip('\n').split('\t')[1]
            cur = list(map(float, line.split(' ')))
            relation_data.append(cur)

    n1 = len(entity_data)
    n2 = len(relation_data)
    n = min(n1, n2)
    chain = []
    cur = []
    i, j = 0, 0
    while (j < n2):
        if i >= n1:
            i = 0
        if j != 0 and j % 15 == 0:
            cur.append(entity_data[i])
            i += 1
            cur_sum = np.sum(np.array(cur), axis=0)
            chain.append(cur_sum)
            cur = []
        if i >= n1:
            i = 0
        cur.append(entity_data[i])
        i += 1
        cur.append(relation_data[j])
        j += 1
    chain = np.array(chain)
    return chain


def plot_dendrogram(model, **kwargs):

    counts = np.zeros(model.children_.shape[0])
    n_samples = len(model.labels_)
    for i, merge in enumerate(model.children_):
        current_count = 0
        for child_idx in merge:
            if child_idx < n_samples:
                current_count += 1 
            else:
                current_count += counts[child_idx - n_samples]
        counts[i] = current_count

    linkage_matrix = np.column_stack(
        [model.children_, model.distances_, counts]
    ).astype(float)

    dendrogram(linkage_matrix, **kwargs)


def watson_embedding(graph_file, node_map, edge_map):

    subgraphs, _ = get_subgraph(filename=graph_file, node_map=node_map)
    # 求idf
    idf = get_idf(subgraphs, original_tuple_list)

    for tup in original_tuple_list:
        event_embding_dict[tup] = numpy.concatenate((entity_embding_dict[tup[0]],
                                                     relation_embding_dict[tup[1]],
                                                     entity_embding_dict[tup[2]]), axis=0)*idf[tup]
    return subgraphs, event_embding_dict, _, 192


def log_fusion_embedding(graph_file, node_map, edge_map, args):
    """
        log_fusion embedding: [entity_embedding] + [relationship_embedding]* tf + [entity_embedding]
    """

    subgraphs, _, check_triplet = get_subgraph_not_dfs(filename=graph_file, node_map=node_map)

    if args.pooling == 'tf-idf':
        weight = get_tf_idf(subgraphs, original_tuple_list)
    if args.pooling == 'idf':
        weight = get_idf(subgraphs, original_tuple_list)
    if args.pooling == 'mean':
        weight = get_mean(subgraphs, original_tuple_list)


    for tup in original_tuple_list:
        event_embding_dict[tup] = numpy.concatenate((entity_embding_dict[tup[0]],
                                                     relation_embding_dict[tup[1]],
                                                     entity_embding_dict[tup[2]]), axis=0)*weight[tup]
    check_size = event_embding_dict[tup].shape[0]
    return subgraphs, event_embding_dict, check_triplet, check_size


def arg_parse():
    parser = argparse.ArgumentParser(description="Command-line arguments.")
    parser.add_argument('--watson', action='store_true')
    parser.add_argument('--classification', type=str, default='SA')
    parser.add_argument('--dataset', type=str, default='Apache')
    parser.add_argument('--n_classification', type=int, default=20)
    parser.add_argument('--min_pts', type=int, default=2)
    parser.add_argument('--lambd', type=float, default=0.1)
    parser.add_argument('--beta', type=float, default=0.5)
    parser.add_argument('--mu', type=int, default=5)
    parser.add_argument('--eps_factor', type=int, default=2)
    parser.add_argument('--pooling', type=str, default='tf-idf')

    return parser.parse_args()


def AggCluster(X):

    metric = 'cosine'
    n_clusters = 9

    model = AgglomerativeClustering(n_clusters=n_clusters, linkage="average", metric=metric)

    model.fit(X)
    return model.labels_


def get_eps(X, eps_factor):

    std_devs = np.std(X, axis=0)

    eps = eps_factor * np.mean(std_devs)
    print(std_devs)
    print(eps)
    return eps


def incdbscanCluster(X, args):

    eps_factor = args.eps_factor
    min_pts = args.min_pts
    from incdbscan import IncrementalDBSCAN
    eps = get_eps(X, eps_factor)
    clusterer = IncrementalDBSCAN(eps=eps, min_pts=min_pts)
    labels = clusterer.insert(X).get_cluster_labels(X)

    return labels


def DenStreamCluster(X, args):
    eps_factor = args.eps_factor
    lambd = args.lambd
    beta = args.beta
    mu = args.mu

    from denstream.DenStream import DenStream
    eps = get_eps(X, eps_factor)
    denstream = DenStream(eps=eps, lambd=lambd, beta=beta, mu=mu)
    y_pred = denstream.fit_predict(X)
    return y_pred

def mykm(X, args):
    import pickle
    from sklearn.cluster import MiniBatchKMeans
    with open(f'../Data/{args.dataset}/equal_dict.pickle','rb') as f:
        equal_dict = pickle.load(f)
    masks = []
    n = X.shape[0]
    print(equal_dict)
    for k in equal_dict:
        mask = numpy.zeros(n)
        for i in equal_dict[k]:
            mask[i] = 1
        masks.append(mask.reshape(-1,1))
    n_clusters = len(masks)
    init_array = []
    for mask in masks:
        tmp = (X*mask)
        tmp = numpy.sum(tmp,axis=0)
        init_array.append(tmp)
    init_array = numpy.array(init_array)
    kmeans = MiniBatchKMeans(n_clusters=n_clusters, batch_size=1000, n_init=1, init=init_array)
    kmeans = kmeans.partial_fit(X)
    labels_combined = kmeans.labels_
    print(labels_combined.shape,labels_combined)
    return labels_combined

def minibathkmCluster(X, args):
    n_clusters = args.n_cluster

    from sklearn.cluster import MiniBatchKMeans
    kmeans = MiniBatchKMeans(n_clusters=n_clusters, random_state=0, batch_size=6, n_init="auto")
    kmeans = kmeans.partial_fit(X)

    labels_combined = kmeans.labels_


    return labels_combined


def ClustreamCluster(X):

    from clusopt_core.cluster import CluStream
    dataset = X
    k = 10
    model = CluStream(
        m=256,  # no microclusters
        h=400,  # horizon
        t=2,  # radius factor
    )
    chunks = np.split(dataset, len(dataset) / 256)

    model.init_offline(chunks.pop(0), seed=42)

    for chunk in chunks:
        model.partial_fit(chunk)

    clusters, labels_ = model.get_macro_clusters(k, seed=42)
    print(labels_)

    return labels_


def StreamKMCluster(X):


    from clusopt_core.cluster import StreamKM
    model = StreamKM()

    pass


def check_triplet_func(original, check):
    for data in check:
        if data not in original:
            print(f'Data Not in Original:{str(data)}')


if __name__ == '__main__':
    arg_parses = arg_parse()

    data_path = f'../Data/{arg_parses.dataset}'
    benchmark_path = f'../Data/{arg_parses.dataset}/benchmark/{arg_parses.dataset.lower()}'

    filename = os.path.join(benchmark_path, 'entity_embeddings.pickle')
    edge_map_file = os.path.join(benchmark_path, 'edge_mapping.pickle')
    relation_file = os.path.join(benchmark_path, 'relation_embeddings.pickle')
    node_map_file = os.path.join(benchmark_path, 'node_mapping.pickle')
    relation_map_file = os.path.join(benchmark_path, 'relation2id.txt')
    if arg_parses.watson:
        graph_file = os.path.join(data_path, 'all_graph_list.pickle')
    else:
        graph_file = os.path.join(data_path, 'graph_list.pickle')
    # graph_file = 'vim.pkl'
    with open(filename, 'rb') as f:
        entity_embding = pickle.load(f)
    with open(edge_map_file, 'rb') as f:
        edge_map = pickle.load(f)
    with open(relation_file, 'rb') as f:
        relation_embding = pickle.load(f)
    with open(node_map_file, 'rb') as f:
        node_map = pickle.load(f)

    entity_embding_dict = {}
    for k in node_map.keys():
        entity_embding_dict[k] = entity_embding[node_map[k]]
    relation_embding_dict = {}
    for k in edge_map.keys():
        relation_embding_dict[k] = relation_embding[edge_map[k]]

    event_embding_dict = {}
    original_triplet = os.path.join(benchmark_path, 'original_triplet.pickle')
    with open(original_triplet, 'rb') as f:
        original_list = pickle.load(f)

    original_tuple_list = []
    for tup in original_list:
        lst = list(tup)
        lst[1], lst[2] = lst[2], lst[1]
        tup2 = tuple(lst)
        original_tuple_list.append(tup2)

    dot_save_path = os.path.join(data_path, 'visualization')
    if not os.path.exists(dot_save_path):
        os.makedirs(dot_save_path)
    if arg_parses.watson:
        subgraphs, event_embding_dict, check_triplet, check_size = watson_embedding(graph_file, node_map, edge_map)
    else:
        subgraphs, event_embding_dict, check_triplet, check_size = log_fusion_embedding(graph_file, node_map, edge_map, arg_parses)

    check_triplet_func(original_list, check_triplet)
    figure_save_path = os.path.join(data_path, 'cluster')

    X = []
    subgraph_list = []
    for subgraph in subgraphs:
        if subgraph != []:
            subgraph_list.append(subgraph)
            _array = np.zeros(check_size)
            for edge in subgraph:
                try:
                    _array += event_embding_dict[edge]
                except KeyError:
                    print("Not find in original_triple", edge)
            X.append(_array)
    X = np.array(X)
    nxgraphs = []
    for subgraph in subgraph_list:
        G1 = nx.MultiDiGraph()
        new_subgraph = []
        for g in subgraph:
            new_subgraph.append((g[0], g[2], g[1]))
        G1.add_edges_from(new_subgraph)
        nxgraphs.append(G1)

    with open(os.path.join(dot_save_path, 'graph.pickle'), 'wb') as pickle_file:
        pickle.dump(nxgraphs, pickle_file)


    function_mapping = {
        'incdbscan': incdbscanCluster,
        'Agg': AggCluster,
        'DenStream': DenStreamCluster,
        'minibathkm': minibathkmCluster,
        'Clustream': ClustreamCluster,
        'StreamKM': StreamKMCluster,
        'SA':mykm
    }

    if arg_parses.cluster in function_mapping:
        selected_function = function_mapping[arg_parses.cluster]
        if arg_parses.watson:
            selected_function = function_mapping["Agg"]
        labels_all = selected_function(X, arg_parses)
    else:
        print("Invalid function name.")

    import scipy.cluster.hierarchy as shc

    plt.figure(figsize=(8, 8))
    plt.title('Visualising the data')
    Dendrogram = shc.dendrogram((shc.linkage(X, method='ward')))
    if not os.path.exists(figure_save_path):
        os.makedirs(figure_save_path)  
    plt.savefig(os.path.join(figure_save_path, 'AggCluster.png'))
    plt.show()

    stdout_backup = sys.stdout
    print_file = open(os.path.join(figure_save_path, "output.txt"), "w")
    sys.stdout = print_file

    labels_ = labels_all
    unique_labels = set(labels_)
    cluster_num = len(unique_labels)

    print(cluster_num)
    print(labels_all)
    for type in unique_labels:
        print("cluster:", type)
        for i in range(0, len(labels_)):
            if labels_[i] == type:
                print("sub_graph:", subgraph_list[i])
        print('-------------------------')

    cluster_pickle_path = os.path.join(figure_save_path, "cluster.pickle")
    with open(cluster_pickle_path, 'wb') as f:
        pickle.dump(labels_, f)


    def compute_cluster_centers(elements, labels):
        unique_labels = np.unique(labels)
        cluster_centers = []

        for label in unique_labels:

            indices = np.where(labels == label)

            cluster_elements = elements[indices]

            center = np.mean(cluster_elements, axis=0)
            cluster_centers.append(center)

        return cluster_centers


    cluster_centers = compute_cluster_centers(X, labels_)
    from scipy.spatial.distance import cdist

    distances = cdist(cluster_centers, X, 'euclidean')

    closest_indices = np.argmin(distances, axis=1)

    with open(os.path.join(dot_save_path, 'cluster_centers.pickle'), 'wb') as pickle_file:
        pickle.dump(closest_indices, pickle_file)

    metric = 'cosine'
    print("%s Silhouette Coefficient: %0.3f"
          % (metric, metrics.silhouette_score(X, labels_, metric='sqeuclidean')))

    from sklearn.metrics import davies_bouldin_score

    db_index = davies_bouldin_score(X, labels_)

    print("Davies-Bouldin Index: %0.3f" % db_index)

    plt.figure()
    plt.axes([0, 0, 1, 1])

    colors = plt.rcParams['axes.prop_cycle'].by_key()['color']  
    for l, c in zip(np.arange(cluster_num), colors):
        row_ix = np.where(l == labels_)
        plt.scatter(X[row_ix, 0], X[row_ix, 1])


    plt.axis("tight")
    plt.axis("off")
    plt.suptitle("AgglomerativeClustering(affinity=%s)" % metric, size=20)
    plt.savefig(os.path.join(figure_save_path, 'dot.png'))
    plt.show()
    sys.stdout = stdout_backup
    print_file.close()


    tsne = TSNE(n_components=2, random_state=0)
    X_reduced_tsne = tsne.fit_transform(X)

    plt.figure(figsize=(10, 6))
    unique_labels = np.unique(labels_all)

    for label in unique_labels:
        plt.scatter(X_reduced_tsne[labels_all == label, 0], X_reduced_tsne[labels_all == label, 1], label=f'Cluster {label}',
                    s=30, alpha=1)

    plt.legend()
    plt.title('t-SNE Visualization of Clustering')
    plt.xlabel('t-SNE Feature 1')
    plt.ylabel('t-SNE Feature 2')
    plt.show()
