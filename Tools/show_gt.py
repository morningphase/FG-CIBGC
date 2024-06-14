from parse_args import args
import os
import pickle
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

if __name__=="__main__":
    data_path = f'../Data/{args.dataset}'
    benchmark_path = f'../Data/{args.dataset}/benchmark/{args.dataset.lower()}'

    figure_save_path = os.path.join(data_path, 'cluster')
    cluster_pickle_path = os.path.join(figure_save_path,"cluster.pickle")
    app_graph_dict_path = os.path.join(data_path, "app_graph_dict.pickle")
    equal_dict_path = os.path.join(data_path, "equal_dict.pickle")
    node_map_file = os.path.join(benchmark_path, 'node_mapping.pickle')
    graph_file = os.path.join(data_path, 'graph_list.pickle')

    
    with open(equal_dict_path,'rb') as f:
        equal_dict = pickle.load(f)
    
    with open(node_map_file, 'rb') as f:
        node_map = pickle.load(f)

    from Cluster.dfs import get_subgraph_not_dfs
    subgraph_list,_,_ = get_subgraph_not_dfs(graph_file,node_map)

    for k in equal_dict.keys():
        equal_dict[k]=[subgraph_list[i] for i in equal_dict[k]]

    stdout_backup = sys.stdout
    print_file = open("output.txt", "w")
    sys.stdout = print_file
    for k  in equal_dict.keys():
        print(k)
        print("-------------------------")
        for i in equal_dict[k]:
            print(i)