import os
import sklearn
import pickle
from collections import Counter
from parse_args import args


if __name__ == "__main__":
    data_path = f'../Data/{args.dataset}'
    print(args.dataset)
    figure_save_path = os.path.join(data_path, 'cluster')
    cluster_pickle_path = os.path.join(figure_save_path,"cluster.pickle")
    app_graph_dict_path = os.path.join(data_path, "app_graph_dict.pickle")
    equal_dict_path = os.path.join(data_path, "equal_dict.pickle")

    with open(cluster_pickle_path,'rb') as f:
        cluster_res = pickle.load(f)
    print(cluster_res,len(cluster_res))

    with open(app_graph_dict_path,'rb') as f:
        app_graph_dict = pickle.load(f)
    # print(len(app_graph_dict))

    with open(equal_dict_path,'rb') as f:
        equal_dict = pickle.load(f)

    print("equal_dict",equal_dict)
    unique_clusters = set(cluster_res)
    cluster_set = {}
    for label in unique_clusters:
        cluster_set[label]=[]
    for i in range(len(cluster_res)):
        cluster_set[cluster_res[i]].append(i)
    reversed_cluster_set = {value: key for key, values in cluster_set.items() for value in values}
    equal_dict_ans={}
    for k,v in equal_dict.items():
        equal_dict_ans[k]=[]
        for l in v:
            equal_dict_ans[k].append(reversed_cluster_set[l])

    for k,v in equal_dict_ans.items():
        #print(k,v)
        counter = Counter(v)
        most_common = counter.most_common()
        max_frequency = most_common[0][1]
        modes = [item for item, freq in most_common if freq == max_frequency]



    from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score

    reversed_GT_set =  {value: key for key, values in equal_dict.items() for value in values}


    actual = [reversed_GT_set[i] for i in range(len(reversed_GT_set))]
    pred_to_label = {}  
    for k,vals in cluster_set.items():
        cur = [reversed_GT_set[l] for l in vals]
        counter = Counter(cur)
        most_common = counter.most_common()
        max_frequency = most_common[0][1]
        modes = [item for item, freq in most_common if freq == max_frequency]
        pred_to_label[k] = modes[0]
    print(pred_to_label)
    pred = [pred_to_label[l] for l in cluster_res]  
    precision = precision_score(y_true=actual, y_pred=pred, average='weighted')
    f1 = f1_score(y_true=actual, y_pred=pred, average='weighted') 
    acc = accuracy_score(y_true=actual, y_pred=pred)
    recall = recall_score(y_true=actual,y_pred=pred,average='weighted') 
    print('Cluster_Number: ',len(unique_clusters))
    print('Precision: ', precision)
    print('Accuracy: ', acc)
    print('Recall: ', recall)
    print('F1-score: ', f1)

