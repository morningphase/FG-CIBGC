import sys
sys.path.append("..") # 模块父目录下的model文件中
from utils import *
from openke.config import Trainer
from openke.module.model import TransE, TransR, TransH, TransD
from openke.module.loss import MarginLoss
from openke.module.strategy import NegativeSampling
from openke.data import TrainDataLoader
import pickle
from sklearn import manifold
from n_n import n_n
from Embedding.LKGE.main import train_eval_lkge
dataset = args.dataset.lower()

def choose_model_loader(model_name):
    if model_name == 'TransE':
        train_dataloader = TrainDataLoader(
            in_path=f"../Data/{args.dataset}/benchmark/{dataset}/",
            nbatches=50,
            threads=8,
            sampling_mode="normal",
            bern_flag=1,
            filter_flag=1,
            neg_ent=25,
            neg_rel=0)
        model = TransE(
            ent_tot=train_dataloader.get_ent_tot(),
            rel_tot=train_dataloader.get_rel_tot(),
            dim=64,
            p_norm=1,
            norm_flag=True)
    elif model_name == 'TransD':
        train_dataloader = TrainDataLoader(
            in_path=f"../Data/{args.dataset}/benchmark/{dataset}/",
            nbatches=50,
            threads=8,
            sampling_mode="normal",
            bern_flag=1,
            filter_flag=1,
            neg_ent=25,
            neg_rel=0)
        model = TransD(
            ent_tot=train_dataloader.get_ent_tot(),
            rel_tot=train_dataloader.get_rel_tot(),
            dim_e=64,
            dim_r=64,
            p_norm=1,
            norm_flag=True)
    elif model_name == 'TransH':
        train_dataloader = TrainDataLoader(
            in_path=f"../Data/{args.dataset}/benchmark/{dataset}/",
            nbatches=50,
            threads=8,
            sampling_mode="normal",
            bern_flag=1,
            filter_flag=1,
            neg_ent=25,
            neg_rel=0)
        model = TransH(
            ent_tot=train_dataloader.get_ent_tot(),
            rel_tot=train_dataloader.get_rel_tot(),
            dim=64,
            p_norm=1,
            norm_flag=True)
    elif model_name == 'TransR':
        train_dataloader = TrainDataLoader(
            in_path=f"../Data/{args.dataset}/benchmark/{dataset}/",
            nbatches=50,
            threads=8,
            sampling_mode="normal",
            bern_flag=1,
            filter_flag=1,
            neg_ent=25,
            neg_rel=0)
        model = TransR(
            ent_tot=train_dataloader.get_ent_tot(),
            rel_tot=train_dataloader.get_rel_tot(),
            dim_e=64,
            dim_r=64,
            p_norm=1,
            norm_flag=True,
            rand_init=False)
    elif model_name == 'LKGE':
        train_dataloader = None
        model = None
    elif model_name == 'GEM':
        train_dataloader = None
        model = None
    elif model_name == 'EMR':
        train_dataloader = None
        model = None
    elif model_name == 'LAN':
        train_dataloader = None
        model = None
    elif model_name == 'finetune':
        train_dataloader = None
        model = None
    elif model_name == 'Snapshot':
        train_dataloader = None
        model = None
    elif model_name == 'SI':
        train_dataloader = None
        model = None
    elif model_name == 'CWR':
        train_dataloader = None
        model = None
    elif model_name == 'PNN':
        train_dataloader = None
        model = None
    elif model_name == 'MEAN':
        train_dataloader = None
        model = None
    elif model_name == 'EWC':
        train_dataloader = None
        model = None
    elif model_name == 'retraining':
        train_dataloader = None
        model = None
    elif model_name == 'DLKGE':
        train_dataloader = None
        model = None
    return model, train_dataloader


def snapshot_kg():
    kg_snapshots = []
    with open(f'../Data/{args.dataset}/graph_snapshots.pickle', 'rb') as f:
        snapshots = pickle.load(f)
    all_edges = set()
    all_nodes = set()
    for idx, snapshot in enumerate(snapshots):
        for source, target, key, attributes in snapshot.edges(keys=True, data=True):
            relation_type = attributes['relation']
            single_triplet = (source, relation_type, target)
            all_nodes.add(source)
            all_nodes.add(target)
            all_edges.add(single_triplet)
    edge_num = len(all_edges)
    existing_nodes = set()
    existing_relation = set()
    kg_snapshots.append([])
    kg_snapshots[0] = random.choices(list(all_edges), k=int(edge_num / 5) + 1)

    edges_to_remove = set()
    for fact in kg_snapshots[0]:
        existing_nodes.add(fact[0])
        existing_nodes.add(fact[2])
        existing_relation.add(fact[1])
        edges_to_remove.add(fact)
    for edge in edges_to_remove:
        all_edges.remove(edge)
    for i in range(1, 5):
        kg_snapshots.append([])
        if i != 4:
            edges_to_remove = set()
            for edge in all_edges:
                if edge[0] in existing_nodes or edge[2] in existing_nodes:
                    existing_nodes.add(edge[0])
                    existing_nodes.add(edge[2])
                    existing_relation.add(edge[1])
                    kg_snapshots[i].append(edge)
                    edges_to_remove.add(edge)
                    if len(kg_snapshots[i]) >= int(edge_num / 5) + 1:
                        break
            for edge in edges_to_remove:
                all_edges.remove(edge)
        else:
            for edge in all_edges:
                existing_nodes.add(edge[0])
                existing_nodes.add(edge[2])
                existing_relation.add(edge[1])
                kg_snapshots[i].append(edge)

    return kg_snapshots


def snapshot_kg_old():
    n = 5
    kg_snapshots  = []

    with open(f'../Data/{args.dataset}/graph_snapshots.pickle', 'rb') as f:
        snapshots = pickle.load(f)
    last_snapshots = None
    for idx, snapshot in enumerate(snapshots):
        s_r__o_triple = set()
        for source, target, key, attributes in snapshot.edges(keys=True, data=True):
            relation_type = attributes['relation']

            single_triplet = (source, relation_type, target)
            if last_snapshots != None and single_triplet not in last_snapshots:
                for last_triplet in last_snapshots:
                    if last_triplet[0] == source or last_triplet[2] == source or last_triplet[0] == target or last_triplet[2] == target:
                        s_r__o_triple.add(last_triplet)
            s_r__o_triple.add((source, relation_type, target))
        kg_snapshots.append(s_r__o_triple)
        last_snapshots = s_r__o_triple


    return kg_snapshots

def train_eval_openke(trans, train_dataloader, model_name):

    model = NegativeSampling(
        model = trans,
        loss = MarginLoss(margin = 5.0),
        batch_size = train_dataloader.get_batch_size()
    )

    trainer = Trainer(model = model, data_loader = train_dataloader, train_times = 1000, alpha = 1.0, use_gpu = False)
    trainer.run()
    checkpoint_dir = f'../Data/{args.dataset}/checkpoint/'
    if not os.path.exists(checkpoint_dir):
        os.makedirs(checkpoint_dir)

    trans.save_checkpoint(f'{checkpoint_dir}/{model_name}.ckpt')
    embeddings = trans.get_parameters()
    entity_embeddings = embeddings["ent_embeddings.weight"]
    relation_embeddings = embeddings["rel_embeddings.weight"]
    return entity_embeddings, relation_embeddings

def save_embeddings(entity_embeddings, relation_embeddings):

    with open(f"../Data/{args.dataset}/benchmark/{dataset}/relation_embeddings.pickle", 'wb') as f:
        pickle.dump(relation_embeddings, f)

    with open(f"../Data/{args.dataset}/benchmark/{dataset}/entity_embeddings.pickle", 'wb') as f:
        pickle.dump(entity_embeddings, f)

    with open(f"../Data/{args.dataset}/benchmark/{dataset}/entity_embeddings.txt", "w") as entity_file:
        for entity_id, embedding in enumerate(entity_embeddings):
            if entity_id not in node_mapping:
                continue
            entity_name = node_mapping[entity_id]
            entity_file.write(f"{entity_id}\t{entity_name}\t{' '.join(map(str, embedding))}\n")

    with open(f"../Data/{args.dataset}/benchmark/{dataset}/relation_embeddings.txt", "w") as relation_file:
        for relation_id, embedding in enumerate(relation_embeddings):
            relation_name = edge_mapping[relation_id]
            relation_file.write(f"{relation_id}\t{relation_name}\t{' '.join(map(str, embedding))}\n")


if __name__ == '__main__':
    print('Start Getting Scores!')
    os.system(f"python test_score.py")

    print('Start Preprocessing KG!')
    edge_name_set = set()
    node_name_set = set()
    original_triple = set()
    s_r__o_triple = set()

    with open(f'../Data/{args.dataset}/graph_schema.pickle', 'rb') as f:
        graph_list = pickle.load(f)
    print(args.dataset)
    for subgraph in graph_list:
        for source, target, key, attributes in subgraph.edges(keys=True, data=True):
            relation_type = attributes['relation']
            edge_name_set.add(relation_type)
            node_name_set.add(source)
            node_name_set.add(target)
            original_triple.add((source, target, relation_type))
            s_r__o_triple.add((source, relation_type, target))

    graph_with_id_dir = f'../Data/{args.dataset}/all_graph_list.pickle'
    edge_set, node_set, kg_set, node_mapping, edge_mapping = re_generate_ids(node_name_set, edge_name_set, original_triple, graph_with_id_dir)

    if args.embedding == 'OpenKE':
        output_file(edge_set, 'relation2id.txt', dataset, first_line_reserved=True)
        output_file(node_set, 'entity2id.txt', dataset, first_line_reserved=True)
        output_file(kg_set, 'train2id.txt', dataset, first_line_reserved=True)
        output_file(kg_set, 'test2id.txt', dataset, first_line_reserved=True)
        output_file(kg_set, 'valid2id.txt', dataset, first_line_reserved=True)
        train2id = f'../Data/{args.dataset}/benchmark/{dataset}/train2id.txt'
        valid2id = f'../Data/{args.dataset}/benchmark/{dataset}/valid2id.txt'
        test2id = f'../Data/{args.dataset}/benchmark/{dataset}/test2id.txt'
        type_constrain = f'../Data/{args.dataset}/benchmark/{dataset}/type_constrain.txt'
        test2id_all = f'../Data/{args.dataset}/benchmark/{dataset}/test2id_all.txt'
        txt_1_1 = f'../Data/{args.dataset}/benchmark/{dataset}/1-1.txt'
        txt_1_n = f'../Data/{args.dataset}/benchmark/{dataset}/1-n.txt'
        txt_n_1 = f'../Data/{args.dataset}/benchmark/{dataset}/n-1.txt'
        txt_n_n = f'../Data/{args.dataset}/benchmark/{dataset}/n-n.txt'
        n_n(train2id, valid2id, test2id, type_constrain,  test2id_all, txt_1_1, txt_1_n, txt_n_1, txt_n_n)

    elif args.embedding == 'LKGE' and False:
        snapshots = snapshot_kg()
        args.memory = min(len(snapshot) for snapshot in snapshots)
        # snapshots = snapshot_kg_old()
        for idx, s_r__o_triple in enumerate(snapshots):
            output_file(s_r__o_triple,f'train.txt', dataset, first_line_reserved=False, snapshot=idx)
            output_file(s_r__o_triple, f'valid.txt', dataset, first_line_reserved=False, snapshot=idx)
            output_file(s_r__o_triple, f'test.txt', dataset, first_line_reserved=False, snapshot=idx)

    mapping_store(node_mapping, 'node_mapping.pickle', dataset)
    mapping_store(edge_mapping, 'edge_mapping.pickle', dataset)
    mapping_store(original_triple, 'original_triplet.pickle', dataset)

    ts = manifold.TSNE(n_components=2, init='pca', random_state=0, perplexity=4)


    node_save_path = f"../Data/{args.dataset}/benchmark/{dataset}/node_mapping.pickle"
    with open(node_save_path, 'rb') as f:
        node_mapping = pickle.load(f)

        node_mapping = dict(zip(node_mapping.values(), node_mapping.keys()))

    edge_save_path = f"../Data/{args.dataset}/benchmark/{dataset}/edge_mapping.pickle"
    with open(edge_save_path, 'rb') as f:
        edge_mapping = pickle.load(f)
        edge_mapping = dict(zip(edge_mapping.values(), edge_mapping.keys()))

    embedding_model, train_dataloader = choose_model_loader(args.kg)
    entity_embeddings, relation_embeddings = [], []
    if args.embedding == 'OpenKE':
        entity_embeddings, relation_embeddings = train_eval_openke(embedding_model, train_dataloader, args.kg)
        relation2id = None
    elif args.embedding == 'LKGE':
        entity_embeddings, relation_embeddings, relation2id, relation2inv = train_eval_lkge(args)
    else:
        pass
    if len(entity_embeddings) != 0 and len(relation_embeddings) != 0:
        if relation2id != None:
            new_relation = torch.Tensor([])
            for edge_id, edge_name in edge_mapping.items():
                real_edge_id = relation2id[edge_name]
                if len(new_relation) == 0:
                    new_relation = relation_embeddings[real_edge_id].unsqueeze(0)
                    print(new_relation.shape)
                else:
                    new_relation = torch.cat((new_relation, relation_embeddings[real_edge_id].unsqueeze(0)), dim=0)
            relation_embeddings = new_relation
            entity_embeddings = entity_embeddings.detach().cpu().numpy()
            relation_embeddings = relation_embeddings.detach().cpu().numpy()

        save_embeddings(entity_embeddings, relation_embeddings)




