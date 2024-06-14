import openke
from openke.config import Trainer, Tester
from openke.module.model import TransE
from openke.module.loss import MarginLoss
from openke.module.strategy import NegativeSampling
from openke.data import TrainDataLoader, TestDataLoader
from utils import dataset

# dataloader for training
train_dataloader = TrainDataLoader(
    in_path = f"benchmarks/{dataset}/",
    nbatches = 1,
    threads = 8,
    sampling_mode = "normal",
    bern_flag = 1,
    filter_flag = 1,
    neg_ent = 25,
    neg_rel = 0)


# define the model
transe = TransE(
    ent_tot = train_dataloader.get_ent_tot(),
    rel_tot = train_dataloader.get_rel_tot(),
    dim = 200,
    p_norm = 1,
    norm_flag = True)


# define the loss function
model = NegativeSampling(
    model = transe,
    loss = MarginLoss(margin = 5.0),
    batch_size = train_dataloader.get_batch_size()
)

# train the model
trainer = Trainer(model = model, data_loader = train_dataloader, train_times = 1000, alpha = 1.0, use_gpu = True)
trainer.run()
transe.save_checkpoint('./checkpoint/transe.ckpt')

# 导出实体和关系的嵌入
entity_embeddings = transe.get_parameters("entity")
relation_embeddings = transe.get_parameters("relation")


# 将实体和关系的嵌入保存到文件中
with open(f"benchmark/{dataset}/entity_embeddings.txt", "w") as entity_file:
    for entity_id, embedding in enumerate(entity_embeddings):
        entity_file.write(f"{entity_id}\t{' '.join(map(str, embedding))}\n")

with open(f"benchmark/{dataset}/relation_embeddings.txt", "w") as relation_file:
    for relation_id, embedding in enumerate(relation_embeddings):
        relation_file.write(f"{relation_id}\t{' '.join(map(str, embedding))}\n")

