import torch.nn
from torch_scatter import scatter_add, scatter_mean, scatter_max
from .BaseModel import *


class DLKGE(BaseModel):
    def __init__(self, args, kg):
        super(DLKGE, self).__init__(args, kg)
        self.init_old_weight()
        self.mse_loss_func = nn.MSELoss(size_average=False)
        self.ent_weight, self.rel_weight, self.rel_attention_weight, self.other_weight = None, None, None, None
        self.margin_loss_func = nn.MarginRankingLoss(float(self.args.margin), size_average=False).to(self.args.device)

    def store_old_parameters(self):
        '''
        Store learned paramters and weights for regularization.
        '''
        self.args.snapshot -= 1
        param_weight = self.get_new_weight()
        self.args.snapshot += 1
        # 仅包含ent_embeddings.weight 和 rel_embeddings.weight两个权重向量
        # 我们的改造需要让他具备处理K个语义分量的能力,现在具备rel_attention和他对应的权重
        for name, param in self.named_parameters():
            name = name.replace('.', '_')
            value = param.data
            old_weight = getattr(self, 'old_weight_{}'.format(name))
            new_weight = param_weight[name]
            self.register_buffer('old_data_{}'.format(name), value)
            if '_embeddings' in name or 'attention' in name:
                if self.args.snapshot == 0:
                    old_weight = torch.zeros_like(new_weight)
                else:
                    # 这段代码检查是否在处理嵌入层的权重，并根据 snapshot 的值来更新一个名为 old_weight 的张量。
                    # 如果是第一次（snapshot 等于0），则创建一个全零的张量。
                    # 否则，扩展 old_weight 张量以匹配 new_weight 的尺寸，通过在必要的维度上添加零来实现。
                    old_weight = torch.cat([old_weight, torch.zeros(new_weight.size(0) - old_weight.size(0), 1).to(self.args.device)], dim=0)
            self.register_buffer('old_weight_{}'.format(name), old_weight + new_weight)


    def init_old_weight(self):
        '''
        Initialize the learned parameters for storage.
        '''
        # 这段代码在一个神经网络模型中为不同的参数类型注册了两种缓冲区：old_weight 和 old_data。
        # 对于实体嵌入和关系嵌入参数，这些缓冲区被初始化为空张量。对于其他类型的参数，old_weight 被初始化为0.0，
        # 而 old_data 则复制了参数的当前数据。
        for name, param in self.named_parameters():
            name_ = name.replace('.', '_')
            if 'ent_embeddings' in name_:
                self.register_buffer('old_weight_{}'.format(name_), torch.tensor([[]]))
                self.register_buffer('old_data_{}'.format(name_), torch.tensor([[]]))
            elif 'rel_embeddings' in name_:
                self.register_buffer('old_weight_{}'.format(name_), torch.tensor([[]]))
                self.register_buffer('old_data_{}'.format(name_), torch.tensor([[]]))
            elif 'attention' in name_:
                self.register_buffer('old_weight_{}'.format(name_), torch.tensor([[]]))
                self.register_buffer('old_data_{}'.format(name_), torch.tensor([[]]))
            else:
                self.register_buffer('old_weight_{}'.format(name_), torch.tensor(0.0))
                self.register_buffer('old_data_{}'.format(name_), param.data)

    def switch_snapshot(self):
        '''
        Prepare for the training on next snapshot.
        '''
        '''store old parameters'''
        self.store_old_parameters()
        '''expand embedding size for new entities and relations'''
        ent_embeddings, rel_embeddings, rel_attentions = self.expand_embedding_size(k=self.k_factor)
        new_ent_embeddings = ent_embeddings.weight.data
        new_rel_embeddings = rel_embeddings.weight.data
        new_rel_attentions = rel_attentions.weight.data
        '''inherit learned paramters'''
        new_ent_embeddings[:self.kg.snapshots[self.args.snapshot].num_ent] = torch.nn.Parameter(self.ent_embeddings.weight.data)
        new_rel_embeddings[:self.kg.snapshots[self.args.snapshot].num_rel] = torch.nn.Parameter(self.rel_embeddings.weight.data)
        new_rel_attentions[:self.kg.snapshots[self.args.snapshot].num_rel] = torch.nn.Parameter(self.rel_attentions.weight.data)

        # 更新嵌入
        self.ent_embeddings.weight = torch.nn.Parameter(new_ent_embeddings)
        self.rel_embeddings.weight = torch.nn.Parameter(new_rel_embeddings)
        self.rel_attentions.weight = torch.nn.Parameter(new_rel_attentions)
        '''embedding transfer'''
        # 论文里面的嵌入迁移
        if self.args.using_embedding_transfer == 'True':
            # 用旧实体旧关系的嵌入获得新实体新关系的嵌入
            reconstruct_ent_embeddings, reconstruct_rel_embeddings, reconstruct_rel_attentions = self.reconstruct()
            new_ent_embeddings[self.kg.snapshots[self.args.snapshot].num_ent:] = reconstruct_ent_embeddings[self.kg.snapshots[self.args.snapshot].num_ent:]
            new_rel_embeddings[self.kg.snapshots[self.args.snapshot].num_rel:] = reconstruct_rel_embeddings[self.kg.snapshots[self.args.snapshot].num_rel:]
            new_rel_attentions[self.kg.snapshots[self.args.snapshot].num_rel:] = reconstruct_rel_attentions[self.kg.snapshots[self.args.snapshot].num_rel:]
            self.ent_embeddings.weight = torch.nn.Parameter(new_ent_embeddings)
            self.rel_embeddings.weight = torch.nn.Parameter(new_rel_embeddings)
            self.rel_attentions.weight = torch.nn.Parameter(new_rel_attentions)
        '''store the total number of facts containing each entity or relation'''
        # 这个weight是正则化项
        new_ent_weight, new_rel_weight, new_att_weight, new_other_weight = self.get_weight()
        # 这个函数的核心就是为了获得新实体和新关系的嵌入
        self.register_buffer('new_weight_ent_embeddings_weight', new_ent_weight.clone().detach())
        self.register_buffer('new_weight_rel_embeddings_weight', new_rel_weight.clone().detach())
        self.register_buffer('new_weight_rel_attentions', new_att_weight.clone().detach())

        '''get regularization weights'''
        self.new_weight_other_weight = new_other_weight

    def reconstruct(self):
        '''
        Reconstruct the entity and relation embeddings.
        '''
        num_ent, num_rel = self.kg.snapshots[self.args.snapshot+1].num_ent, self.kg.snapshots[self.args.snapshot+1].num_rel
        edge_index, edge_type = self.kg.snapshots[self.args.snapshot+1].edge_index, self.kg.snapshots[self.args.snapshot+1].edge_type
        try:
            old_entity_weight = self.old_weight_entity_embeddings
            old_relation_weight = self.old_weight_relation_embeddings
            old_x = self.old_data_entity_embeddings
            old_r = self.old_data_relation_embeddings
            old_att = self.old_data_rel_attentions
            old_relation_attention_weight = self.old_weight_rel_attentions
        except:
            old_entity_weight, old_relation_weight = None, None
            old_x, old_r = None, None
            old_att = None
            old_relation_attention_weight = None
        new_embeddings, rel_embeddings, rel_att = self.gcn(self.ent_embeddings.weight, self.rel_embeddings.weight, self.rel_attentions.weight, edge_index, edge_type, num_ent, num_rel, old_entity_weight, old_relation_weight, old_relation_attention_weight, old_x, old_r, old_att)
        return new_embeddings, rel_embeddings, rel_att

    def get_new_weight(self):
        '''
        Calculate the regularization weights for entities and relations.
        :return: weights for entities and relations.
        '''
        ent_weight, rel_weight, att_weight, other_weight = self.get_weight()
        weight = dict()
        for name, param in self.named_parameters():
            name_ = name.replace('.','_')
            if 'ent_embeddings' in name_:
                weight[name_] = ent_weight
                # print(param)
            elif 'rel_embeddings' in name_:
                weight[name_] = rel_weight
                # print(param)
            elif 'attention' in name_:
                weight[name_] = att_weight
                # print(param)
            else:
                weight[name_] = other_weight
                # print(param)
        return weight

    def new_loss(self, head, rel, tail=None, label=None):
        margin_loss, top_att = self.margin_loss(head, rel, tail, label)
        return margin_loss.mean(), top_att

    def attentions(self):
        return self.rel_attentions.weight


    def lkge_regular_loss(self):
        '''
        Calculate regularization loss to avoid catastrophic forgetting.
        :return: regularization loss.
        '''
        # 这个就是正则化损失函数
        if self.args.snapshot == 0:
            return 0.0
        losses = []
        '''get samples number of entities and relations'''
        new_ent_weight, new_rel_weight, new_att_weight, new_other_weight = self.new_weight_ent_embeddings_weight, self.new_weight_rel_embeddings_weight, self.new_weight_rel_attentions, self.new_weight_other_weight
        '''calculate regularization loss'''
        for name, param in self.named_parameters():
            name = name.replace('.', '_')
            if 'ent_embeddings' in name:
                new_weight = new_ent_weight
            elif 'rel_embeddings' in name:
                new_weight = new_rel_weight
            elif 'attention' in name:
                new_weight = new_att_weight
            else:
                new_weight = new_other_weight
            new_data = param
            if 'embeddings' in name:
                old_weight = getattr(self, 'old_weight_{}'.format(name))
                old_data = getattr(self, 'old_data_{}'.format(name))
            if 'attention' in name:
                old_weight = getattr(self, 'old_weight_{}'.format(name))
                old_data = getattr(self, 'old_data_{}'.format(name))
            if type(new_weight) != int:
                new_weight = new_weight[:old_weight.size(0)]
                new_data = new_data[:old_data.size(0)]
            losses.append((((new_data - old_data) * old_weight / (new_weight+old_weight)) ** 2).sum())
        return sum(losses)


class TransE(DLKGE):
    def __init__(self, args, kg):
        super(TransE, self).__init__(args, kg)
        self.gcn = MAE(args, kg)

    def attention_loss(self, rel, top_att):
        top_num_att = torch.sum(top_att, 1)
        y2 = torch.ones(int(rel.size(0))).cuda()
        att_loss = torch.mean(y2 - top_num_att)
        return att_loss

    def MAE_loss(self, head, rel, tail):
        '''
        Calculate the MAE loss by masking and reconstructing embeddings.
        :return: MAE loss
        '''
        num_ent = self.kg.snapshots[self.args.snapshot].num_ent
        num_rel = self.kg.snapshots[self.args.snapshot].num_rel
        '''get subgraph(edge indexs and relation types of all facts in the training facts)'''
        edge_index = self.kg.snapshots[self.args.snapshot].edge_index
        edge_type = self.kg.snapshots[self.args.snapshot].edge_type

        '''reconstruct'''
        # 这个函数只是纯Return嵌入值
        ent_embeddings, rel_embeddings = self.embedding('Train')
        rel_attentions = self.attentions()

        try:
            old_entity_weight = self.old_weight_entity_embeddings
            old_relation_weight = self.old_weight_relation_embeddings
            old_x = self.old_data_entity_embeddings
            old_r = self.old_data_relation_embeddings
            old_att = self.old_data_rel_attentions
            old_relation_attention_weight = self.old_weight_rel_attentions
        except:
            old_entity_weight, old_relation_weight = None, None
            old_x, old_r = None, None
            old_att = None
            old_relation_attention_weight = None
        # 新旧实体关系嵌入都会集成到一起
        ent_embeddings_reconstruct, rel_embeddings_reconstruct, rel_attentions_reconstruct = self.gcn(ent_embeddings, rel_embeddings, rel_attentions, edge_index, edge_type, num_ent, num_rel, old_entity_weight, old_relation_weight, old_relation_attention_weight, old_x, old_r, old_att)
        # 这段代码计算了两组嵌入之间的均方误差（Mean Squared Error, MSE）损失，并将这两个损失相加
        return(self.mse_loss_func(ent_embeddings_reconstruct, ent_embeddings[:num_ent]) / num_ent + self.mse_loss_func(
            rel_embeddings_reconstruct, rel_embeddings[:num_rel]) / num_rel + self.mse_loss_func(
            rel_attentions_reconstruct, rel_attentions[:num_rel]) / num_rel)

    def loss(self, head, rel, tail=None, label=None):
        '''
        :param head: subject entity
        :param rel: relation
        :param tail: object entity
        :param label: positive or negative facts
        :return: new facts loss + MAE loss + regularization loss
        '''
        # 这里得到的head, tail, relation 都仅仅是索引值
        new_margin_loss, top_att = self.new_loss(head, rel, tail, label)
        new_loss = new_margin_loss/head.size(0)
        loss = new_loss
        if self.args.using_reconstruct_loss == 'True':
            MAE_loss = self.MAE_loss(head, rel, tail)
            loss += float(self.args.reconstruct_weight)*MAE_loss
        if self.args.using_regular_loss == 'True':
            regular_loss = self.lkge_regular_loss()
            loss += float(self.args.regular_weight)*regular_loss
        if self.args.using_att_norm_loss == 'True':
            att_norm_loss = self.attention_loss(rel, top_att)
            loss += float(self.args.atten_weight) * att_norm_loss
        return loss

    def get_weight(self):
        '''get the total number of samples containing each entity or relation'''
        num_ent = self.kg.snapshots[self.args.snapshot+1].num_ent
        num_rel = self.kg.snapshots[self.args.snapshot+1].num_rel
        ent_weight, rel_weight, att_weight, other_weight = self.gcn.get_weight(num_ent, num_rel)
        return ent_weight, rel_weight, att_weight, other_weight


class MAE(nn.Module):
    def __init__(self, args, kg):
        super(MAE, self).__init__()
        self.args = args
        self.kg = kg
        '''masked KG auto encoder'''
        self.conv_layers = nn.ModuleList()
        for i in range(args.num_layer):
            self.conv_layers.append(ConvLayer(args, kg))

    def forward(self, ent_embeddings, rel_embeddings, rel_att, edge_index, edge_type, num_ent, num_rel, old_entity_weight, old_relation_weight, old_relation_attention_weight, old_x, old_r, old_att):
        '''
        Reconstruct embeddings for all entities and relations
        :param x: input entity embeddings
        :param r: input relation embeddings
        :param edge_index: (s, o)
        :param edge_type: (r)
        :param num_ent: entity number
        :param num_rel: relation number
        :return: reconstructed embeddings
        '''
        x, r , r_att = ent_embeddings, rel_embeddings, rel_att
        for i in range(self.args.num_layer):
            x, r, r_att = self.conv_layers[i](x, r, rel_att, edge_index, edge_type, num_ent, num_rel, old_entity_weight, old_relation_weight, old_relation_attention_weight, old_x, old_r, old_att)
        return x, r, r_att

    def get_weight(self, num_ent, num_rel):
        '''get the total number of samples containing each entity or relation'''
        edge_index, edge_type = self.kg.snapshots[self.args.snapshot+1].edge_index, self.kg.snapshots[self.args.snapshot+1].edge_type
        other_weight = edge_index.size(1)
        # 这里的操作似乎是计算每个实体作为边的起点出现的次数。
        # scatter_add 是一个常见的操作，特别是在PyTorch这样的深度学习框架中。
        # 它是一种特殊的张量（tensor）操作，用于在指定的维度上按索引聚合（累加）值。
        ent_weight = scatter_add(src=torch.ones_like(edge_index[0]).unsqueeze(1), dim=0, index=edge_index[0], dim_size=num_ent)
        # 计算每种关系类型在图中出现的次数。
        rel_weight = scatter_add(src=torch.ones_like(edge_index[0]).unsqueeze(1), dim=0, index=edge_type, dim_size=num_rel)
        return ent_weight + 1, rel_weight + 1, rel_weight + 1, other_weight

class ConvLayer(nn.Module):
    def __init__(self, args, kg):
        super(ConvLayer, self).__init__()
        self.args = args
        self.kg = kg
        self.softmax = torch.nn.Softmax(dim=1)  # 处理注意力权重
        self.activate_function = torch.nn.ReLU()
        self.k_factor = args.k_factor
        self.top_n = args.top_n
        self.emb_s = int(self.args.emb_dim / self.k_factor)
        # 本质上就是TransE


    def forward(self, x, r, r_att, edge_index, edge_type, num_ent, num_rel, old_entity_weight, old_relation_weight, old_relation_attention_weight, old_x, old_r, old_att):
        '''
        Reconstruct embeddings for all entities and relations
        :param x: input entity embeddings
        :param r: input relation embeddings
        :param edge_index: (s, o)
        :param edge_type: (r)
        :param num_ent: entity number
        :param num_rel: relation number
        :return: reconstructed embeddings
        '''
        '''avoid the reliance for learned facts'''
        if old_entity_weight == None:  # for embedding transfer
            edge_index, edge_type = self.add_loop_edge(edge_index, edge_type, num_ent, num_rel)
            # torch.zeros(1, r.size(1))  将创建一个形状为 [1, m] 的零张量，即一行和 m 列的零矩阵。
            # 这段代码的作用是在原始张量 r 的底部添加一行零，从而扩展了它的行数，同时保持列数不变
            r = torch.cat([r, torch.zeros(1, r.size(1)).to(self.args.device)], dim=0)
            r_att = torch.cat([r_att, torch.zeros(1, r_att.size(1)).to(self.args.device)], dim=0)

            # 这行代码从张量 x 中选取特定的行。
            # 这里，x 是包含实体嵌入的张量，edge_index[1] 包含了图中每条边的目标节点（或称为“尾节点”）的索引。
            # torch.index_select 根据这些索引从 x 中选取相应的行（实体嵌入），构成一个新的张量 neigh_t。
            # 0 参数表示操作是沿着第一个维度（即行）进行的。
            neigh_t = torch.index_select(x, 0, edge_index[1])
            neigh_r = torch.index_select(r, 0, edge_type)
            neigh_h = torch.index_select(x, 0, edge_index[0])
            # ent_embed = torch.empty(neigh_t.size()).double()
            # rel_embed = torch.empty(neigh_r.size()).double()
            ent_embed = nn.Embedding(neigh_h.size(0), neigh_h.size(1)).to(self.args.device).double()
            nn.init.xavier_normal_(ent_embed.weight, gain= 1.414)
            ent_embed = ent_embed.weight

            neigh_t_factor = neigh_t.view(-1, self.k_factor, self.emb_s)
            ori_neigh_h_factor = neigh_h.view(-1, self.k_factor, self.emb_s)

            tmp = torch.index_select(r_att, 0, edge_type) # r_att[edge_type, :]
            att = self.softmax(tmp)
            # choose top n
            sorted_att, sorted_indices_in = torch.sort(att, dim=-1, descending=True)
            top_indices_in = sorted_indices_in[:, :self.top_n]
            # 获取除了top_n之外的其他索引
            remaining_indices_in = sorted_indices_in[:, self.top_n:]

            neigh_t_factor = neigh_t_factor.gather(1, top_indices_in.unsqueeze(-1).expand(-1, self.top_n, self.emb_s))
            neigh_h_factor = ori_neigh_h_factor.gather(1, top_indices_in.unsqueeze(-1).expand(-1, self.top_n, self.emb_s))
            neigh_h_remain = ori_neigh_h_factor.gather(1, remaining_indices_in.unsqueeze(-1).expand(-1, self.k_factor - self.top_n, self.emb_s))


            neigh_t_factor = neigh_t_factor.view(-1, self.top_n * self.emb_s)
            neigh_h_factor = neigh_h_factor.view(-1, self.top_n * self.emb_s)


            # 结果是一个张量 ent_embed，它包含了图中每个实体基于其邻居节点和关系的平均嵌入。
            tmp_ent_embed = neigh_h_factor + neigh_r
            tmp_ent_embed = tmp_ent_embed.view(-1, self.top_n, self.emb_s)
            ent_embed = ent_embed.view(-1, self.k_factor, self.emb_s)
            ent_embed = ent_embed.scatter(1, top_indices_in.unsqueeze(-1).expand(-1, self.top_n, self.emb_s), tmp_ent_embed)
            ent_embed = ent_embed.scatter(1, remaining_indices_in.unsqueeze(-1).expand(-1, self.k_factor - self.top_n, self.emb_s),
                                          neigh_h_remain)
            ent_embed = ent_embed.view(-1, self.k_factor * self.emb_s)

            ent_embed = scatter_mean(src=ent_embed, dim=0, index=edge_index[1], dim_size=num_ent)

            # 结果是一个张量 rel_embed，它包含了图中每种关系类型基于其连接的节点嵌入的平均嵌入。
            rel_embed = scatter_mean(src=neigh_t_factor - neigh_h_factor, dim=0, index=edge_type, dim_size=num_rel + 1)

            # ent_embed = torch.relu(ent_embed)
            ent_embed = self.activate_function(ent_embed)
            # 目的就是获取实体和关系的嵌入
            # 这段代码是图神经网络中的一部分，用于基于图的边和节点信息计算实体和关系的平均嵌入。
            # 它首先计算基于邻居节点和关系的实体嵌入和关系嵌入的聚合平均值，然后应用ReLU激活函数，并返回这些嵌入。
            # 这种计算方式有助于提取图中实体和关系的特征，通常用于图神经网络的节点和边的特征更新。
            return ent_embed, rel_embed[:-1], r_att[:-1]
        else:
            '''prepare old parameter and the number of |N(x)|'''
            if x.size(0) > old_entity_weight.size(0): # 这个条件检查当前实体嵌入的大小 (x.size(0)) 是否大于旧实体权重的大小。
                # 如果是，说明需要扩展旧权重以匹配当前的实体数量。
                old_entity_weight = torch.cat((old_entity_weight, torch.zeros(x.size(0)-old_entity_weight.size(0))), dim=0)
                old_x = torch.cat((old_x, torch.zeros(x.size(0)-old_entity_weight.size(0), x.size(1))), dim=0)
            if r.size(0) > old_relation_weight.size(0): # 同理
                old_relation_weight = torch.cat((old_relation_weight, torch.zeros(x.size(0) - old_relation_weight.size(0))),dim=0)
                old_r = torch.cat((old_r, torch.zeros(r.size(0) - old_relation_weight.size(0), r.size(1))), dim=0)
            if r_att.size(0) > old_att.size(0):
                old_relation_attention_weight = torch.cat((old_relation_attention_weight, torch.zeros(x.size(0) - old_relation_attention_weight.size(0))), dim=0)
                old_r_att = torch.cat((old_att, torch.zeros(r_att.size(0) - old_relation_attention_weight.size(0), r_att.size(1))), dim=0)


            '''add self-loop edges'''
            edge_index, edge_type = self.add_loop_edge(edge_index, edge_type, num_ent, num_rel)
            r = torch.cat([r, torch.zeros(1, r.size(1)).to(self.args.device)], dim=0)
            r_att = torch.cat([r_att, torch.zeros(1, r_att.size(1)).to(self.args.device)], dim=0)

            '''get neighbor embeddings'''
            neigh_t = torch.index_select(x, 0, edge_index[1])
            neigh_r = torch.index_select(r, 0, edge_type)
            neigh_h = torch.index_select(x, 0, edge_index[0])

            ent_embed_new = nn.Embedding(neigh_h.size(0), neigh_h.size(1)).to(self.args.device).double()
            nn.init.xavier_normal_(ent_embed_new.weight, gain=1.414)
            ent_embed_new = ent_embed_new.weight

            neigh_t_factor = neigh_t.view(-1, self.k_factor, self.emb_s)
            ori_neigh_h_factor = neigh_h.view(-1, self.k_factor, self.emb_s)

            tmp = torch.index_select(r_att, 0, edge_type)  # r_att[edge_type, :]
            att = self.softmax(tmp)
            # choose top n
            sorted_att, sorted_indices_in = torch.sort(att, dim=-1, descending=True)
            top_indices_in = sorted_indices_in[:, :self.top_n]
            # 获取除了top_n之外的其他索引
            remaining_indices_in = sorted_indices_in[:, self.top_n:]

            neigh_t_factor = neigh_t_factor.gather(1, top_indices_in.unsqueeze(-1).expand(-1, self.top_n, self.emb_s))
            neigh_h_factor = ori_neigh_h_factor.gather(1,
                                                       top_indices_in.unsqueeze(-1).expand(-1, self.top_n, self.emb_s))
            neigh_h_remain = ori_neigh_h_factor.gather(1, remaining_indices_in.unsqueeze(-1).expand(-1,
                                                                                                    self.k_factor - self.top_n,
                                                                                                    self.emb_s))

            neigh_t_factor = neigh_t_factor.view(-1, self.top_n * self.emb_s)
            neigh_h_factor = neigh_h_factor.view(-1, self.top_n * self.emb_s)

            # 结果是一个张量 ent_embed，它包含了图中每个实体基于其邻居节点和关系的平均嵌入。
            tmp_ent_embed = neigh_h_factor + neigh_r
            tmp_ent_embed = tmp_ent_embed.view(-1, self.top_n, self.emb_s)
            ent_embed_new = ent_embed_new.view(-1, self.k_factor, self.emb_s)
            ent_embed_new = ent_embed_new.scatter(1, top_indices_in.unsqueeze(-1).expand(-1, self.top_n, self.emb_s),
                                          tmp_ent_embed)
            ent_embed_new = ent_embed_new.scatter(1, remaining_indices_in.unsqueeze(-1).expand(-1, self.k_factor - self.top_n,
                                                                                       self.emb_s),
                                          neigh_h_remain)
            ent_embed_new = ent_embed_new.view(-1, self.k_factor * self.emb_s)

            ent_embed_new = scatter_mean(src=ent_embed_new, dim=0, index=edge_index[1], dim_size=num_ent)

            '''calculate entity embeddings'''
            # ent_embed_new = scatter_add(src=neigh_h + neigh_r, dim=0, index=edge_index[1], dim_size=num_ent)
            ent_embed_old = old_entity_weight.unsqueeze(1) * old_x
            ent_embed = ent_embed_old + ent_embed_new # 直接相加，去结合
            ent_involving_num = old_entity_weight + scatter_add(src=torch.ones(edge_index.size(1)), index=edge_index[1], dim_size = num_ent)
            ent_embed = ent_embed/ent_involving_num
            # ent_embed = torch.relu(ent_embed)
            ent_embed = self.activate_function(ent_embed)
            # 其实就是计算新的，计算旧的，然后加权更新

            '''calculate relation embeddings'''
            rel_embed_new = scatter_add(src=neigh_t_factor - neigh_h_factor, dim=0, index=edge_index[1], dim_size=num_rel)
            rel_embed_old = old_relation_weight.unsqueeze(1) * old_r
            rel_embed = rel_embed_old + rel_embed_new
            rel_involving_num = old_relation_weight + scatter_add(src=torch.ones(edge_type.size(0)), index=edge_type,
                                                                dim_size=num_rel)
            rel_embed = rel_embed / rel_involving_num
            # 同理对于attention也是一样的
            r_att_old = old_relation_attention_weight.unsqueeze(1) * old_r_att
            r_att = r_att + r_att_old
            rel_involving_num = old_relation_attention_weight + scatter_add(src=torch.ones(edge_type.size(0)), index=edge_type,
                                                                  dim_size=num_rel)
            r_att = r_att / rel_involving_num

            return ent_embed, rel_embed[:-1], r_att[:-1]

    def add_loop_edge(self, edge_index, edge_type, num_ent, num_rel):
        '''add self-loop edge for entities'''
        u, v = torch.arange(0, num_ent).unsqueeze(0).to(self.args.device), torch.arange(0, num_ent).unsqueeze(0).to(self.args.device)
        r = torch.zeros(num_ent).to(self.args.device).long()
        loop_edge = torch.cat([u, v], dim=0) # 第一部获得所有的节点编号，然后直接复制做自环
        edge_index = torch.cat([edge_index, loop_edge], dim=-1)
        edge_type = torch.cat([edge_type, r+num_rel], dim=-1)
        return edge_index, edge_type




