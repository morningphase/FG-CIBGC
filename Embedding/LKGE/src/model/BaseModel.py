import torch

from Embedding.utils import *


class BaseModel(nn.Module):
    def __init__(self, args, kg):
        super(BaseModel, self).__init__()
        self.args = args
        self.kg = kg  # information of snapshot sequence, self.kg.snapshots[i] is the i-th snapshot
        '''initialize the entity and relation embeddings for the first snapshot'''
        if self.args.kg != 'DLKGE':
            self.ent_embeddings = nn.Embedding(self.kg.snapshots[0].num_ent, self.args.emb_dim).to(self.args.device).double()
            self.rel_embeddings = nn.Embedding(self.kg.snapshots[0].num_rel, self.args.emb_dim).to(self.args.device).double()
        else:
            self.ent_embeddings = nn.Embedding(self.kg.snapshots[0].num_ent, self.args.emb_dim).to(self.args.device).double()
            self.rel_embeddings = nn.Embedding(self.kg.snapshots[0].num_rel, (int(self.args.emb_dim / self.args.k_factor) * self.args.top_n)).to(self.args.device).double()

        xavier_normal_(self.ent_embeddings.weight, gain=1.414)
        xavier_normal_(self.rel_embeddings.weight, gain=1.414)

        if self.args.kg == 'DLKGE':
            self.k_factor = args.k_factor
            self.top_n = args.top_n
            self.emb_s = int(self.args.emb_dim / self.k_factor)
            self.rel_attentions = nn.Embedding(self.kg.snapshots[0].num_rel, self.k_factor).to(self.args.device).double()
            # self.rel_attentions = nn.Parameter(torch.Tensor(self.kg.snapshots[0].num_rel, self.k_factor)).to(self.args.device).double()  # 每条边K个attention
            xavier_normal_(self.rel_attentions.weight, gain=1.414)


        '''loss function'''
        self.margin_loss_func = nn.MarginRankingLoss(margin=float(self.args.margin), reduction="sum")#.to(self.args.device)  #
        self.softmax = torch.nn.Softmax(dim=1)  # 处理注意力权重


    def reinit_param(self):
        '''
        Re-initialize all model parameters
        '''
        for n, p in self.named_parameters():
            if p.requires_grad:
                xavier_normal_(p, gain=1.414)

    def expand_embedding_size(self, k=None):
        '''
        Initialize entity and relation embeddings for next snapshot
        '''
        # 初始化下一个快照的实体和关系
        ent_embeddings = nn.Embedding(self.kg.snapshots[self.args.snapshot + 1].num_ent, self.args.emb_dim).to(
            self.args.device).double()
        if self.args.kg == 'DLKGE':
            rel_embeddings = nn.Embedding(self.kg.snapshots[self.args.snapshot + 1].num_rel,  (int(self.args.emb_dim / self.args.k_factor) * self.args.top_n)).to(
            self.args.device).double()
        else:
            rel_embeddings = nn.Embedding(self.kg.snapshots[self.args.snapshot + 1].num_rel, self.args.emb_dim).to(self.args.device).double()
        xavier_normal_(ent_embeddings.weight, gain=1.414)
        xavier_normal_(rel_embeddings.weight, gain=1.414)
        if args.kg == 'DLKGE':
            rel_attentions = nn.Embedding(self.kg.snapshots[self.args.snapshot + 1].num_rel, k).to(self.args.device).double() # 每条边K个attention
            xavier_normal_(rel_attentions.weight, gain=1.414)
            return deepcopy(ent_embeddings), deepcopy(rel_embeddings), deepcopy(rel_attentions)
        else:
            return deepcopy(ent_embeddings), deepcopy(rel_embeddings)

    def switch_snapshot(self):
        '''
        After the training process of a snapshot, prepare for next snapshot
        '''
        pass

    def pre_snapshot(self):
        '''
        Preprocess before training on a snapshot
        '''
        pass

    def epoch_post_processing(self, size=None):
        '''
        Post process after a training iteration
        '''
        pass

    def snapshot_post_processing(self):
        '''
        Post process after training on a snapshot
        '''
        pass

    def store_old_parameters(self):
        '''
        Store the learned model after training on a snapshot
        '''
        for name, param in self.named_parameters():
            name = name.replace('.', '_')
            if param.requires_grad:
                value = param.data
                self.register_buffer('old_data_{}'.format(name), value.clone().detach())

    def attentions(self):
        return self.rel_attentions.weight

    def initialize_old_data(self):
        '''
        Initialize the storage of old parameters
        '''
        for n, p in self.named_parameters():
            if p.requires_grad:
                n = n.replace('.', '_')
                self.register_buffer('old_data_{}'.format(n), p.data.clone())

    def embedding(self, stage=None):
        '''
        :param stage: Train / Valid / Test
        :return: entity and relation embeddings
        '''
        return self.ent_embeddings.weight, self.rel_embeddings.weight

    def new_loss(self, head, rel, tail=None, label=None):
        '''
        :param head: subject entity
        :param rel: relation
        :param tail: object entity
        :param label: positive or negative facts
        :return: loss of new facts
        '''
        return self.margin_loss(head, rel, tail, label)/head.size(0)



    def margin_loss(self, head, rel, tail, label=None):
        '''
        Pair Wise Margin loss: L1-norm(s + r - o)
        :param head:
        :param rel:
        :param tail:
        :param label:
        :return:
        '''
        ent_embeddings, rel_embeddings = self.embedding('Train')

        s = torch.index_select(ent_embeddings, 0, head)
        r = torch.index_select(rel_embeddings, 0, rel)
        o = torch.index_select(ent_embeddings, 0, tail)
        if args.kg != 'DLKGE':
            score = self.score_fun(s, r, o)
            p_score, n_score = self.split_pn_score(score, label)
            y = torch.Tensor([-1]).to(self.args.device)
            loss = self.margin_loss_func(p_score, n_score, y)
            return loss
        else:
            sub_factor = s.view(-1, self.k_factor, self.emb_s)
            obj_factor = o.view(-1, self.k_factor, self.emb_s)
            rel_attentions = self.attentions()
            tmp = rel_attentions[rel, :]
            att = self.softmax(tmp)
            # choose top n
            sorted_att, sorted_indices_in = torch.sort(att, dim=-1, descending=True)
            top_indices_in = sorted_indices_in[:, :self.top_n]
            top_att = sorted_att[:, :self.top_n]

            sub_factor = sub_factor.gather(1, top_indices_in.unsqueeze(-1).expand(-1, self.top_n, self.emb_s))
            obj_factor = obj_factor.gather(1, top_indices_in.unsqueeze(-1).expand(-1, self.top_n, self.emb_s))

            s = sub_factor.view(-1, self.top_n * self.emb_s)
            o = obj_factor.view(-1, self.top_n * self.emb_s)

            score = self.score_fun(s, r, o)
            p_score, n_score = self.split_pn_score(score, label)
            y = torch.Tensor([-1]).to(self.args.device)
            loss = self.margin_loss_func(p_score, n_score, y)
            return loss, top_att

    def split_pn_score(self, score, label):
        '''
        Get the scores of positive and negative facts
        :param score: scores of all facts
        :param label: positive facts: 1, negative facts: -1
        :return:
        '''
        p_score = score[torch.where(label>0)]
        n_score = (score[torch.where(label<0)]).reshape(-1, self.args.neg_ratio).mean(dim=1)
        return p_score, n_score

    def score_fun(self, s, r, o):
        '''
        score function f(s, r, o) = L1-norm(s + r - o)
        :param h:
        :param r:
        :param t:
        :return:
        '''
        s = self.norm_ent(s)
        r = self.norm_rel(r)
        o = self.norm_ent(o)
        return torch.norm(s + r - o, 1, -1)

    def predict(self, sub, rel, stage='Valid'):
        '''
        Scores all candidate facts for evaluation
        :param head: subject entity id
        :param rel: relation id
        :param stage: object entity id
        :return: scores of all candidate facts
        '''

        '''get entity and relation embeddings'''
        if stage != 'Test':
            num_ent = self.kg.snapshots[self.args.snapshot].num_ent
        else:
            num_ent = self.kg.snapshots[self.args.snapshot_test].num_ent
        if self.args.kg != 'DLKGE':
            ent_embeddings, rel_embeddings = self.embedding(stage)
            s = torch.index_select(ent_embeddings, 0, sub)
            r = torch.index_select(rel_embeddings, 0, rel)
            o_all = ent_embeddings[:num_ent]
            s = self.norm_ent(s)
            r = self.norm_rel(r)
            o_all = self.norm_ent(o_all)

            '''s + r - o'''
            pred_o = s + r
            score = 9.0 - torch.norm(pred_o.unsqueeze(1) - o_all, p=1, dim=2)
            score = torch.sigmoid(score)

            return score
        else:
            ent_embeddings, rel_embeddings = self.embedding(stage)
            rel_attentions = self.attentions()
            s = torch.index_select(ent_embeddings, 0, sub)
            r = torch.index_select(rel_embeddings, 0, rel)
            o_all = ent_embeddings[:num_ent]
            o_all = o_all - torch.zeros([s.size(0), 1, o_all.size(1)]).to(self.args.device)

            r_att = torch.index_select(rel_attentions, 0, rel)

            sub_factor = s.view(-1, self.k_factor, self.emb_s)
            obj_factor = o_all.view(-1, o_all.size(1), self.k_factor, self.emb_s)

            r_att = self.softmax(r_att)
            # choose top n
            sorted_att, sorted_indices_in = torch.sort(r_att, dim=-1, descending=True)
            top_indices_in = sorted_indices_in[:, :self.top_n]
            # 为 obj_factor 扩展 top_indices_in
            # 注意：这里假设 num_ent 是 obj_factor 的第一维的大小
            expanded_top_indices_in = top_indices_in.unsqueeze(1).expand(-1, num_ent, -1)

            # reshaped_obj_factor = obj_factor.reshape(-1, self.emb_s)
            # 对 obj_factor 应用 gather
            selected_obj_factor = obj_factor.gather(0, expanded_top_indices_in.unsqueeze(-1).expand(-1, o_all.size(1), self.top_n, self.emb_s))
            # 将 obj_factor 重新整形回原来的形状
            obj_factor = selected_obj_factor.view(-1, num_ent, self.top_n * self.emb_s)

            sub_factor = sub_factor.gather(1, top_indices_in.unsqueeze(-1).expand(-1, self.top_n, self.emb_s))

            s = sub_factor.view(-1, self.top_n * self.emb_s)
            o = obj_factor.view(-1, o_all.size(1), self.top_n * self.emb_s)

            s = self.norm_ent(s)
            r = self.norm_rel(r)
            o = self.norm_ent(o)

            '''s + r - o'''
            pred_o = s + r
            score = 9.0 - torch.norm(pred_o.unsqueeze(1) - o, p=1, dim=2)
            score = torch.sigmoid(score)
            return score

    def norm_rel(self, r):
        return nn.functional.normalize(r, 2, -1)

    def norm_ent(self, e):
        return nn.functional.normalize(e, 2, -1)

class Rel_attention(nn.Module):
    def __init__(self, num_rel, K):
        super(Rel_attention, self).__init__()
        self.rel_attention = nn.Parameter(torch.zeros((num_rel, K))) # 每条边K个attention
        nn.init.xavier_normal_(self.rel_attention.data, gain=1.414)

    def forward(self, batch_relation):
        return self.rel_attention[batch_relation, :]