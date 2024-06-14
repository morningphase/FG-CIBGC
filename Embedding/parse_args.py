import argparse
parser = argparse.ArgumentParser(description='Parser For Arguments',
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)

# training control
parser.add_argument('-snapshot_num', dest='snapshot_num', default=5, help='The snapshot number of the dataset')
parser.add_argument('-gpu', dest='gpu', default=0)
parser.add_argument('-loss_name', dest='loss_name', default='Margin', help='Margin: pairwise margin loss')
parser.add_argument('-train_new', dest='train_new', default=True, help='True: Training on new facts; False: Training on all seen facts')
parser.add_argument('-skip_previous', dest='skip_previous', default='False', help='Allow re-training and snapshot_only models skip previous training')

# model setting
# model name: Snapshot, retraining, finetune, MEAN, LAN, PNN, CWR, SI, EWC, EMR, GEM, LKGE
parser.add_argument('-optimizer_name', dest='optimizer_name', default='Adam')
parser.add_argument('-embedding_model', dest='embedding_model', default='TransE')
parser.add_argument('-epoch_num', dest='epoch_num', default=200, help='max epoch num')
parser.add_argument('-margin', dest='margin', default=8.0, help='The margin of MarginLoss')
parser.add_argument('-batch_size', dest='batch_size', default=2048, type=int, help='Mini-batch size')
parser.add_argument('-learning_rate', dest='learning_rate', type=float, default=0.0001)
parser.add_argument('-emb_dim', dest='emb_dim', default=240, type=int, help='embedding dimension')
parser.add_argument('-l2', dest='l2', default=0.0, type=float, help='optimizer l2')
parser.add_argument('-neg_ratio', dest='neg_ratio', default=10, type=int, help='the ratio of negative/positive facts')
parser.add_argument('-patience', dest='patience', default=4, type=int, help='early stop step')
parser.add_argument('-regular_weight', dest='regular_weight', default=0.01, type=float, help='Regularization strength: alpha')
parser.add_argument('-reconstruct_weight', dest='reconstruct_weight', default=0.1, type=float, help='The weight of MAE loss: beta')
parser.add_argument('-atten_weight', dest='atten_weight', default=0.01, type=float, help='The weight of Attention loss')
parser.add_argument('-k_factor', dest='k_factor', default=6, type=int, help='The number of K factor')
parser.add_argument('-top_n', dest='top_n', default=4, type=int, help='The number of N component')


# ablation study
parser.add_argument('-using_regular_loss', dest='using_regular_loss', default='True')
parser.add_argument('-using_reconstruct_loss', dest='using_reconstruct_loss', default='True')
parser.add_argument('-using_embedding_transfer', dest='using_embedding_transfer', default='True')
parser.add_argument('-using_finetune', dest='using_finetune', default='True')
parser.add_argument('-using_att_norm_loss', dest='using_att_norm_loss', default='True')

# others
parser.add_argument('-save_path', dest='save_path', default='./LKGE/checkpoint/')
parser.add_argument('-data_path', dest='data_path', default='../Data/')
parser.add_argument('-log_path', dest='log_path', default='./LKGE/logs/')
parser.add_argument('-num_layer', dest='num_layer', default=1, help='MAE layer')
parser.add_argument('-num_workers', dest='num_workers', default=1)
parser.add_argument('-valid_metrics', dest='valid_metrics', default='mrr')
parser.add_argument('-valid', dest='valid', default=True, help='indicator of test or valid')
parser.add_argument('-note', dest='note', default='', help='The note of log file name')
parser.add_argument('-seed', dest='seed', default=55, help='random seed, 11 22 33 44 55 for our experiments')
parser.add_argument('-memory', dest='memory', default=100, type=int, help='The number of memory')


parser.add_argument(
    "--label",
    type=str,
    default='audit',
    help="Choose neo4j graph label",
)
parser.add_argument(
    "--dataset",
    type=str,
    default='ImageMagick-2016',
    help="Choose dataset name",
)
parser.add_argument(
    "--setting",
    type=str,
    default='pickle',
    help="Choose dataset name",
)
parser.add_argument(
    "--kg",
    type=str,
    default='DLKGE',
    help="Choose Knowledge Graph name",
)
parser.add_argument(
    "--embedding",
    type=str,
    default='LKGE',
    help="Choose Knowledge Graph Tool Set",
)
args = parser.parse_args()