def config(args):
    '''
    Hyperparameters for all models and datasets.
    '''

    '''base model'''
    args.learning_rate = args.learning_rate
    args.emb_dim = args.emb_dim
    args.batch_size = args.batch_size

    '''other parameters'''
    if args.dataset == 'ENTITY':
        if args.kg == 'EWC':
            args.regular_weight = 0.1
        elif args.kg == 'SI':
            args.regular_weight = 0.01
        elif args.kg == 'LKGE':
            args.regular_weight = 0.01
            args.reconstruct_weight = 0.1
    elif args.dataset == 'RELATION':
        if args.kg == 'EWC':
            args.regular_weight = 0.1
        elif args.kg == 'SI':
            args.regular_weight = 1.0
        elif args.kg == 'LKGE':
            args.regular_weight = 0.01
            args.reconstruct_weight = 0.1
    elif args.dataset == 'FACT':
        if args.kg == 'EWC':
            args.regular_weight = 0.01
        elif args.kg == 'SI':
            args.regular_weight = 0.01
        elif args.kg == 'LKGE':
            args.regular_weight = 0.01
            args.reconstruct_weight = 1.0
    elif args.dataset == 'HYBRID':
        if args.kg == 'EWC':
            args.regular_weight = 0.01
        elif args.kg == 'SI':
            args.regular_weight = 0.01
        elif args.kg == 'LKGE':
            args.regular_weight = 0.01
            args.reconstruct_weight = 0.1
    else:
        pass
        # if args.kg == 'EWC':
        #     args.regular_weight = 0.01
        # elif args.kg == 'SI':
        #     args.regular_weight = 0.01
        # elif args.kg == 'LKGE':
        #     args.regular_weight = 0.01
        #     args.reconstruct_weight = 0.1
        # elif args.kg == 'DLKGE':
        #     args.regular_weight = 0.01
        #     args.reconstruct_weight = 0.1
        #     args.k_factor = 6 # 需要检查我们的算法对于维度的可扩展性
        #     args.top_n = 4
        #     args.atten_weight = 0.01
        #     args.emb_dim = 96 # 96 /6 *4 = 64，因而理论上来讲这个算法应该具备稳定性





