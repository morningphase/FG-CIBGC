切图流程：
输入json，运行test_score.py作为入口。test_score.py是核心的切图文件
    a. 首先调用getSubgraphs函数，用于读取json文件，把高层日志图分图结果和所有的高层日志取出来；
    b. 接着调用subgraph_divided函数，这个函数用于记录应用日志的等价性，即不考虑时间，这些子图可以被分为几类；
    c. 接下来调用auditd_log2default，把审计日志做一个解析，生成auditlist
    d. 调用save_all_graph函数，把审计日志进行构图。这里的构图仅保留
    e. 调用test_divided_log函数，这个函数是过渡时期的产物，主要是告知数据集有多少能表示时间开始的系统调用
    f. 调用evaluate_score函数，核心目的是做评分，然后把图切出来生成graph_list
    g. 调用manual_verify函数，这个是便于我debug会输出一些乱七八糟的过程文件
