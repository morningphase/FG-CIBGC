#!/bin/bash
source /root/miniconda3/etc/profile.d/conda.sh
# 算法数组
algorithms=("CWR" "EWC" "finetune" "LAN" "LKGE" "MEAN" "PNN" "retraining" "SI" "Snapshot")

# 数据集数组
datasets=("Apache")

# 聚类数组
classifications=("incdbscan" "DenStream" "minibathkm")

# 设置输出目录
output_dir="results"

# 创建输出目录
mkdir -p $output_dir

# 循环遍历数据集
for dataset in "${datasets[@]}"; do
    cd Parse
    python3 hlogs_parse.py -datasetname=$dataset
    cd ../Embedding
    python3 test_score.py --dataset=$dataset
    # 循环遍历算法
    for algorithm in "${algorithms[@]}"; do
        echo "Dataset: $dataset Embedding: $algorithm."
        python3 run.py --dataset=$dataset --kg=$algorithm
        # 循环遍历参数
        for classification in "${classifications[@]}"; do
            cd ../Classification
            echo "Dataset: $dataset classification: $classification."
            python3 run.py --dataset=$dataset --classification=$classification
            cd ../Tools
            command="python3 evaluate.py --dataset $dataset"
            $command > "../$output_dir/$algorithm-$dataset-$classification.txt"
            echo "Experiment completed."
        done
        cd ../Embedding
    done
    cd ..
done

echo "All experiments completed."

