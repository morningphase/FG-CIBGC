#!/bin/bash
# This Grid Search Script Is For Base Model Parameters Only
source /root/miniconda3/etc/profile.d/conda.sh
# 算法数组
algorithms=("DLKGE" "LKGE")

# 数据集数组
datasets=("Apache")

# 聚类数组
clusters=("SA" "Denstream")

# batch size数组
bs_params=(2048)

# embedding size数组
emb_params=(240)

# 池化方法
pooling=("mean" "tf-idf")

# eps_factor 参数数组
eps_factor=(4)

# min_pts 参数数组
min_pts=(2)

# learning rate 数组
lr1=0.0001
lr_params=($lr1)

# cluster数目
n_cluster=(10)


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
        for lr in "${lr_params[@]}"; do
            for bs in "${bs_params[@]}"; do
              for emd_dim in "${emb_params[@]}"; do
                cd ../Embedding
                command_embeding="python3 run.py --dataset=$dataset --kg=$algorithm -learning_rate=$lr -emb_dim=$emd_dim -batch_size=$bs"
                $command_embeding > "../$output_dir/$algorithm-$dataset-$lr-$emd_dim-$bs.txt"
                # 循环遍历参数
                for cluster in "${clusters[@]}"; do
                    cd ../Cluster
                    echo "Dataset: $dataset cluster: $cluster."
                    if [ "$cluster" = "minibathkm" ]; then
                      for n_c in "${n_cluster[@]}"; do
                        for pool in "${pooling[@]}"; do
                          python3 run.py --dataset=$dataset --cluster=$cluster --n_cluster=$n_c --pooling=$pool
                          cd ../Tools
                          command="python3 evaluate.py --dataset $dataset"
                          $command > "../$output_dir/$algorithm-$dataset-$pool-$lr-$emd_dim-$bs-$cluster-$n_c.txt"
                          echo "Single Experiment completed."
                          cd ../Cluster
                          done
                        done
                    elif [ "$cluster" = "incdbscan" ]; then
                      for eps in "${eps_factor[@]}"; do
                        for min_p in "${min_pts[@]}"; do
                          for pool in "${pooling[@]}"; do
                            python3 run.py --dataset=$dataset --cluster=$cluster --eps_factor=$eps --min_pts=$min_p --pooling=$pool
                            cd ../Tools
                            command="python3 evaluate.py --dataset $dataset"
                            $command > "../$output_dir/$algorithm-$dataset-$pool-$lr-$emd_dim-$bs-$cluster-$eps-$min_p.txt"
                            echo "Single Experiment completed."
                            cd ../Cluster
                            done
                          done
                        done
                    elif [ "$cluster" = "SA" ]; then
                          for pool in "${pooling[@]}"; do
                            python3 run.py --dataset=$dataset --cluster=$cluster --pooling=$pool
                            cd ../Tools
                            command="python3 evaluate.py --dataset $dataset"
                            $command > "../$output_dir/$algorithm-$dataset-$pool-$lr-$emd_dim-$bs-$cluster.txt"
                            echo "Single Experiment completed."
                            cd ../Cluster
                            done
                    fi
                  done
                done
            done
          done
        rm -r "../Embedding/LKGE/checkpoint/$dataset-TransE-$algorithm-Margin"
        cd ../Embedding
    done
    cd ..
done

echo "All experiments completed."
