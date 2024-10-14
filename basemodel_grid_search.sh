#!/bin/bash
# This Grid Search Script Is For Base Model Parameters Only
source /root/miniconda3/etc/profile.d/conda.sh
# 算法数组
algorithms=("CWR" "EWC" "finetune" "LAN" "EMR" "LKGE" "MEAN" "PNN" "retraining" "SI" "Snapshot" "DLKGE")


# 数据集数组
datasets=("Apache")

# 聚类数组
classifications=("incdbscan" "DenStream" "minibathkm" "SA")


# batch size数组
bs_params=(1024 2048)

# embedding size数组
emb_params=(120 240)

# learning rate 数组
lr1=0.0001
lr2=0.0005
lr_params=($lr1 $lr2)

# k_factor 参数
k_factor=(2 4 6 8 12)

# top_n 参数
top_n=(2 4 6)

# regular_weight 参数数组
rw1=0.01
rw2=0.1
rw3=1.0
regular_weight=($rw1 $rw2 $rw3)

# reconstruct_weight 参数数组
reconstruct_weight=($rw1 $rw2 $rw3)

# attention_weight 参数数组
attention_weight=($rw1 $rw2 $rw3)

# classification数目
n_classification=(5 10 20)

# eps_factor 参数数组
eps_factor=(1 2 4)

# min_pts 参数数组
min_pts=(2 4)

# lambd 参数数组
lambd1=0.1
lambd2=0.2
lambd=($lambd1 $lambd2)

# beta 参数数组
beta1=0.6
beta2=5
beta=($beta1 $beta2)

# mu 参数数组
mu1=2
mu2=10
mu=($mu1 $mu2)


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
                for classification in "${classifications[@]}"; do
                    cd ../Classification
                    echo "Dataset: $dataset classification: $classification."
                    if [ "$classification" = "incdbscan" ]; then
                      for eps in "${eps_factor[@]}"; do
                        for min_p in "${min_pts[@]}"; do
                          python3 run.py --dataset=$dataset --classification=$classification --eps_factor=$eps --min_pts=$min_p
                          cd ../Tools
                          command="python3 evaluate.py --dataset $dataset"
                          $command > "../$output_dir/$algorithm-$dataset-$lr-$emd_dim-$bs-$classification-$eps-$min_p.txt"
                          echo "Single Experiment completed."
                          cd ../Classification
                          done
                        done
                    elif [ "$classification" = "DenStream" ]; then
                      for eps in "${eps_factor[@]}"; do
                        for lambd_n in "${lambd[@]}"; do
                          for beta1 in "${beta[@]}"; do
                            for mu1 in "${mu[@]}"; do
                              python3 run.py --dataset=$dataset --classification=$classification --eps_factor=$eps --lambd=$lambd_n --beta=$beta1 --mu=$mu1
                              cd ../Tools
                              command="python3 evaluate.py --dataset $dataset"
                              $command > "../$output_dir/$algorithm-$dataset-$lr-$emd_dim-$bs-$classification-$eps-$lambd_n-$beta1-$mu1.txt"
                              echo "Single Experiment completed."
                              cd ../Classification
                              done
                            done
                          done
                        done
                    elif [ "$classification" = "minibathkm" ]; then
                      for n_c in "${n_classification[@]}"; do
                        python3 run.py --dataset=$dataset --classification=$classification --n_classification=$n_c
                        cd ../Tools
                        command="python3 evaluate.py --dataset $dataset"
                        $command > "../$output_dir/$algorithm-$dataset-$lr-$emd_dim-$bs-$classification-$n_c.txt"
                        echo "Single Experiment completed."
                        cd ../Classification
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
