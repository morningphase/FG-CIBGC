#!/bin/bash
# This Grid Search Script Is For Base Model Parameters Only
source /root/miniconda3/etc/profile.d/conda.sh
# 算法数组
#algorithms=("CWR" "EWC" "finetune" "LAN" "LKGE" "EMR" "PNN" "retraining" "DLKGE")
algorithms=("DLKGE")

# 数据集数组
# datasets=("Apache" "Apache_Pgsql" "Redis" "Proftpd" "Nginx" "Vim" "ImageMagick" "ImageMagick-2016")
datasets=("Apache")

# 聚类数组
clusters=("SA")

# 池化方法
pooling=("tf-idf")

# batch size数组
bs_params=(2048)

# embedding size数组
emb_params=(240)

# learning rate 数组
lr1=0.0001
lr_params=($lr1)

# k_factor 参数
k_factor=(2 4 6 8 10 12 14 16)

# top_n 参数
top_n=(2)

# regular_weight 参数数组
rw1=0.01
rw2=0.1
rw3=1.0
regular_weight=($rw1)

# reconstruct_weight 参数数组
reconstruct_weight=($rw2)

# attention_weight 参数数组
attention_weight=($rw1)

# cluster数目
n_cluster=(5 10 20)

# eps_factor 参数数组
eps_factor=(4)

# min_pts 参数数组
min_pts=(2)

# lambd 参数数组
lambd1=0.1
lambd=($lambd1)

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
runtime_path="/root/autodl-tmp/Log_Fusion-main/runtime_table_lan_emr.txt"

# 创建输出目录
mkdir -p $output_dir

# 记录执行时间

# 循环遍历数据集
for dataset in "${datasets[@]}"; do
    echo "Dataset: $dataset"
    echo -e "\nDataset: $dataset" >> $runtime_path
    # 开始测量时间
    start=$(date +%s)
    cd Parse
    python3 hlogs_parse.py -datasetname=$dataset
    cd ../Embedding
    python3 test_score.py --dataset=$dataset
    # 结束时间
    end=$(date +%s)
    # 计算并显示脚本运行时间
    runtime=$((end-start))
    #echo -e "\nBehavior Identification Phase executed in $runtime seconds." >> $runtime_path
    echo "Behavior Identification Phase executed in $runtime seconds."
    # 循环遍历算法
    for algorithm in "${algorithms[@]}"; do
        echo "Dataset: $dataset Embedding: $algorithm."
        echo -e "\nAlgorithm: $algorithm" >> $runtime_path
        echo "Algorithm: $algorithm"
        for lr in "${lr_params[@]}"; do
            for bs in "${bs_params[@]}"; do
              for emd_dim in "${emb_params[@]}"; do
                echo "Begin" > "../$output_dir/$algorithm-$dataset-$lr-$emd_dim-$bs-SA-kfactor.txt"
                for k_factor in "${k_factor[@]}"; do
                  for top_n in "${top_n[@]}"; do
                    cd ../Embedding
                    command_embeding="python3 run.py --dataset=$dataset --kg=$algorithm -learning_rate=$lr -emb_dim=$emd_dim -batch_size=$bs -k_factor=$k_factor -top_n=$top_n"
                    # 开始测量时间
                    start=$(date +%s)
                    $command_embeding > "../$output_dir/$algorithm-$dataset-$lr-$emd_dim-$bs.txt"
                    # 结束时间
                    end=$(date +%s)
                    # 计算并显示脚本运行时间
                    runtime=$((end-start))
                    #echo -e "\nLifelong Training Phase executed in $runtime seconds." >> $runtime_path
                    echo "Lifelong Training Phase executed in $runtime seconds."
                    # 循环遍历参数
                    for cluster in "${clusters[@]}"; do
                        cd ../Cluster
                        echo "Dataset: $dataset cluster: $cluster."
                        echo -e "\ncluster: $cluster" >> $runtime_path
                        if [ "$cluster" = "incdbscan" ]; then
                          for eps in "${eps_factor[@]}"; do
                            for min_p in "${min_pts[@]}"; do
                              # 开始测量时间
                              start=$(date +%s)
                              python3 run.py --dataset=$dataset --cluster=$cluster --eps_factor=$eps --min_pts=$min_p
                              # 结束时间
                              end=$(date +%s)
                              # 计算并显示脚本运行时间
                              runtime=$((end-start))
                              #echo -e "\nAttack Investigation Phase executed in $runtime seconds." >> $runtime_path
                              cd ../Tools
                              command="python3 evaluate.py --dataset $dataset"
                              $command > "../$output_dir/$algorithm-$dataset-$lr-$emd_dim-$bs-$cluster-$eps-$min_p.txt"
                              echo "Single Experiment completed."
                              cd ../Cluster
                              done
                            done
                        elif [ "$cluster" = "DenStream" ]; then
                          for eps in "${eps_factor[@]}"; do
                            for lambd_n in "${lambd[@]}"; do
                              for beta1 in "${beta[@]}"; do
                                for mu1 in "${mu[@]}"; do
                                  # 开始测量时间
                                  start=$(date +%s)
                                  python3 run.py --dataset=$dataset --cluster=$cluster --eps_factor=$eps --lambd=$lambd_n --beta=$beta1 --mu=$mu1
                                  # 结束时间
                                  end=$(date +%s)
                                  # 计算并显示脚本运行时间
                                  runtime=$((end-start))
                                  echo -e "\nAttack Investigation Phase executed in $runtime seconds." >> $runtime_path
                                  cd ../Tools
                                  command="python3 evaluate.py --dataset $dataset"
                                  $command > "../$output_dir/$algorithm-$dataset-$lr-$emd_dim-$bs-$cluster-$eps-$lambd_n-$beta1-$mu1.txt"
                                  echo "Single Experiment completed."
                                  cd ../Cluster
                                  done
                                done
                              done
                            done
                        elif [ "$cluster" = "SA" ]; then
                              for pool in "${pooling[@]}"; do
                                # 开始测量时间
                                start=$(date +%s)
                                python3 run.py --dataset=$dataset --cluster=$cluster --pooling=$pool
                                # 结束时间
                                end=$(date +%s)
                                # 计算并显示脚本运行时间
                                runtime=$((end-start))
                                #echo -e "\nAttack Investigation Phase executed in $runtime seconds." >> $runtime_path
                                echo "Attack Investigation Phase executed in $runtime seconds."
                    echo "Compute time completed"
                                cd ../Tools
                                command="python3 evaluate.py --dataset $dataset"
                                echo -e "Dataset: $dataset Embedding: $algorithm." >> "../$output_dir/$algorithm-$dataset-$lr-$emd_dim-$bs-$cluster-kfactor.txt"
                                echo -e "k_factor: $k_factor\ntop_n: $top_n" >> "../$output_dir/$algorithm-$dataset-$lr-$emd_dim-$bs-$cluster-kfactor.txt"
                                $command >> "../$output_dir/$algorithm-$dataset-$lr-$emd_dim-$bs-$cluster-kfactor.txt"
                                echo "Single Experiment completed."
                                cd ../Cluster
                                done
                        elif [ "$cluster" = "minibathkm" ]; then
                          for n_c in "${n_cluster[@]}"; do
                            python3 run.py --dataset=$dataset --cluster=$cluster --n_cluster=$n_c
                            cd ../Tools
                            command="python3 evaluate.py --dataset $dataset"
                            $command > "../$output_dir/$algorithm-$dataset-$lr-$emd_dim-$bs-$cluster-$n_c.txt"
                            echo "Single Experiment completed."
                            cd ../Cluster
                            done
                        fi
                    done
                  done
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
