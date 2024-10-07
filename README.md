# FG-CIBGC

## Breif Overview

> Attacks on multimedia services

## Python environment setup with Conda

Our code is written in Python3.10.8 with cuda 12.1 and pytorch 2.1.0 on Ubuntu 22.04.

install anaconda：https://repo.anaconda.com/archive/index.html.

install torch-scatter 2.1.2+pt21cu121：https://pytorch-geometric.com/whl/torch-2.1.2%2Bcu121.html.

```
conda create --name LBAS
conda activate LBAS
pip install -r requirments.txt
```

## Dataset

Our full dataset's compressed file size is around 2.3GB. Due to space constraints, we are only providing a sample dataset (Apache)  here.

Here is the description of datasets:

| Scenarios | Vulnerability  | Description                                                  |
| --------- | -------------- | ------------------------------------------------------------ |
| Apache    | CVE-2021-41773 | Vulnerability allows attackers to gain control of the server and access sensitive files. |
| IM-1      | CVE-2016–3714  | The vulnerability exists because of the insufficient filtering for the file names passed to a system() call. |
| Vim       | CVE-2019-12735 | Vulnerability allows remote attackers to execute arbitrary OS commands via the :source! command |
| Redis     | CVE-2022-0543  | Vulnerability allows remote attackers to <br/> escape the sandbox to execute arbitrary commands. |
| Pgsql     | CVE-2019-9193  | Vulnerability allows specific users to execute arbitrary code within the PostgreSQL environment. |
| ProFTPd   | CVE-2019-12815 | There is a vulnerability in ProFTPD <= 1.3.6 that allows arbitrary file copying. |
| IM-2      | CVE-2022-44268 | Vulnerability leads to the reading of arbitrary files on the current operating system when converting images. |
| Nginx     | Path Traversal | Forgetting to include a trailing slash can result in a directory traversal vulnerability. |





## Directory

We present a brief introduction about the directories.

- Cluster/    # Clustering code
- Data/    # The directory for storing data and intermediate results of the algorithm.
- Embedding/    # Embedding code.
- Parse/    # Data parsing and graph construction code.
- Tools/    # Utility functions.
- README.md # Guide to the project
- ablation_study.sh  # Script for Ablation Study
- basemode_grid_search.sh  # Script for grid search
- bash.sh * # Script for simply running the project 
- image.png #An overview image of LBAS
- main_table_kfactor.sh  # Script for running hyper-parameter sensitivity in terms of changing K
- main_table_topn.sh  # Script for running hyper-parameter sensitivity in terms of changing n
- requirements.txt # Dependencies installed py pip install

## Workflow

In this section, we introduce the workflow of the overall project.

#### Parse

The "hlogs_parse.py" file in this directory serves as the entry point for all log preprocessing and parsing.
This part is responsible for parsing audit logs, application logs, and traffic logs, and it generates associated JSON files
for subsequent correlation with high-level behavior patterns and audit logs. See the following command :

```
cd Parse
python hlogs_parse.py ---datasetname=$dataset
```

#### Embedding

The code in this directory accomplishes two main tasks. Firstly, "run.py" correlates high-level
behavior patterns with audit logs, ultimately generating fine-grained behavior graphs. Secondly, "run.py" executes
lifelong knowledge graph embedding. See the following command :

```
cd Embedding
python run.py --dataset=$dataset --kg=$algorithm
```

#### Cluster 

The code in this directory aims to produce clustering results. First, execute the pooling algorithm
to generate embeddings for each behavior graph, then perform incremental clustering algorithm. See the following
command :

```
cd Cluster
python run.py --dataset=$dataset --cluster=$cluster
```

#### Evaluate

The code in this directory produces evaluation results. See the following command :

```
cd Tools
python3 evaluate.py --dataset $dataset > output.txt
```

## Reproducibility

We report the results of all models in runs with 20 random seeds to minimize the impact of random noise

Use `bash.sh` to reproduce the results of performance comparison.

```
bash bash.sh
```

Use `basemode_grid_search.sh` to  reproduce the results of grid search.

```
bash basemode_grid_search.sh
```

Use `ablation_study.sh` to reproduce the results of ablation study.

```
bash ablation_study.sh
```

Use `main_table_kfactor.sh` and `main_table_topn.sh` to reproduce the results of hyper-parameter sensitivity.

```
bash main_table_kfactor.sh
bash main_table_topn.sh
```

