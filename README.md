# FG-CIBGC

## Breif Overview

> Learning-based Behavior Graph Classification (BGC) has been widely adopted in Internet infrastructure for partitioning and identifying similar behavior graphs. However, the research communities realize significant limitations when deploying existing proposals in real-world scenarios.  The challenges are mainly concerned with (\romannumeral1) fine-grained emerging behavior graphs, and (\romannumeral2) incremental model adaptations. To tackle these problems, we propose to (\romannumeral1) mine semantics in multi-source logs using Large Language Models (LLMs) under In-Context Learning (ICL), and (\romannumeral2) bridge the gap between Out-Of-Distribution (OOD) detection and class-incremental graph learning. Based on the above core ideas, we develop the first unified framework termed as \textbf{F}ine-\textbf{G}rained and \textbf{C}lass-\textbf{I}ncremental \textbf{B}ehavior \textbf{G}raph \textbf{C}lassification (\textbf{FG-CIBGC}). It consists of two novel modules, i.e., gPartition and gAdapt, that are used for partitioning fine-grained graphs and performing unknown class detection and adaptation, respectively. To validate the efficacy of FG-CIBGC, we introduce a new benchmark, comprising a new 4,992-graph, 32-class dataset generated from 8 attack scenarios, as well as a novel Edge Intersection over Union (EIoU) metric for evaluation. Extensive experiments demonstrate FG-CIBGC's superior performance on fine-grained and class-incremental BGC tasks, as well as its ability to generate fine-grained behavior graphs that facilitate downstream tasks. The code and dataset are available at: https://anonymous.4open.science/r/FG-CIBGC-4D62/README.md.

## Python environment setup with Conda

Our code is written in Python3.10.8 with cuda 12.1 and pytorch 2.1.0 on Ubuntu 22.04.

install anaconda：https://repo.anaconda.com/archive/index.html.

install torch-scatter 2.1.2+pt21cu121：https://pytorch-geometric.com/whl/torch-2.1.2%2Bcu121.html.

```
conda create --name FG-CIBGC
conda activate FG-CIBGC
pip install openai
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
behavior units with audit logs, ultimately generating fine-grained behavior graphs. Secondly, "run.py" executes
graph embedding. See the following command :

```
cd Embedding
python run.py --dataset=$dataset --kg=$algorithm
```

#### Classification 

The code in this directory aims to produce classification results. First, execute the pooling algorithm
to generate embeddings for each behavior graph, then perform classification algorithm. See the following
command :

```
cd Classification 
python run.py --dataset=$dataset --classification=$classification
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


