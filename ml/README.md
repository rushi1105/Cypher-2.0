# ML workspace

Reproducible training and evaluation for Cypher using **CIC-IDS2017**.

## Pipeline

```text
scripts/download_cicids2017.py   download the 8 daily CSVs
ml/audit_dataset.py              inspect columns, labels, duplicates, missing values
ml/prepare_dataset.py            map labels, build 24 flow features, deduplicate, split
ml/train.py                      train binary RF, multi-class RF, IsolationForest, evaluate
ml/evaluate.py                   report multiple operating points
```

Run:

```powershell
.\.venv\Scripts\python.exe scripts\download_cicids2017.py
.\.venv\Scripts\python.exe ml\audit_dataset.py
.\.venv\Scripts\python.exe ml\prepare_dataset.py
.\.venv\Scripts\python.exe ml\train.py
.\.venv\Scripts\python.exe ml\evaluate.py
```

## Actual results

Binary Random Forest on the held-out test split:

| Operating point | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|
| Validation-selected 0.81 | 0.9992 | 0.8529 | 0.9202 | 0.0001 |
| **Deployment 0.50** | **0.9903** | **0.8963** | **0.9410** | **0.0019** |
| High-recall 0.02 | 0.8168 | 0.9516 | 0.8791 | 0.0455 |

- Test ROC-AUC: 0.9922
- Test PR-AUC: 0.9797

Isolation Forest:

- Test ROC-AUC: 0.8416
- Attack detection rate: 14.02%
- Normal false-positive rate: 1.42%

The anomaly detector is weaker than the supervised model and is not sufficient on its own.

## Current gap

The new models use **24 flow features**, while the server still uses the old **11 packet-window features**. The models are therefore **not yet wired into serving**. The next step is a flow-level feature extractor in the server with exact parity to `ml/features.py`, followed by end-to-end tests and model replacement.

## Rules

- Do not commit raw CIC-IDS2017 data; it is ignored under `data/raw/`.
- Do not claim self-captured training data until a real local capture is added.
- Do not publish a recall/F1 number without the threshold, split, and FPR.
- Read `ml/reports/model_card.md` before using the models in a demo.
