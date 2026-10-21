# Cypher ML model card

**Date:** 2026-10-20  
**Dataset:** CIC-IDS2017  
**Task:** binary Normal vs Attack, with an additional multi-class diagnostic model and a normal-traffic anomaly detector.

## Dataset and split

- 8 daily CSV files, 2,830,743 raw rows.
- 2,415,814 rows after global exact deduplication.
- Split: chronological 70/15/15 within each label and source file.
- Train: 1,691,065 rows. Validation: 362,371. Test: 362,378.
- Training sample for the binary model: 597,301 rows (300,000 normal + 297,301 attack).
- No timestamp column exists in the CSV. Row order within each day is the time proxy.

## Features

24 flow features shared through `ml/features.py`:

```text
duration_s, fwd_packets, bwd_packets, total_packets, fwd_bytes, bwd_bytes,
total_bytes, fwd_packet_size_mean, bwd_packet_size_mean, packet_size_mean,
packet_size_std, syn_count, ack_count, fin_count, rst_count, psh_count,
iat_mean, iat_std, flow_packets_per_sec, flow_bytes_per_sec,
down_up_ratio, syn_ratio, dst_port, is_well_known_port
```

## Binary Random Forest

| Operating point | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|
| Validation-selected 0.81 | 0.9992 | 0.8529 | 0.9202 | 0.0001 |
| **Deployment 0.50** | **0.9903** | **0.8963** | **0.9410** | **0.0019** |
| High-recall 0.02 | 0.8168 | 0.9516 | 0.8791 | 0.0455 |

- Test ROC-AUC: 0.9922
- Test PR-AUC: 0.9797
- Validation at 0.81: precision 0.9993, recall 0.9897, F1 0.9945, FPR 0.0001.

The default deployment threshold is **0.50**. It gives the strongest balanced test F1 with a 0.19% false-positive rate. The validation-selected threshold overfits the validation split and has lower test recall.

## Multi-class diagnostic model

Test classification report at the same 24-feature contract:

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| Normal | 0.98 | 0.98 | 0.98 | 298,668 |
| Scan | 0.88 | 1.00 | 0.94 | 13,623 |
| DoS/DDoS | 1.00 | 0.84 | 0.91 | 48,111 |
| Brute Force | 0.98 | 0.96 | 0.97 | 1,363 |
| Web Attack | 0.36 | 0.89 | 0.51 | 314 |
| Bot/C2 | 0.00 | 0.00 | 0.00 | 293 |
| Other | 1.00 | 0.67 | 0.80 | 6 |

Macro F1: 0.73. Weighted F1: 0.97. The Bot/C2 and rare-class results are not reliable and should not be used in the dashboard without further work.

## Isolation Forest

- Trained on 250,000 normal flows.
- Contamination: 0.05.
- Test ROC-AUC: 0.8416.
- Test PR-AUC: 0.5055.
- Attack detection rate at the default threshold: 14.02%.
- Normal false-positive rate: 1.42%.

The anomaly detector is currently much weaker than the supervised model and is not sufficient on its own.

## Artifacts

Generated under `ml/artifacts/` (ignored by Git):

- `binary_threat_classifier.joblib`
- `multiclass_attack_classifier.joblib`
- `flow_anomaly_detector.joblib`

Reports under `ml/reports/`:

- `dataset_audit.json`
- `dataset_manifest.json`
- `metrics.json`
- `operating_points.json`
- `evaluation_summary.md`
- `feature_importance.csv`
- `binary_classification_report.txt`
- `multiclass_classification_report.txt`

## Limitations

- CIC-IDS2017 is from 2017 and has known quality and labeling issues.
- Exact duplicates were removed, but near-duplicate flows may still leak across splits.
- No self-captured baseline or controlled lab attack traffic is included yet.
- The CSV has no timestamp; the split uses row order within each day.
- The multi-class model is weak on Bot/C2 and rare classes.
- **The new models are not yet wired into the server.** The server still uses the old 11-feature window model. Serving integration requires a flow-level feature extractor with exact parity to this 24-feature contract.
- Do not advertise a single recall/F1 pair without naming the threshold, split, and false-positive rate.

## Citation

Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP 2018.
