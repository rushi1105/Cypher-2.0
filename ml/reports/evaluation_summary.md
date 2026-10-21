# Binary model operating points

Test split: CIC-IDS2017, chronological within label and day, 362,378 rows.

| Threshold | Precision | Recall | F1 | FPR |
|---:|---:|---:|---:|---:|
| 0.02 | 0.8168 | 0.9516 | 0.8791 | 0.0455 |
| 0.05 | 0.8941 | 0.9289 | 0.9112 | 0.0235 |
| 0.50 | 0.9903 | 0.8963 | 0.9410 | 0.0019 |
| 0.81 | 0.9992 | 0.8529 | 0.9202 | 0.0001 |

## Interpretation

- `0.50` is the default operating point: strongest balanced F1 with a very low false-positive rate.
- `0.02` is a high-recall operating point: catches more attacks but sends far more false positives.
- `0.81` is the validation-F1 optimum with an extremely low false-positive rate, but its test recall is lower.

Do not advertise a single recall/F1 pair without naming the threshold, split, and false-positive rate.
