"""Report operating points for the trained binary CIC-IDS2017 model."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.features import FEATURE_NAMES  # noqa: E402

PROCESSED_DIR = ROOT / "data" / "processed" / "cicids2017"
REPORT_DIR = ROOT / "ml" / "reports"
MODEL_PATH = ROOT / "ml" / "artifacts" / "binary_threat_classifier.joblib"

THRESHOLDS = [0.02, 0.05, 0.50, 0.81]


def metrics_at(y_true: np.ndarray, probabilities: np.ndarray, threshold: float) -> dict:
    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    return {
        "threshold": threshold,
        "accuracy": round(float(accuracy_score(y_true, predictions)), 4),
        "precision": round(float(precision_score(y_true, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, predictions, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, predictions, zero_division=0)), 4),
        "fpr": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "roc_auc": round(float(roc_auc_score(y_true, probabilities)), 4),
        "pr_auc": round(float(average_precision_score(y_true, probabilities)), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def main() -> int:
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    test = pd.read_parquet(PROCESSED_DIR / "test.parquet")
    y_true = (test["label"] != "Normal").astype(int).to_numpy()
    probabilities = model.predict_proba(test[FEATURE_NAMES].to_numpy(dtype=np.float32))[:, 1]

    points = {f"{threshold:.2f}": metrics_at(y_true, probabilities, threshold)
              for threshold in THRESHOLDS}
    (REPORT_DIR / "operating_points.json").write_text(json.dumps(points, indent=2), encoding="utf-8")

    lines = [
        "# Binary model operating points",
        "",
        "Test split: CIC-IDS2017, chronological within label and day, 362,378 rows.",
        "",
        "| Threshold | Precision | Recall | F1 | FPR |",
        "|---:|---:|---:|---:|---:|",
    ]
    for threshold, metrics in points.items():
        lines.append(
            f"| {threshold} | {metrics['precision']:.4f} | {metrics['recall']:.4f} "
            f"| {metrics['f1']:.4f} | {metrics['fpr']:.4f} |"
        )
    lines.extend([
        "",
        "## Interpretation",
        "",
        "- `0.50` is the default operating point: strongest balanced F1 with a very low false-positive rate.",
        "- `0.02` is a high-recall operating point: catches more attacks but sends far more false positives.",
        "- `0.81` is the validation-F1 optimum with an extremely low false-positive rate, but its test recall is lower.",
        "",
        "Do not advertise a single recall/F1 pair without naming the threshold, split, and false-positive rate.",
    ])
    (REPORT_DIR / "evaluation_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(points, indent=2))
    print(f"\nWrote {REPORT_DIR / 'operating_points.json'}")
    print(f"Wrote {REPORT_DIR / 'evaluation_summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
