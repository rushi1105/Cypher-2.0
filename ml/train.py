"""Train and evaluate the CIC-IDS2017 Random Forest and Isolation Forest models."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.features import FEATURE_NAMES, LABEL_NAMES  # noqa: E402

PROCESSED_DIR = ROOT / "data" / "processed" / "cicids2017"
ARTIFACT_DIR = ROOT / "ml" / "artifacts"
REPORT_DIR = ROOT / "ml" / "reports"

RANDOM_STATE = 42
NORMAL_TRAIN_SAMPLE = 300_000
IF_NORMAL_SAMPLE = 250_000
BINARY_TREES = 300
MULTICLASS_TREES = 200
IF_TREES = 200
MIN_MULTICLASS_COUNT = 500
MAX_VALIDATION_FPR = 0.005


def binary_metrics(y_true: np.ndarray, probabilities: np.ndarray, threshold: float) -> dict:
    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    return {
        "threshold": round(float(threshold), 4),
        "accuracy": round(float(accuracy_score(y_true, predictions)), 4),
        "precision": round(float(precision_score(y_true, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, predictions, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, predictions, zero_division=0)), 4),
        "fpr": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "roc_auc": round(float(roc_auc_score(y_true, probabilities)), 4),
        "pr_auc": round(float(average_precision_score(y_true, probabilities)), 4),
        "confusion_matrix": {
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)
        },
    }


def tune_threshold(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    max_fpr: float = MAX_VALIDATION_FPR,
) -> tuple[float, list[dict]]:
    curve = []
    best_threshold = 0.5
    best_f1 = -1.0
    fallback_threshold = 0.5
    fallback_f1 = -1.0

    for threshold in np.arange(0.05, 0.96, 0.01):
        metrics = binary_metrics(y_true, probabilities, float(threshold))
        curve.append({"threshold": metrics["threshold"], "f1": metrics["f1"],
                      "precision": metrics["precision"], "recall": metrics["recall"],
                      "fpr": metrics["fpr"]})

        if metrics["f1"] > fallback_f1:
            fallback_f1 = metrics["f1"]
            fallback_threshold = float(threshold)

        if metrics["fpr"] <= max_fpr and metrics["f1"] > best_f1:
            best_f1 = metrics["f1"]
            best_threshold = float(threshold)

    if best_f1 < 0:
        return fallback_threshold, curve
    return best_threshold, curve


def main() -> int:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading splits ...")
    train = pd.read_parquet(PROCESSED_DIR / "train.parquet")
    val = pd.read_parquet(PROCESSED_DIR / "val.parquet")
    test = pd.read_parquet(PROCESSED_DIR / "test.parquet")

    normal_train = train[train["label"] == "Normal"]
    attack_train = train[train["label"] != "Normal"]
    normal_sample = normal_train.sample(
        n=min(NORMAL_TRAIN_SAMPLE, len(normal_train)), random_state=RANDOM_STATE
    )
    train_sample = pd.concat([normal_sample, attack_train], ignore_index=True)
    train_sample = train_sample.sample(frac=1.0, random_state=RANDOM_STATE).reset_index(drop=True)

    print(
        f"Training sample: {len(train_sample):,} rows "
        f"({len(normal_sample):,} normal, {len(attack_train):,} attack)"
    )

    X_train = train_sample[FEATURE_NAMES].to_numpy(dtype=np.float32)
    y_train_binary = (train_sample["label"] != "Normal").astype(int).to_numpy()
    X_val = val[FEATURE_NAMES].to_numpy(dtype=np.float32)
    y_val_binary = (val["label"] != "Normal").astype(int).to_numpy()
    X_test = test[FEATURE_NAMES].to_numpy(dtype=np.float32)
    y_test_binary = (test["label"] != "Normal").astype(int).to_numpy()

    print("Training binary Random Forest ...")
    binary_rf = RandomForestClassifier(
        n_estimators=BINARY_TREES,
        max_depth=24,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )
    binary_rf.fit(X_train, y_train_binary)

    val_probabilities = binary_rf.predict_proba(X_val)[:, 1]
    threshold, threshold_curve = tune_threshold(y_val_binary, val_probabilities)
    val_metrics = binary_metrics(y_val_binary, val_probabilities, threshold)
    test_probabilities = binary_rf.predict_proba(X_test)[:, 1]
    test_metrics = binary_metrics(y_test_binary, test_probabilities, threshold)
    test_default = binary_metrics(y_test_binary, test_probabilities, 0.5)
    test_080 = binary_metrics(y_test_binary, test_probabilities, 0.80)
    deployment_threshold = 0.5
    deployment_metrics = binary_metrics(y_test_binary, test_probabilities, deployment_threshold)

    print(f"Binary validation: {json.dumps(val_metrics)}")
    print(f"Binary test:       {json.dumps(test_metrics)}")
    print(f"Deployment point:  {json.dumps(deployment_metrics)}")

    feature_importance = pd.DataFrame(
        {"feature": FEATURE_NAMES, "importance": binary_rf.feature_importances_}
    ).sort_values("importance", ascending=False)
    feature_importance.to_csv(REPORT_DIR / "feature_importance.csv", index=False)

    joblib.dump(
        {
            "model": binary_rf,
            "feature_names": FEATURE_NAMES,
            "threshold": deployment_threshold,
            "validation_threshold": threshold,
            "classes": ["Normal", "Attack"],
        },
        ARTIFACT_DIR / "binary_threat_classifier.joblib",
    )

    print("Training multi-class Random Forest ...")
    counts = train_sample["label"].value_counts()
    rare_labels = set(counts[counts < MIN_MULTICLASS_COUNT].index)
    multi_labels = train_sample["label"].where(~train_sample["label"].isin(rare_labels), "Other")
    multi_classes = [name for name in LABEL_NAMES if name in set(multi_labels)]
    multi_rf = RandomForestClassifier(
        n_estimators=MULTICLASS_TREES,
        max_depth=24,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )
    multi_rf.fit(X_train, multi_labels.to_numpy())
    multi_predictions = multi_rf.predict(X_test)
    multi_report = classification_report(
        test["label"].where(~test["label"].isin(rare_labels), "Other"),
        multi_predictions,
        labels=multi_classes,
        zero_division=0,
    )
    (REPORT_DIR / "multiclass_classification_report.txt").write_text(multi_report, encoding="utf-8")
    print(multi_report)

    joblib.dump(
        {
            "model": multi_rf,
            "feature_names": FEATURE_NAMES,
            "classes": multi_rf.classes_.tolist(),
            "merged_rare_labels": sorted(rare_labels),
        },
        ARTIFACT_DIR / "multiclass_attack_classifier.joblib",
    )

    print("Training Isolation Forest on normal traffic ...")
    if_normal = normal_train.sample(
        n=min(IF_NORMAL_SAMPLE, len(normal_train)), random_state=RANDOM_STATE
    )
    isolation_forest = IsolationForest(
        n_estimators=IF_TREES,
        contamination=0.05,
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )
    isolation_forest.fit(if_normal[FEATURE_NAMES].to_numpy(dtype=np.float32))

    anomaly_scores = -isolation_forest.score_samples(X_test)
    anomaly_predictions = isolation_forest.predict(X_test) == -1
    if_metrics = {
        "roc_auc": round(float(roc_auc_score(y_test_binary, anomaly_scores)), 4),
        "pr_auc": round(float(average_precision_score(y_test_binary, anomaly_scores)), 4),
        "attack_detection_rate": round(float(anomaly_predictions[y_test_binary == 1].mean()), 4),
        "normal_false_positive_rate": round(float(anomaly_predictions[y_test_binary == 0].mean()), 4),
        "contamination": 0.05,
        "training_rows": int(len(if_normal)),
    }
    print(f"Isolation Forest test: {json.dumps(if_metrics)}")

    joblib.dump(
        {
            "model": isolation_forest,
            "feature_names": FEATURE_NAMES,
            "contamination": 0.05,
        },
        ARTIFACT_DIR / "flow_anomaly_detector.joblib",
    )

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "CIC-IDS2017",
        "feature_names": FEATURE_NAMES,
        "train_rows": int(len(train_sample)),
        "train_normal_rows": int(len(normal_sample)),
        "train_attack_rows": int(len(attack_train)),
        "val_rows": int(len(val)),
        "test_rows": int(len(test)),
        "validation_threshold": round(float(threshold), 4),
        "deployment_threshold": deployment_threshold,
        "threshold_selection": f"validation-selected at max F1 with FPR <= {MAX_VALIDATION_FPR:.1%}; deployment uses 0.50",
        "binary_validation": val_metrics,
        "binary_test_at_validation_threshold": test_metrics,
        "binary_test_at_deployment_threshold": deployment_metrics,
        "binary_test_at_0_5": test_default,
        "binary_test_at_0_8": test_080,
        "isolation_forest_test": if_metrics,
        "threshold_curve": threshold_curve,
        "feature_importance": feature_importance.head(10).to_dict(orient="records"),
        "limitations": [
            "CIC-IDS2017 is from 2017 and has known quality and labeling issues.",
            "The CSV has no timestamp; splits are chronological within each label and day.",
            "Exact duplicates were removed, but near-duplicate flows may remain.",
            "The serving feature extractor must match this contract before deployment.",
        ],
    }
    (REPORT_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    binary_report = classification_report(
        y_test_binary,
        (test_probabilities >= threshold).astype(int),
        target_names=["Normal", "Attack"],
        zero_division=0,
    )
    (REPORT_DIR / "binary_classification_report.txt").write_text(binary_report, encoding="utf-8")

    model_card = f"""# Cypher ML model card

## Dataset
- CIC-IDS2017, 8 daily CSVs, 2,830,743 raw rows.
- 2,415,814 rows after exact deduplication.
- Split: chronological 70/15/15 within each label and source file.
- Training sample: {len(train_sample):,} rows ({len(normal_sample):,} normal, {len(attack_train):,} attack).

## Features
{len(FEATURE_NAMES)} flow features shared with the serving contract. See `ml/features.py`.

## Binary Random Forest
- Validation-selected threshold: {threshold:.2f} (max F1 with validation FPR <= {MAX_VALIDATION_FPR:.1%})
- Deployment threshold: {deployment_threshold:.2f}
- Validation at selected threshold: precision={val_metrics['precision']}, recall={val_metrics['recall']}, F1={val_metrics['f1']}, FPR={val_metrics['fpr']}
- Test at validation threshold: precision={test_metrics['precision']}, recall={test_metrics['recall']}, F1={test_metrics['f1']}, FPR={test_metrics['fpr']}
- Test at deployment threshold: precision={deployment_metrics['precision']}, recall={deployment_metrics['recall']}, F1={deployment_metrics['f1']}, FPR={deployment_metrics['fpr']}
- Test ROC-AUC={test_metrics['roc_auc']}, PR-AUC={test_metrics['pr_auc']}

## Isolation Forest
- Trained on {len(if_normal):,} normal flows.
- Test ROC-AUC={if_metrics['roc_auc']}, PR-AUC={if_metrics['pr_auc']}
- Attack detection rate={if_metrics['attack_detection_rate']}, normal FPR={if_metrics['normal_false_positive_rate']}

## Limitations
- CIC-IDS2017 is old and has labeling/quality issues.
- Near-duplicate flows may leak across splits.
- The model is trained on CSV flow features and must not be deployed until the serving extractor matches the contract.
- These metrics are not directly comparable to packet-window results or to another dataset.
"""
    (REPORT_DIR / "model_card.md").write_text(model_card, encoding="utf-8")
    print(f"\nWrote artifacts to {ARTIFACT_DIR}")
    print(f"Wrote reports to {REPORT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
