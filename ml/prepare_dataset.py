"""Prepare CIC-IDS2017 for modelling with a chronological per-file split."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.features import CIC_COLUMNS, FEATURE_NAMES, LABEL_NAMES, cic_frame_to_features, validate_feature_frame  # noqa: E402

RAW_DIR = ROOT / "data" / "raw" / "cicids2017"
PROCESSED_DIR = ROOT / "data" / "processed" / "cicids2017"
REPORT_DIR = ROOT / "ml" / "reports"
MANIFEST_PATH = REPORT_DIR / "dataset_manifest.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def split_frame(frame: pd.DataFrame) -> dict[str, pd.DataFrame]:
    parts: dict[str, list[pd.DataFrame]] = {"train": [], "val": [], "test": []}
    for _, group in frame.groupby("label", sort=False):
        group = group.sort_values("row_index")
        total = len(group)
        train_end = int(total * 0.70)
        val_end = int(total * 0.85)
        parts["train"].append(group.iloc[:train_end])
        parts["val"].append(group.iloc[train_end:val_end])
        parts["test"].append(group.iloc[val_end:])
    return {
        name: pd.concat(frames, ignore_index=True) if frames else frame.iloc[0:0].copy()
        for name, frames in parts.items()
    }


def main() -> int:
    files = sorted(RAW_DIR.glob("*.csv"))
    if not files:
        print(f"No CSV files found in {RAW_DIR}")
        return 1

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    parts: list[pd.DataFrame] = []
    source_manifest: dict[str, dict] = {}

    wanted = set(CIC_COLUMNS.values())

    for path in files:
        print(f"Preparing {path.name} ...")
        frame = pd.read_csv(
            path,
            usecols=lambda column: str(column).strip().lstrip("\ufeff") in wanted,
            low_memory=False,
        )
        frame.columns = [str(column).strip().lstrip("\ufeff") for column in frame.columns]
        features = cic_frame_to_features(frame)
        features["source_file"] = path.name
        features["row_index"] = range(len(features))
        parts.append(features)
        source_manifest[path.name] = {
            "rows": int(len(features)),
            "sha256": sha256(path),
        }
        print(f"  rows={len(features):,}")

    combined = pd.concat(parts, ignore_index=True)
    before = len(combined)
    combined = combined.drop_duplicates(subset=FEATURE_NAMES + ["label"], keep="first")
    combined = combined.sort_values(["source_file", "row_index"]).reset_index(drop=True)
    print(f"Rows before dedup: {before:,}")
    print(f"Rows after dedup:  {len(combined):,}")

    splits: dict[str, list[pd.DataFrame]] = {"train": [], "val": [], "test": []}
    for source_file, group in combined.groupby("source_file", sort=True):
        for split_name, split in split_frame(group).items():
            splits[split_name].append(split)

    split_counts: dict[str, dict] = {}
    for split_name in ("train", "val", "test"):
        split = pd.concat(splits[split_name], ignore_index=True)
        validate_feature_frame(split)
        output_path = PROCESSED_DIR / f"{split_name}.parquet"
        split.to_parquet(output_path, index=False)
        labels = split["label"].value_counts().reindex(LABEL_NAMES, fill_value=0)
        split_counts[split_name] = {
            "rows": int(len(split)),
            "labels": {name: int(labels[name]) for name in LABEL_NAMES},
            "attacks": int((split["label"] != "Normal").sum()),
            "normal": int((split["label"] == "Normal").sum()),
        }
        print(f"{split_name}: {len(split):,} rows -> {output_path}")

    manifest = {
        "dataset": "CIC-IDS2017",
        "source": "https://huggingface.co/datasets/c01dsnap/CIC-IDS2017",
        "feature_names": FEATURE_NAMES,
        "label_names": LABEL_NAMES,
        "split_method": "chronological 70/15/15 within each label and source file after global exact deduplication",
        "rows_before_dedup": int(before),
        "rows_after_dedup": int(len(combined)),
        "splits": split_counts,
        "sources": source_manifest,
        "limitations": [
            "CIC-IDS2017 is from 2017 and has known quality and labeling issues.",
            "The CSV has no timestamp column; row order within each day is used as the time proxy.",
            "Exact duplicates are removed, but near-duplicate flows may remain.",
            "The feature contract must be matched by the serving extractor before deployment.",
        ],
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nWrote {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
