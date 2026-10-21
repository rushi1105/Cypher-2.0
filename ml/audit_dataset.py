"""Audit the downloaded CIC-IDS2017 CSVs and write a summary report."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw" / "cicids2017"
REPORT_DIR = ROOT / "ml" / "reports"
REPORT_PATH = REPORT_DIR / "dataset_audit.json"


def main() -> int:
    files = sorted(RAW_DIR.glob("*.csv"))
    if not files:
        print(f"No CSV files found in {RAW_DIR}")
        return 1

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    summary: dict = {"files": {}, "columns": None}

    for path in files:
        print(f"Reading {path.name} ...")
        frame = pd.read_csv(path, low_memory=False)
        frame.columns = [str(column).strip().lstrip("\ufeff") for column in frame.columns]

        if summary["columns"] is None:
            summary["columns"] = list(frame.columns)

        labels = frame["Label"].astype(str).str.strip().value_counts()
        safe_labels = {
            label.encode("ascii", "backslashreplace").decode("ascii"): int(count)
            for label, count in labels.items()
        }
        file_summary = {
            "rows": int(len(frame)),
            "columns": int(frame.shape[1]),
            "duplicate_rows": int(frame.duplicated().sum()),
            "missing_cells": int(frame.isna().sum().sum()),
            "labels": safe_labels,
            "has_timestamp": any("time" in column.lower() for column in frame.columns),
        }
        summary["files"][path.name] = file_summary
        print(
            f"  rows={file_summary['rows']:,} cols={file_summary['columns']} "
            f"duplicates={file_summary['duplicate_rows']:,} "
            f"missing={file_summary['missing_cells']:,}"
        )
        for label, count in safe_labels.items():
            print(f"    {label}: {count:,}")

    REPORT_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nWrote {REPORT_PATH}")
    print("\nColumns:")
    for column in summary["columns"]:
        print(f"  {column}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
