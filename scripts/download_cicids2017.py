"""Download the CIC-IDS2017 MachineLearningCSV files from the Hugging Face mirror.

The dataset is large and is intentionally not committed. Raw files land in
data/raw/cicids2017 by default.

Usage:
    .venv\\Scripts\\python.exe scripts\\download_cicids2017.py
    .venv\\Scripts\\python.exe scripts\\download_cicids2017.py --files Monday-WorkingHours.pcap_ISCX.csv
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import urllib.request
from pathlib import Path

BASE_URL = "https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main"

FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]


def download(url: str, destination: Path) -> str:
    digest = hashlib.sha256()
    partial = destination.with_suffix(destination.suffix + ".part")

    with urllib.request.urlopen(url) as response, partial.open("wb") as handle:
        total = int(response.headers.get("Content-Length", "0"))
        downloaded = 0
        next_report = 10 * 1024 * 1024

        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            handle.write(chunk)
            digest.update(chunk)
            downloaded += len(chunk)

            if downloaded >= next_report:
                if total:
                    pct = downloaded * 100 / total
                    sys.stdout.write(
                        f"\r  {downloaded / 1024 / 1024:7.1f} MB "
                        f"of {total / 1024 / 1024:7.1f} MB ({pct:5.1f}%)"
                    )
                else:
                    sys.stdout.write(f"\r  {downloaded / 1024 / 1024:7.1f} MB")
                sys.stdout.flush()
                next_report += 10 * 1024 * 1024

    if total and downloaded != total:
        partial.unlink(missing_ok=True)
        raise RuntimeError(f"incomplete download: {downloaded} of {total} bytes")

    partial.replace(destination)
    sys.stdout.write("\n")
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default="data/raw/cicids2017")
    parser.add_argument("--files", nargs="*", default=FILES)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    output_dir = (root / args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    unknown = [name for name in args.files if name not in FILES]
    if unknown:
        print(f"Unknown files: {unknown}", file=sys.stderr)
        print(f"Available files: {FILES}", file=sys.stderr)
        return 2

    manifest: list[str] = []
    for index, name in enumerate(args.files, start=1):
        destination = output_dir / name
        print(f"[{index}/{len(args.files)}] {name}")
        if destination.exists() and destination.stat().st_size > 0:
            print(f"  already exists: {destination}")
            digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        else:
            url = f"{BASE_URL}/{name}?download=true"
            print(f"  downloading: {url}")
            digest = download(url, destination)
            print(f"  saved: {destination}")
        manifest.append(f"{digest}  {name}")

    manifest_path = output_dir / "SHA256SUMS.txt"
    manifest_path.write_text("\n".join(manifest) + "\n", encoding="utf-8")
    print(f"\nWrote {manifest_path}")
    print("Raw data is ignored by Git. Do not commit it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
