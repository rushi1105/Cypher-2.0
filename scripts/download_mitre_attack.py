"""Download MITRE ATT&CK Enterprise STIX and build a compact technique index."""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MITRE_DIR = ROOT / "data" / "mitre"
RAW_PATH = MITRE_DIR / "enterprise-attack.json"
INDEX_PATH = MITRE_DIR / "attack_techniques.json"
URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {url}")
    with urllib.request.urlopen(url) as response, destination.open("wb") as handle:
        total = int(response.headers.get("Content-Length", "0"))
        downloaded = 0
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            handle.write(chunk)
            downloaded += len(chunk)
            if total:
                print(f"\r  {downloaded / 1024 / 1024:.1f} / {total / 1024 / 1024:.1f} MB", end="")
        print()


def compact_technique(obj: dict) -> dict | None:
    references = obj.get("external_references") or []
    attack_reference = next(
        (reference for reference in references if reference.get("source_name") == "mitre-attack"),
        None,
    )
    if not attack_reference:
        return None
    technique_id = attack_reference.get("external_id", "")
    if not technique_id.startswith("T"):
        return None
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return None

    tactics = [
        phase.get("phase_name", "")
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
    ]
    description = (obj.get("description") or "").strip()
    detection = (obj.get("x_mitre_detection") or "").strip()
    return {
        "id": technique_id,
        "name": obj.get("name", ""),
        "tactics": sorted(set(tactics)),
        "description": description,
        "detection": detection,
        "platforms": sorted(set(obj.get("x_mitre_platforms", []))),
        "url": attack_reference.get("url", f"https://attack.mitre.org/techniques/{technique_id}/"),
    }


def main() -> int:
    if not RAW_PATH.exists():
        download(URL, RAW_PATH)
    print(f"Reading {RAW_PATH}")
    bundle = json.loads(RAW_PATH.read_text(encoding="utf-8"))
    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        technique = compact_technique(obj)
        if technique:
            techniques.append(technique)
    techniques.sort(key=lambda item: item["id"])
    INDEX_PATH.write_text(json.dumps(techniques, indent=2), encoding="utf-8")
    print(f"Wrote {len(techniques)} techniques to {INDEX_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
