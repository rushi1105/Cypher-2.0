"""Upload a PCAP and verify that the uploaded file streams through detections."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:8000"
PCAP = ROOT / "engine" / "test_attack.pcap"
EXPECTED_RULES = {
    "port_scan",
    "syn_flood",
    "dns_flood",
    "suspicious_port",
    "brute_force",
    "beaconing",
}


def main() -> int:
    with PCAP.open("rb") as handle:
        response = httpx.post(
            f"{BASE}/upload",
            files={"file": (PCAP.name, handle, "application/vnd.tcpdump.pcap")},
            timeout=30.0,
        )
    response.raise_for_status()
    uploaded = response.json()
    print("upload:", json.dumps(uploaded))

    rules = set()
    with httpx.stream("GET", f"{BASE}/stream/detections", params={"pcap": uploaded["pcap"]}, timeout=60.0) as stream:
        stream.raise_for_status()
        for line in stream.iter_lines():
            if not line.startswith("data:"):
                continue
            event = json.loads(line[5:].strip())
            if event.get("kind") == "rule":
                rules.add(event["rule"])

    print("rules:", sorted(rules))
    missing = EXPECTED_RULES - rules
    if missing:
        print(f"FAILED: missing {sorted(missing)}")
        return 1
    print("UPLOAD_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
