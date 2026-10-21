"""Offline end-to-end smoke test for the Cypher FastAPI bridge.

Start the API first, then run:
    .venv\\Scripts\\python.exe scripts\\verify-offline-e2e.py
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict

import httpx

BASE = "http://127.0.0.1:8000"


def sse_events(path: str) -> list[dict]:
    events: list[dict] = []
    with httpx.stream("GET", BASE + path, timeout=60.0) as response:
        response.raise_for_status()
        for line in response.iter_lines():
            if line.startswith("data:"):
                events.append(json.loads(line[5:].strip()))
    return events


def main() -> int:
    failures: list[str] = []

    health = httpx.get(BASE + "/health", timeout=10.0).json()
    print("health:", json.dumps(health))
    if health.get("status") != "ok":
        failures.append("/health status is not ok")
    if not health.get("engine_ready") and not health.get("shim_active"):
        failures.append("neither the C++ engine nor the shim is available")
    if not health.get("ml_loaded"):
        failures.append("window ML models are not loaded")
    if not health.get("flow_ml_loaded"):
        failures.append("flow ML models are not loaded")

    enriched = sse_events("/stream/enriched")
    print(f"enriched events: {len(enriched)}")
    if not enriched:
        failures.append("/stream/enriched returned no packets")

    by_window: dict[int, list[dict]] = defaultdict(list)
    for packet in enriched:
        by_window[packet["ml"]["window_id"]].append(packet)

    for window_id, packets in sorted(by_window.items()):
        labels = Counter(packet["ml"]["label"] for packet in packets)
        confidences = {packet["ml"]["confidence"] for packet in packets}
        print(
            f"  window {window_id}: packets={len(packets)} "
            f"labels={dict(labels)} confidences={sorted(confidences)}"
        )
        if len(packets) == 25:
            if len(labels) != 1 or len(confidences) != 1:
                failures.append(f"window {window_id} does not share one prediction")
        elif not (len(labels) == 1 and "Pending" in labels):
            failures.append(f"partial window {window_id} is not Pending")

    windows = sse_events("/stream/windows")
    print(f"window events: {len(windows)}")
    if not windows:
        failures.append("/stream/windows returned no events")
    for event in windows[:3]:
        prediction = event["prediction"]
        print(
            f"  window {event['window_id']}: label={prediction['label']} "
            f"confidence={prediction['confidence']} "
            f"is_threat={prediction['is_threat']} "
            f"is_anomaly={prediction['is_anomaly']} "
            f"features={event['features']}"
        )

    flows = sse_events("/stream/flows")
    print(f"flow events: {len(flows)}")
    if not flows:
        failures.append("/stream/flows returned no flows")
    for event in flows[:8]:
        prediction = event["prediction"]
        print(
            f"  flow {event['flow_id']}: {event.get('app', '?')} "
            f"{event.get('src', '?')}:{event.get('sport', '?')} -> "
            f"{event.get('dst', '?')}:{event.get('dport', '?')} "
            f"label={prediction['label']} p={prediction['attack_probability']} "
            f"category={prediction['category']} anomaly={prediction['is_anomaly']}"
        )
        if len(event["features"]) != 24:
            failures.append(f"flow {event['flow_id']} has the wrong feature count")
        if not prediction.get("model_active"):
            failures.append(f"flow {event['flow_id']} used an inactive model")

    detection_events = sse_events("/stream/detections?pcap=test_attack.pcap")
    detections = [event for event in detection_events if event.get("kind") == "rule"]
    detected_rules = {event["rule"] for event in detections}
    print(f"attack detection events: {len(detection_events)}")
    print(f"rule alerts: {len(detections)} rules={sorted(detected_rules)}")
    for event in detections[:10]:
        print(
            f"  {event['rule']}: {event['severity']} "
            f"{event['src']} -> {event['dst']}:{event['dport']} "
            f"mitre={event.get('mitre', {}).get('id')} "
            f"evidence={event['evidence']}"
        )
    expected_rules = {
        "port_scan",
        "syn_flood",
        "dns_flood",
        "suspicious_port",
        "brute_force",
        "beaconing",
    }
    missing_rules = expected_rules - detected_rules
    if missing_rules:
        failures.append(f"missing attack rules: {sorted(missing_rules)}")
    for event in detections:
        if not event.get("mitre", {}).get("id"):
            failures.append(f"rule {event['rule']} has no MITRE mapping")

    stats = httpx.get(BASE + "/stats", timeout=10.0).json()
    print("stats:", json.dumps(stats))
    if stats.get("total_packets", 0) <= 0:
        failures.append("/stats total_packets is not positive")
    if stats.get("total_flows", 0) <= 0:
        failures.append("/stats total_flows is not positive")
    if stats.get("total_detections", 0) <= 0:
        failures.append("/stats total_detections is not positive")

    threats = httpx.get(BASE + "/threats", timeout=10.0).json()
    print("threats count:", threats.get("count"))
    if "threats" not in threats:
        failures.append("/threats did not return a threats list")

    if failures:
        print("\nFAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("\nE2E_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
