"""Quick test script for all Cypher 2.0 server endpoints."""
import urllib.request
import json
import time

BASE = "http://127.0.0.1:8000"

# 1. Health check
print("=== /health ===")
r = urllib.request.urlopen(f"{BASE}/health")
health = json.loads(r.read())
for k, v in health.items():
    print(f"  {k}: {v}")
print()

# 2. Enriched stream — get first 30 packets (enough for 1 ML window)
print("=== /stream/enriched (first 30 packets) ===")
req = urllib.request.urlopen(f"{BASE}/stream/enriched", timeout=15)
count = 0
for raw_line in req:
    line = raw_line.decode("utf-8").strip()
    if line.startswith("data:"):
        pkt = json.loads(line[5:].strip())
        ml = pkt.get("ml", {})
        label = ml.get("label", "?")
        conf = ml.get("confidence", 0)
        anomaly = ml.get("is_anomaly", "?")
        win_id = ml.get("window_id", 0)
        src = pkt.get("src", "?")
        dst = pkt.get("dst", "?")
        proto = pkt.get("proto", "?")
        app = pkt.get("app", "?")
        size = pkt.get("size", "?")
        print(f"  [{proto}] {src} -> {dst}  app={app}  size={size}  ML={label}({conf:.2f})  anomaly={anomaly}  win={win_id}")
        count += 1
        if count >= 30:
            break
print(f"  ... got {count} packets")
print()

# 3. Window stream — get first 2 windows
print("=== /stream/windows (first 2 windows) ===")
req2 = urllib.request.urlopen(f"{BASE}/stream/windows", timeout=15)
wcount = 0
for raw_line in req2:
    line = raw_line.decode("utf-8").strip()
    if line.startswith("data:"):
        event = json.loads(line[5:].strip())
        pred = event.get("prediction", {})
        feats = event.get("features", {})
        print(f"  Window #{event['window_id']}: {pred['label']} (conf={pred['confidence']:.2f})  anomaly={pred['is_anomaly']}")
        print(f"    features: pkt_count={feats.get('packet_count')} avg_size={feats.get('avg_packet_size')} tcp={feats.get('tcp_count')} syn={feats.get('syn_count')} unique_ips={feats.get('unique_ips')} iat={feats.get('avg_interarrival_time')}")
        wcount += 1
        if wcount >= 2:
            break
print(f"  ... got {wcount} windows")
print()

# 4. Stats
print("=== /stats ===")
r = urllib.request.urlopen(f"{BASE}/stats")
stats = json.loads(r.read())
for k, v in stats.items():
    print(f"  {k}: {v}")
print()

# 5. Threats
print("=== /threats ===")
r = urllib.request.urlopen(f"{BASE}/threats")
threats = json.loads(r.read())
print(f"  count: {threats['count']}")
for t in threats["threats"][:5]:
    p = t["prediction"]
    print(f"  window={t['window_id']}  label={p['label']}  conf={p['confidence']}  anomaly={p['is_anomaly']}")

print("\n=== ALL TESTS COMPLETE ===")
