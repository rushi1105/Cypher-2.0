# Offline end-to-end verification

**Date:** 2026-10-20  
**Path:** engine -> FastAPI -> ML -> SSE  
**Input:** `engine/test_dpi.pcap` (77 packets)

## How to reproduce

```powershell
.\scripts\build-engine.ps1
.\.venv\Scripts\python.exe -m uvicorn server.server:app --host 127.0.0.1 --port 8000
.\.venv\Scripts\python.exe scripts\verify-offline-e2e.py
```

## Result

`/health` reported:

```json
{
  "status": "ok",
  "engine_ready": true,
  "shim_active": false,
  "ml_loaded": true,
  "ml_error": null
}
```

`/stream/enriched` emitted 77 packets grouped as:

```text
window 1: 25 packets, Normal, confidence 0.5371
window 2: 25 packets, Normal, confidence 0.5392
window 3: 25 packets, Attack, confidence 0.6273
window 4:  2 packets, Pending
```

All packets in a full window shared the same prediction, confirming the enriched-stream fix. The final partial window was emitted as `Pending`.

## Window 3 detection example

```json
{
  "window_id": 3,
  "features": {
    "packet_count": 25,
    "avg_packet_size": 77.2,
    "tcp_count": 21,
    "udp_count": 4,
    "unique_ips": 10,
    "syn_count": 11,
    "tcp_ratio": 0.84,
    "syn_ratio": 0.44,
    "packet_size_std": 35.0357,
    "avg_interarrival_time": 1.003775,
    "unique_ports": 6
  },
  "prediction": {
    "label": "Attack",
    "confidence": 0.6273,
    "is_threat": false,
    "anomaly_score": -0.724,
    "is_anomaly": true,
    "model_active": true,
    "window_id": 3
  }
}
```

## Flow-level model (`/stream/flows`)

The 24-feature CIC-IDS2017 model emitted 27 flow events. Example:

```text
flow 2: YouTube 192.168.1.100:58867 -> 142.250.185.110:443
  label=Normal, p=0.028, category=Normal, anomaly=False
```

Stats after the flow stream:

```json
{
  "total_flows": 27,
  "flow_threats": 0,
  "flow_anomalies": 0,
  "top_attack_categories": {"Normal": 27}
}
```

The five single-packet flows from the synthetic blocked-IP scenario were not flagged by the flow model. This is expected for a flow-level model on one-packet flows and is a reason to add deterministic rule detectors (port scan, SYN rate, suspicious ports) rather than relying on ML alone.

## Rule + MITRE detection on `test_attack.pcap`

Command:

```text
GET /stream/detections?pcap=test_attack.pcap
```

The synthetic attack capture produced six rule alerts:

| Rule | Severity | MITRE | Evidence |
|---|---|---|---|
| port_scan | High | T1046 | 20 unique ports in 60s |
| syn_flood | High | T1498 | 50 SYNs in 5s |
| dns_flood | Medium | T1498 | 50 DNS packets in 5s |
| suspicious_port | High | T1571 | destination port 4444 |
| brute_force | High | T1110 | 10 SYN attempts to port 22 |
| beaconing | Medium | T1071 | 8 samples at 5s intervals, CV 0.0 |

Stats:

```json
{
  "total_detections": 6,
  "detections_by_severity": {"high": 4, "medium": 2},
  "mitre_techniques": {
    "T1046": 1, "T1498": 2, "T1571": 1, "T1110": 1, "T1071": 1
  }
}
```

All flow-level ML predictions for this attack capture were `Normal`; the deterministic rules caught the synthetic attacks. This is the hybrid detection story: rules for known patterns, ML for flow-level behavior.

## Observations

- The C++ engine now supplies `size` and `flags`, so `avg_packet_size`, `packet_size_std`, and `syn_count` are no longer estimated or zero.
- The partial final window is emitted as `Pending`.
- All four windows were marked anomalous by the current Isolation Forest; the synthetic `test_dpi.pcap` is out of distribution for the pre-trained model.
- Window 3 was labeled `Attack` with confidence `0.6273`, below the `0.80` threshold, so `is_threat` remained `false`. This threshold/label interaction needs to be clarified in the next ML iteration.
- `/stats` accumulated 154 packets and 6 windows because `/stream/enriched` and `/stream/windows` each spawn their own engine process. The single-session architecture in M4 will fix duplicated stats and threats.
- The legacy window model is an inference artifact only. The new CIC-IDS2017 flow models are documented in `ml/reports/model_card.md`.
- Serving feature parity is name-level and contract-level; value parity is approximate because packet bytes are estimated as `size - 14` and CICFlowMeter semantics are not identical.

## Next step

The rules and MITRE mapping are working. The next major work items are the dashboard, live capture, and serving the rule and flow events in the UI. The legacy window endpoints still need to be retired or clearly marked as legacy.
