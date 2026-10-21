"""
server.py — Cypher 2.0 FastAPI Bridge
======================================
Connects the C++ DPI engine (Cypher 1.0) with the ML threat detection
model via three streaming/REST endpoints:

  GET /health            → liveness check
  GET /stream            → raw NDJSON SSE (one event per packet, no ML)
  GET /stream/enriched   → ML-enriched SSE (ML result appended to each packet)
  GET /stream/windows    → SSE window events (one per 25 packets, includes ML prediction)
  GET /stream/flows      → SSE flow events (one per completed flow, 24-feature model)
  GET /stream/detections → SSE flow events + deterministic rule alerts + MITRE mapping
  GET /stream/live       → dashboard stream: packets + rule alerts + flow events
  GET /rules             → rule catalog and MITRE technique metadata
  GET /mitre/search      → retrieve ATT&CK techniques for a query
  GET /mitre/{id}        → technique details
  POST /explain          → grounded, cited ATT&CK explanation for an alert
  GET /stats             → accumulated statistics (JSON)
  GET /threats           → list of detected threats (JSON)

Architecture
------------
  [dpi_simple.exe --json]
        │ stdout NDJSON
        ▼
  generator()  ──►  PacketWindowBuffer  ──►  MLPredictor
        │                                          │
        ▼                                          ▼
  /stream (raw)                          /stream/enriched
                                         /stream/windows
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Generator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse

try:
    from .flow_features import FlowFeatureTracker
    from .flow_predictor import flow_predictor
    from .mitre_kb import mitre_kb
    from .ml_bridge import PacketWindowBuffer
    from .ml_predictor import predictor
    from .rules import MITRE_TECHNIQUES, RULE_SPECS, RuleEngine
except ImportError:
    from flow_features import FlowFeatureTracker
    from flow_predictor import flow_predictor
    from mitre_kb import mitre_kb
    from ml_bridge import PacketWindowBuffer
    from ml_predictor import predictor
    from rules import MITRE_TECHNIQUES, RULE_SPECS, RuleEngine

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("cypher.server")

# ── Paths (all relative to this file so CWD doesn't matter) ───────────────────
_HERE        = Path(__file__).parent
_ENGINE_DIR  = _HERE.parent / "engine"

ENGINE_BIN   = _ENGINE_DIR / "dpi_simple.exe"
ENGINE_PCAP  = _ENGINE_DIR / "test_dpi.pcap"
ENGINE_OUT   = _ENGINE_DIR / "output.pcap"
ENGINE_SHIM  = _ENGINE_DIR / "engine_shim.py"   # Python fallback

def _resolve_pcap(pcap: str | None) -> Path:
    if not pcap:
        return ENGINE_PCAP
    candidate = (_ENGINE_DIR / pcap).resolve()
    if candidate.parent != _ENGINE_DIR.resolve() or candidate.suffix.lower() != ".pcap":
        raise HTTPException(status_code=400, detail="pcap must name a .pcap file in the engine directory")
    if not candidate.is_file():
        raise HTTPException(status_code=404, detail=f"pcap not found: {pcap}")
    return candidate

# ── Startup: load ML models ────────────────────────────────────────────────────
predictor.load()
flow_predictor.load()
mitre_kb.load()


def _engine_binary_works() -> bool:
    """
    Quick probe: run the C++ binary with no args and check the exit code.
    - 0 or 1  → binary runs fine (1 = "usage error", still means it loaded OK)
    - Large positive or negative → DLL-load failure / format mismatch → use shim
    """
    if not ENGINE_BIN.exists():
        return False
    try:
        result = subprocess.run(
            [str(ENGINE_BIN)],
            capture_output=True,
            timeout=5,
        )
        # 0xC000007B = 3221225595 = "not a valid Win32 application" (missing DLL, arch mismatch)
        # Any other giant value also signals an OS-level load failure
        BAD_CODES = {3221225595, 3221225501, 3221225781}   # STATUS_INVALID_IMAGE_FORMAT, etc
        ok = result.returncode not in BAD_CODES and result.returncode <= 255
        logger.debug("Engine probe exit code: %d → %s", result.returncode, "OK" if ok else "FAIL")
        return ok
    except Exception as exc:
        logger.debug("Engine probe exception: %s", exc)
        return False



_USE_SHIM = not _engine_binary_works()
if _USE_SHIM:
    logger.warning(
        "⚠️  C++ engine binary unavailable — using Python PCAP shim. "
        "This is equivalent for development but the C++ engine is faster for production."
    )
else:
    logger.info("✅  C++ engine binary ready")

# ── FastAPI app ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Cypher 2.0",
    description="Real-time network threat detection — DPI + ML bridge",
    version="2.0.0",
)

# Allow dashboard (any origin during development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── In-memory stats accumulator ────────────────────────────────────────────────
_stats: dict = {
    "total_packets":        0,
    "total_windows":        0,
    "total_flows":          0,
    "attacks_detected":     0,
    "anomalies_detected":   0,
    "flow_threats":         0,
    "flow_anomalies":       0,
    "total_detections":     0,
    "detections_by_severity": {},
    "detections_by_rule":   {},
    "mitre_techniques":     {},
    "blocked_packets":      0,
    "top_apps":             {},
    "top_attack_categories": {},
    "start_time":           time.time(),
}

_threats: list[dict] = []   # rolling list of detected threat events


def _update_stats(packet: dict) -> None:
    """Update global counters from a single raw packet."""
    _stats["total_packets"] += 1
    if packet.get("blocked"):
        _stats["blocked_packets"] += 1
    app_label = packet.get("app", "Unknown")
    _stats["top_apps"][app_label] = _stats["top_apps"].get(app_label, 0) + 1


def _record_threat(window_id: int, features: dict, prediction: dict) -> None:
    """Append a detected threat / anomaly to the threat log."""
    _stats["total_windows"] += 1
    if prediction.get("is_threat"):
        _stats["attacks_detected"] += 1
    if prediction.get("is_anomaly"):
        _stats["anomalies_detected"] += 1

    if prediction.get("is_threat") or prediction.get("is_anomaly"):
        _threats.append({
            "kind":          "window",
            "window_id":     window_id,
            "timestamp":     time.time(),
            "prediction":    prediction,
            "features":      features,
        })
        # Keep last 500 threats in memory
        if len(_threats) > 500:
            _threats.pop(0)


def _record_flow(event: dict) -> None:
    """Update flow counters and append flagged flows to the threat log."""
    prediction = event["prediction"]
    _stats["total_flows"] += 1
    category = prediction.get("category", "Unknown")
    _stats["top_attack_categories"][category] = (
        _stats["top_attack_categories"].get(category, 0) + 1
    )
    if prediction.get("is_threat"):
        _stats["flow_threats"] += 1
    if prediction.get("is_anomaly"):
        _stats["flow_anomalies"] += 1

    if prediction.get("is_threat") or prediction.get("is_anomaly"):
        _threats.append({
            "kind":       "flow",
            "flow_id":    event["flow_id"],
            "timestamp":  time.time(),
            "src":        event.get("src", ""),
            "dst":        event.get("dst", ""),
            "sport":      event.get("sport", 0),
            "dport":      event.get("dport", 0),
            "proto":      event.get("proto", ""),
            "app":        event.get("app", ""),
            "sni":        event.get("sni", ""),
            "prediction": prediction,
            "features":   event["features"],
        })
        if len(_threats) > 500:
            _threats.pop(0)


def _record_detection(event: dict) -> None:
    """Update detection counters and append a rule alert to the threat log."""
    _stats["total_detections"] += 1
    severity = event.get("severity", "unknown")
    rule_id = event.get("rule", "unknown")
    _stats["detections_by_severity"][severity] = (
        _stats["detections_by_severity"].get(severity, 0) + 1
    )
    _stats["detections_by_rule"][rule_id] = (
        _stats["detections_by_rule"].get(rule_id, 0) + 1
    )
    technique = event.get("mitre")
    if technique:
        technique_id = technique.get("id", "unknown")
        _stats["mitre_techniques"][technique_id] = (
            _stats["mitre_techniques"].get(technique_id, 0) + 1
        )
    _threats.append({"kind": "rule", "timestamp": time.time(), **event})
    if len(_threats) > 500:
        _threats.pop(0)


# ── Engine process factory ─────────────────────────────────────────────────────
def _spawn_engine(pcap_path: Path | None = None) -> subprocess.Popen | None:
    """
    Spawn the DPI engine subprocess for a PCAP.
    Prefers the C++ binary; falls back to the Python shim automatically.
    """
    pcap_path = pcap_path or ENGINE_PCAP
    if _USE_SHIM:
        if not ENGINE_SHIM.exists():
            logger.error("Neither engine binary nor Python shim found")
            return None
        cmd = [sys.executable, str(ENGINE_SHIM), str(pcap_path), str(ENGINE_OUT)]
        logger.info("Spawning Python shim: %s", " ".join(cmd))
    else:
        cmd = [str(ENGINE_BIN), str(pcap_path), str(ENGINE_OUT), "--json"]
        logger.info("Spawning C++ engine: %s", " ".join(cmd))

    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,  # engine banners/stats → /dev/null
        text=True,
        encoding="utf-8",
        errors="replace",
    )


# ══════════════════════════════════════════════════════════════════════════════
#  Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
def health() -> JSONResponse:
    """Liveness check — also reports model and engine status."""
    return JSONResponse({
        "status":         "ok",
        "engine_path":    str(ENGINE_BIN),
        "engine_ready":   ENGINE_BIN.exists() and not _USE_SHIM,
        "shim_active":    _USE_SHIM,
        "shim_path":      str(ENGINE_SHIM),
        "ml_loaded":      predictor.is_loaded,
        "ml_error":       predictor.load_error,
        "flow_ml_loaded": flow_predictor.is_loaded,
        "flow_ml_error":  flow_predictor.load_error,
        "flow_model_threshold": flow_predictor.threshold,
        "flow_feature_count": len(flow_predictor.feature_names),
        "rule_count":     len(RULE_SPECS),
        "mitre_technique_count": len(MITRE_TECHNIQUES),
        "mitre_kb_loaded": mitre_kb.is_loaded,
        "mitre_kb_techniques": mitre_kb.technique_count,
        "mitre_kb_error": mitre_kb.load_error,
        "uptime_s":       round(time.time() - _stats["start_time"], 1),
    })


# ── /stream  (raw, no ML) ──────────────────────────────────────────────────────
@app.get("/stream")
def stream_packets(pcap: str | None = None) -> StreamingResponse:
    """
    Raw SSE stream — one event per packet as emitted by the DPI engine.
    No ML enrichment.  Keeps backward compatibility.
    """

    def generator() -> Generator[str, None, None]:
        process = _spawn_engine(_resolve_pcap(pcap))
        if process is None:
            yield "data: {\"error\": \"engine binary not found\"}\n\n"
            return

        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    packet = json.loads(line)
                    _update_stats(packet)
                    yield f"data: {json.dumps(packet)}\n\n"
                except json.JSONDecodeError as exc:
                    logger.debug("Non-JSON engine line: %s  (%s)", line[:80], exc)
        finally:
            process.stdout.close()
            process.wait()

    return StreamingResponse(generator(), media_type="text/event-stream")


# ── /stream/enriched  (ML-annotated per-packet stream) ────────────────────────
@app.get("/stream/enriched")
def stream_enriched(pcap: str | None = None) -> StreamingResponse:
    """
    SSE stream — packets are buffered in 25-packet windows.  Once a window is
    full, its prediction is computed and all 25 packets are emitted together
    with the same "ml" block.  A final partial window is emitted as Pending.

    Event shape:
    {
      "ts": ..., "src": ..., ...,          ← engine fields
      "ml": {
        "label":         "Normal"|"Attack",
        "confidence":    0.93,
        "is_threat":     false,
        "anomaly_score": -0.12,
        "is_anomaly":    false,
        "window_id":     7,
        "model_active":  true
      }
    }
    """

    def generator() -> Generator[str, None, None]:
        process = _spawn_engine(_resolve_pcap(pcap))
        if process is None:
            yield "data: {\"error\": \"engine binary not found\"}\n\n"
            return

        buf = PacketWindowBuffer()

        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    packet = json.loads(line)
                    _update_stats(packet)

                    result = buf.add_packet(packet)
                    if result is not None:
                        features, packets, window_id = result
                        prediction = predictor.predict(features)
                        prediction["window_id"] = window_id
                        _record_threat(window_id, features, prediction)

                        for window_packet in packets:
                            enriched = dict(window_packet)
                            enriched["ml"] = prediction
                            yield f"data: {json.dumps(enriched)}\n\n"

                except json.JSONDecodeError as exc:
                    logger.debug("Non-JSON engine line: %s  (%s)", line[:80], exc)

            packets, window_id = buf.flush_partial()
            if packets:
                pending = {
                    "label":         "Pending",
                    "confidence":    0.0,
                    "is_threat":     False,
                    "anomaly_score": 0.0,
                    "is_anomaly":    False,
                    "window_id":     window_id,
                    "model_active":  predictor.is_loaded,
                }
                for window_packet in packets:
                    enriched = dict(window_packet)
                    enriched["ml"] = pending
                    yield f"data: {json.dumps(enriched)}\n\n"
        finally:
            process.stdout.close()
            process.wait()

    return StreamingResponse(generator(), media_type="text/event-stream")


# ── /stream/windows  (window-level events) ────────────────────────────────────
@app.get("/stream/windows")
def stream_windows(pcap: str | None = None) -> StreamingResponse:
    """
    SSE stream — one event per 25-packet window.  Ideal for dashboard
    threat-timeline charts and ML confidence graphs.

    Event shape:
    {
      "window_id":   7,
      "timestamp":   1700000050.0,
      "features":    { ... 11 features ... },
      "prediction":  { "label": "Attack", "confidence": 0.87, ... },
      "packets":     [ {...}, {...}, ... ]   ← the 25 raw packets
    }
    """

    def generator() -> Generator[str, None, None]:
        process = _spawn_engine(_resolve_pcap(pcap))
        if process is None:
            yield "data: {\"error\": \"engine binary not found\"}\n\n"
            return

        buf = PacketWindowBuffer()

        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    packet = json.loads(line)
                    _update_stats(packet)

                    result = buf.add_packet(packet)
                    if result is not None:
                        features, packets, window_id = result
                        prediction = predictor.predict(features)
                        prediction["window_id"] = window_id
                        _record_threat(window_id, features, prediction)

                        event = {
                            "window_id":  window_id,
                            "timestamp":  time.time(),
                            "features":   features,
                            "prediction": prediction,
                            "packets":    packets,
                        }
                        yield f"data: {json.dumps(event)}\n\n"

                except json.JSONDecodeError as exc:
                    logger.debug("Non-JSON engine line: %s  (%s)", line[:80], exc)
        finally:
            process.stdout.close()
            process.wait()

    return StreamingResponse(generator(), media_type="text/event-stream")


# ── /stream/flows  (flow-level 24-feature model) ─────────────────────────────
@app.get("/stream/flows")
def stream_flows(pcap: str | None = None) -> StreamingResponse:
    """
    SSE stream — one event per completed, closed, or expired flow.

    Event shape:
    {
      "flow_id": 3,
      "src": "...", "dst": "...", "sport": 443, "dport": 58867,
      "proto": "TCP", "app": "YouTube", "sni": "www.youtube.com",
      "packet_count": 4,
      "features": { ...24 features... },
      "prediction": {
        "label": "Attack"|"Normal",
        "attack_probability": 0.93,
        "category": "Scan",
        "anomaly_score": 0.12,
        "is_anomaly": false,
        ...
      }
    }
    """

    def generator() -> Generator[str, None, None]:
        process = _spawn_engine(_resolve_pcap(pcap))
        if process is None:
            yield "data: {\"error\": \"engine binary not found\"}\n\n"
            return

        tracker = FlowFeatureTracker()

        def emit(event: dict) -> str:
            event["prediction"] = flow_predictor.predict(event["features"])
            _record_flow(event)
            return f"data: {json.dumps(event)}\n\n"

        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    packet = json.loads(line)
                    _update_stats(packet)
                    timestamp = float(packet.get("ts", time.time()))
                    for event in tracker.expire(timestamp):
                        yield emit(event)
                    for event in tracker.add_packet(packet):
                        yield emit(event)
                except json.JSONDecodeError as exc:
                    logger.debug("Non-JSON engine line: %s  (%s)", line[:80], exc)

            for event in tracker.flush_all():
                yield emit(event)
        finally:
            process.stdout.close()
            process.wait()

    return StreamingResponse(generator(), media_type="text/event-stream")


# ── /stream/detections  (rules + ML + MITRE) ─────────────────────────────────
@app.get("/stream/detections")
def stream_detections(pcap: str | None = None) -> StreamingResponse:
    """
    SSE stream — deterministic rule alerts plus flow-level ML predictions.

    Packet rule alerts are emitted as they fire. Completed/expired flows are
    emitted with their prediction and any flow-level rule matches.
    """

    def generator() -> Generator[str, None, None]:
        process = _spawn_engine(_resolve_pcap(pcap))
        if process is None:
            yield "data: {\"error\": \"engine binary not found\"}\n\n"
            return

        tracker = FlowFeatureTracker()
        rules = RuleEngine()

        def handle_detection(detection: dict) -> str:
            _record_detection(detection)
            return f"data: {json.dumps(detection)}\n\n"

        def handle_flow(event: dict) -> list[str]:
            event["kind"] = "flow"
            event["prediction"] = flow_predictor.predict(event["features"])
            event["rules"] = rules.process_flow(event)
            _record_flow(event)
            chunks = [handle_detection(detection) for detection in event["rules"]]
            chunks.append(f"data: {json.dumps(event)}\n\n")
            return chunks

        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    packet = json.loads(line)
                    _update_stats(packet)
                    timestamp = float(packet.get("ts", time.time()))
                    for detection in rules.process_packet(packet):
                        yield handle_detection(detection)
                    for event in tracker.expire(timestamp):
                        for chunk in handle_flow(event):
                            yield chunk
                    for event in tracker.add_packet(packet):
                        for chunk in handle_flow(event):
                            yield chunk
                except json.JSONDecodeError as exc:
                    logger.debug("Non-JSON engine line: %s  (%s)", line[:80], exc)

            for event in tracker.flush_all():
                for chunk in handle_flow(event):
                    yield chunk
        finally:
            process.stdout.close()
            process.wait()

    return StreamingResponse(generator(), media_type="text/event-stream")


# ── /stream/live  (packets + rules + flows, one engine) ───────────────────────
@app.get("/stream/live")
def stream_live(pcap: str | None = None) -> StreamingResponse:
    """
    SSE stream for the dashboard. One engine process emits:
    - packet events (kind=packet)
    - deterministic rule alerts (kind=rule)
    - completed/expired flow predictions (kind=flow)
    """
    def generator() -> Generator[str, None, None]:
        process = _spawn_engine(_resolve_pcap(pcap))
        if process is None:
            yield "data: {\"error\": \"engine binary not found\"}\n\n"
            return

        tracker = FlowFeatureTracker()
        rules = RuleEngine()

        def handle_detection(detection: dict) -> str:
            _record_detection(detection)
            return f"data: {json.dumps(detection)}\n\n"

        def handle_flow(event: dict) -> list[str]:
            event["kind"] = "flow"
            event["prediction"] = flow_predictor.predict(event["features"])
            event["rules"] = rules.process_flow(event)
            _record_flow(event)
            chunks = [handle_detection(detection) for detection in event["rules"]]
            chunks.append(f"data: {json.dumps(event)}\n\n")
            return chunks

        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    packet = json.loads(line)
                    _update_stats(packet)
                    timestamp = float(packet.get("ts", time.time()))
                    packet_event = dict(packet)
                    packet_event["kind"] = "packet"
                    yield f"data: {json.dumps(packet_event)}\n\n"
                    for detection in rules.process_packet(packet):
                        yield handle_detection(detection)
                    for event in tracker.expire(timestamp):
                        for chunk in handle_flow(event):
                            yield chunk
                    for event in tracker.add_packet(packet):
                        for chunk in handle_flow(event):
                            yield chunk
                except json.JSONDecodeError as exc:
                    logger.debug("Non-JSON engine line: %s  (%s)", line[:80], exc)

            for event in tracker.flush_all():
                for chunk in handle_flow(event):
                    yield chunk
        finally:
            process.stdout.close()
            process.wait()

    return StreamingResponse(generator(), media_type="text/event-stream")


# ── /rules ────────────────────────────────────────────────────────────────────
@app.get("/rules")
def get_rules() -> JSONResponse:
    """Return the rule catalog and MITRE ATT&CK metadata."""
    return JSONResponse({"rules": RULE_SPECS, "mitre": MITRE_TECHNIQUES})


# ── /mitre  (retrieval and grounded explanations) ────────────────────────────
@app.get("/mitre/status")
def mitre_status() -> JSONResponse:
    return JSONResponse({
        "loaded": mitre_kb.is_loaded,
        "technique_count": mitre_kb.technique_count,
        "error": mitre_kb.load_error,
        "source": "https://github.com/mitre-attack/attack-stix-data",
    })


@app.get("/mitre/search")
def mitre_search(q: str, top_k: int = 5) -> JSONResponse:
    if not mitre_kb.is_loaded:
        raise HTTPException(status_code=503, detail=mitre_kb.load_error or "ATT&CK knowledge base not loaded")
    top_k = max(1, min(top_k, 20))
    return JSONResponse({"query": q, "results": mitre_kb.search(q, top_k=top_k)})


@app.get("/mitre/{technique_id}")
def mitre_technique(technique_id: str) -> JSONResponse:
    if not mitre_kb.is_loaded:
        raise HTTPException(status_code=503, detail=mitre_kb.load_error or "ATT&CK knowledge base not loaded")
    technique = mitre_kb.get(technique_id)
    if technique is None:
        raise HTTPException(status_code=404, detail=f"Unknown technique: {technique_id}")
    return JSONResponse(technique)


@app.post("/explain")
def explain_alert(alert: dict) -> JSONResponse:
    if not mitre_kb.is_loaded:
        raise HTTPException(status_code=503, detail=mitre_kb.load_error or "ATT&CK knowledge base not loaded")
    result = mitre_kb.explain_alert(alert)
    status = 404 if result.get("error") else 200
    return JSONResponse(result, status_code=status)


# ── /stats ────────────────────────────────────────────────────────────────────
@app.get("/stats")
def get_stats() -> JSONResponse:
    """Accumulated packet/threat statistics since server start."""
    uptime = round(time.time() - _stats["start_time"], 1)
    # Top 10 apps by packet count
    top_apps = dict(
        sorted(_stats["top_apps"].items(), key=lambda x: x[1], reverse=True)[:10]
    )
    top_categories = dict(
        sorted(_stats["top_attack_categories"].items(), key=lambda x: x[1], reverse=True)[:10]
    )
    return JSONResponse({
        **_stats,
        "top_apps": top_apps,
        "top_attack_categories": top_categories,
        "uptime_s": uptime,
    })


# ── /threats ──────────────────────────────────────────────────────────────────
@app.get("/threats")
def get_threats() -> JSONResponse:
    """
    Returns the list of detected threats and anomalies (most recent last).
    Capped at 500 entries in memory.
    """
    return JSONResponse({"threats": _threats, "count": len(_threats)})