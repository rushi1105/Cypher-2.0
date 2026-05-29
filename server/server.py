"""
server.py — Cypher 2.0 FastAPI Bridge
======================================
Connects the C++ DPI engine (Cypher 1.0) with the ML threat detection
model via three streaming/REST endpoints:

  GET /health            → liveness check
  GET /stream            → raw NDJSON SSE (one event per packet, no ML)
  GET /stream/enriched   → ML-enriched SSE (ML result appended to each packet)
  GET /stream/windows    → SSE window events (one per 25 packets, includes ML prediction)
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

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse

from ml_bridge    import PacketWindowBuffer
from ml_predictor import predictor

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

ENGINE_CMD = [
    str(ENGINE_BIN),
    str(ENGINE_PCAP),
    str(ENGINE_OUT),
    "--json",
]

SHIM_CMD = [
    sys.executable,       # same Python that runs this server
    str(ENGINE_SHIM),
    str(ENGINE_PCAP),
    str(ENGINE_OUT),
]

# ── Startup: load ML models ────────────────────────────────────────────────────
predictor.load()


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
    "total_packets":      0,
    "total_windows":      0,
    "attacks_detected":   0,
    "anomalies_detected": 0,
    "blocked_packets":    0,
    "top_apps":           {},
    "start_time":         time.time(),
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
            "window_id":     window_id,
            "timestamp":     time.time(),
            "prediction":    prediction,
            "features":      features,
        })
        # Keep last 500 threats in memory
        if len(_threats) > 500:
            _threats.pop(0)


# ── Engine process factory ─────────────────────────────────────────────────────
def _spawn_engine() -> subprocess.Popen | None:
    """
    Spawn the DPI engine subprocess.
    Prefers the C++ binary; falls back to the Python shim automatically.
    Returns the Popen object, or None if neither is available.
    """
    if _USE_SHIM:
        if not ENGINE_SHIM.exists():
            logger.error("Neither engine binary nor Python shim found")
            return None
        cmd = SHIM_CMD
        logger.info("Spawning Python shim: %s", " ".join(cmd))
    else:
        cmd = ENGINE_CMD
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
        "uptime_s":       round(time.time() - _stats["start_time"], 1),
    })


# ── /stream  (raw, no ML) ──────────────────────────────────────────────────────
@app.get("/stream")
def stream_packets() -> StreamingResponse:
    """
    Raw SSE stream — one event per packet as emitted by the DPI engine.
    No ML enrichment.  Keeps backward compatibility.
    """

    def generator() -> Generator[str, None, None]:
        process = _spawn_engine()
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
def stream_enriched() -> StreamingResponse:
    """
    SSE stream — every packet carries an "ml" block with the result of the
    most-recently-completed window prediction.  Within a window, packets share
    the same prediction (they belong to the same 25-packet cohort).

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
        process = _spawn_engine()
        if process is None:
            yield "data: {\"error\": \"engine binary not found\"}\n\n"
            return

        buf = PacketWindowBuffer()
        # Start with a neutral "not yet predicted" ML block
        last_prediction: dict = {
            "label":         "Pending",
            "confidence":    0.0,
            "is_threat":     False,
            "anomaly_score": 0.0,
            "is_anomaly":    False,
            "window_id":     0,
            "model_active":  predictor.is_loaded,
        }

        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    packet = json.loads(line)
                    _update_stats(packet)

                    # Feed into window buffer
                    result = buf.add_packet(packet)
                    if result is not None:
                        features, _packets, window_id = result
                        pred = predictor.predict(features)
                        pred["window_id"] = window_id
                        _record_threat(window_id, features, pred)
                        last_prediction = pred

                    enriched = dict(packet)
                    enriched["ml"] = last_prediction
                    yield f"data: {json.dumps(enriched)}\n\n"

                except json.JSONDecodeError as exc:
                    logger.debug("Non-JSON engine line: %s  (%s)", line[:80], exc)
        finally:
            process.stdout.close()
            process.wait()

    return StreamingResponse(generator(), media_type="text/event-stream")


# ── /stream/windows  (window-level events) ────────────────────────────────────
@app.get("/stream/windows")
def stream_windows() -> StreamingResponse:
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
        process = _spawn_engine()
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


# ── /stats ────────────────────────────────────────────────────────────────────
@app.get("/stats")
def get_stats() -> JSONResponse:
    """Accumulated packet/threat statistics since server start."""
    uptime = round(time.time() - _stats["start_time"], 1)
    # Top 10 apps by packet count
    top_apps = dict(
        sorted(_stats["top_apps"].items(), key=lambda x: x[1], reverse=True)[:10]
    )
    return JSONResponse({
        **_stats,
        "top_apps":  top_apps,
        "uptime_s":  uptime,
    })


# ── /threats ──────────────────────────────────────────────────────────────────
@app.get("/threats")
def get_threats() -> JSONResponse:
    """
    Returns the list of detected threats and anomalies (most recent last).
    Capped at 500 entries in memory.
    """
    return JSONResponse({"threats": _threats, "count": len(_threats)})