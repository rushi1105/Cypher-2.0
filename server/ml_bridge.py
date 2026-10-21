"""
ml_bridge.py
------------
Sliding-window buffer that consumes individual packet dicts (as emitted
by the C++ DPI engine in --json mode) and returns a computed feature
vector once a full window of WINDOW_SIZE packets is accumulated.

Engine packet schema
--------------------
{
  "ts":      float,    -- UNIX timestamp
  "src":     str,      -- source IP
  "dst":     str,      -- destination IP
  "sport":   int,      -- source port
  "dport":   int,      -- destination port
  "proto":   str,      -- "TCP" | "UDP" | "ICMP" | ...
  "app":     str,      -- DPI app label
  "sni":     str,      -- TLS SNI (empty string if N/A)
  "blocked": bool,     -- engine blocked this packet
  "size":    int,      -- [Phase 3] total packet bytes  (optional, estimated if absent)
  "flags":   int,      -- [Phase 3] TCP flags byte      (optional, estimated if absent)
}

Output feature schema (11 features — matches ML model training)
---------------------------------------------------------------
{
  "packet_count":          int,
  "avg_packet_size":       float,
  "tcp_count":             int,
  "udp_count":             int,
  "unique_ips":            int,
  "syn_count":             int,
  "tcp_ratio":             float,
  "syn_ratio":             float,
  "packet_size_std":       float,
  "avg_interarrival_time": float,
  "unique_ports":          float,
}
"""

from __future__ import annotations

import logging
import math
from collections import deque
from typing import Optional

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────
WINDOW_SIZE = 25          # must match ML training window size
SYN_FLAG    = 0x02        # TCP SYN bit

# Port → estimated packet-size heuristics (used only when engine doesn't send "size")
_PORT_SIZE_ESTIMATE = {
    53:   80,    # DNS
    80:   512,   # HTTP
    443:  900,   # HTTPS / TLS
    8080: 512,
    8443: 900,
    25:   300,   # SMTP
    22:   200,   # SSH
    21:   150,   # FTP control
}
_DEFAULT_SIZE = 500       # fallback when port not in table


def _estimate_size(packet: dict) -> int:
    """
    Return a best-effort packet size estimate when the engine doesn't
    emit the "size" field.  Once Phase 3 engine changes land this is never called.
    """
    dport = packet.get("dport", 0)
    sport = packet.get("sport", 0)
    return _PORT_SIZE_ESTIMATE.get(dport) or _PORT_SIZE_ESTIMATE.get(sport) or _DEFAULT_SIZE


class PacketWindowBuffer:
    """
    Accumulates packets into fixed-size windows and computes the 11
    features the ML model expects once a window is full.

    Usage
    -----
        buf = PacketWindowBuffer()
        for raw_packet in engine_stream:
            result = buf.add_packet(raw_packet)
            if result is not None:
                features, packets, window_id = result
                prediction = predictor.predict(features)
    """

    def __init__(self, window_size: int = WINDOW_SIZE) -> None:
        self.window_size   = window_size
        self._window: deque[dict] = deque()
        self._window_id    = 0

    def reset(self) -> None:
        self._window.clear()

    @property
    def buffer_size(self) -> int:
        return len(self._window)

    # ── Public API ─────────────────────────────────────────────────────────────
    def add_packet(
        self, packet: dict
    ) -> Optional[tuple[dict, list[dict], int]]:
        """
        Add a single parsed packet dict to the internal window buffer.

        Returns
        -------
        None
            If the window is not yet full.
        (feature_dict, packet_list, window_id)
            When the window reaches WINDOW_SIZE.
            feature_dict  → 11 computed features ready for ML inference
            packet_list   → the raw packets that make up this window (copy)
            window_id     → monotonically increasing int (useful for dashboard)
        """
        self._window.append(packet)

        if len(self._window) < self.window_size:
            return None

        # Window full — compute features, clear, return
        packets = list(self._window)
        self._window.clear()
        self._window_id += 1

        features = self._compute_features(packets)
        return features, packets, self._window_id

    def flush_partial(self) -> tuple[list[dict], int]:
        """
        Return the packets left in a partial window at stream end.

        The partial window is cleared and the window id is advanced so callers
        can label those packets as Pending without reusing a completed id.
        """
        if not self._window:
            return [], self._window_id

        packets = list(self._window)
        self._window.clear()
        self._window_id += 1
        return packets, self._window_id

    # ── Feature computation ────────────────────────────────────────────────────
    def _compute_features(self, packets: list[dict]) -> dict:
        """
        Compute all 11 features from a window of packet dicts.
        """
        n = len(packets)

        # ── Packet sizes ───────────────────────────────────────────────────────
        sizes = [
            int(p.get("size", _estimate_size(p)))
            for p in packets
        ]
        avg_size = sum(sizes) / n
        # Standard deviation (sample, ddof=1)
        if n > 1:
            variance = sum((s - avg_size) ** 2 for s in sizes) / (n - 1)
            size_std = math.sqrt(variance)
        else:
            size_std = 0.0

        # ── Protocol counts ────────────────────────────────────────────────────
        tcp_count = sum(1 for p in packets if p.get("proto", "").upper() == "TCP")
        udp_count = sum(1 for p in packets if p.get("proto", "").upper() == "UDP")

        # ── SYN count ─────────────────────────────────────────────────────────
        # Use "flags" if engine emits it (Phase 3), otherwise fall back to 0
        syn_count = sum(
            1 for p in packets
            if (int(p.get("flags", 0)) & SYN_FLAG) != 0
        )

        # ── Unique IPs ─────────────────────────────────────────────────────────
        ip_set: set[str] = set()
        for p in packets:
            src = p.get("src", "")
            dst = p.get("dst", "")
            if src:
                ip_set.add(src)
            if dst:
                ip_set.add(dst)
        unique_ips = len(ip_set)

        # ── Unique destination ports ───────────────────────────────────────────
        unique_ports = len({p.get("dport", 0) for p in packets})

        # ── Inter-arrival times ────────────────────────────────────────────────
        timestamps = sorted(
            [float(p["ts"]) for p in packets if "ts" in p]
        )
        if len(timestamps) > 1:
            diffs = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]
            avg_interarrival = sum(diffs) / len(diffs)
        else:
            avg_interarrival = 0.0

        # ── Ratio features ─────────────────────────────────────────────────────
        pc          = max(n, 1)    # avoid division by zero
        tcp_ratio   = tcp_count / pc
        syn_ratio   = syn_count / pc

        return {
            "packet_count":          n,
            "avg_packet_size":       round(avg_size, 4),
            "tcp_count":             tcp_count,
            "udp_count":             udp_count,
            "unique_ips":            unique_ips,
            "syn_count":             syn_count,
            "tcp_ratio":             round(tcp_ratio, 4),
            "syn_ratio":             round(syn_ratio, 4),
            "packet_size_std":       round(size_std, 4),
            "avg_interarrival_time": round(avg_interarrival, 6),
            "unique_ports":          unique_ports,
        }
