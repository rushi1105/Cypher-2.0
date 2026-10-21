"""Flow-level feature extraction for serving.

The feature contract must stay in sync with ml/features.py. The training
pipeline uses CICFlowMeter-style flow features, so this module aggregates the
engine's packet JSON by flow_id and approximates the same semantics.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

FEATURE_NAMES = [
    "duration_s",
    "fwd_packets",
    "bwd_packets",
    "total_packets",
    "fwd_bytes",
    "bwd_bytes",
    "total_bytes",
    "fwd_packet_size_mean",
    "bwd_packet_size_mean",
    "packet_size_mean",
    "packet_size_std",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "iat_mean",
    "iat_std",
    "flow_packets_per_sec",
    "flow_bytes_per_sec",
    "down_up_ratio",
    "syn_ratio",
    "dst_port",
    "is_well_known_port",
]

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
ETH_HEADER_LEN = 14


@dataclass
class FlowState:
    flow_id: int
    first_ts: float
    last_ts: float
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    protocol: str = ""
    app: str = ""
    sni: str = ""
    blocked: bool = False
    client_ip: str = ""
    server_ip: str = ""
    client_port: int = 0
    server_port: int = 0
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    sizes: list[int] = field(default_factory=list)
    timestamps: list[float] = field(default_factory=list)
    closed: bool = False


class FlowFeatureTracker:
    def __init__(self, idle_timeout_s: float = 30.0) -> None:
        self.idle_timeout_s = idle_timeout_s
        self._flows: dict[int, FlowState] = {}

    def add_packet(self, packet: dict) -> list[dict]:
        flow_id = int(packet["flow_id"])
        timestamp = float(packet["ts"])
        direction = str(packet.get("direction", "outbound"))
        size = max(int(packet.get("size", 0)) - ETH_HEADER_LEN, 0)
        flags = int(packet.get("flags", 0))

        state = self._flows.get(flow_id)
        if state is None:
            state = FlowState(flow_id=flow_id, first_ts=timestamp, last_ts=timestamp)
            self._flows[flow_id] = state

        state.last_ts = max(state.last_ts, timestamp)
        state.src = str(packet.get("src", state.src))
        state.dst = str(packet.get("dst", state.dst))
        state.sport = int(packet.get("sport", state.sport))
        state.dport = int(packet.get("dport", state.dport))
        state.protocol = str(packet.get("proto", state.protocol))
        state.app = str(packet.get("app", state.app))
        state.sni = str(packet.get("sni", state.sni))
        state.blocked = state.blocked or bool(packet.get("blocked", False))

        if direction == "outbound":
            state.fwd_packets += 1
            state.fwd_bytes += size
            state.client_ip = str(packet.get("src", state.client_ip))
            state.server_ip = str(packet.get("dst", state.server_ip))
            state.client_port = int(packet.get("sport", state.client_port))
            state.server_port = int(packet.get("dport", state.server_port))
        else:
            state.bwd_packets += 1
            state.bwd_bytes += size
            state.server_ip = str(packet.get("src", state.server_ip))
            state.client_ip = str(packet.get("dst", state.client_ip))
            state.server_port = int(packet.get("sport", state.server_port))
            state.client_port = int(packet.get("dport", state.client_port))

        state.sizes.append(size)
        state.timestamps.append(timestamp)
        if flags & SYN:
            state.syn_count += 1
        if flags & ACK:
            state.ack_count += 1
        if flags & FIN:
            state.fin_count += 1
        if flags & RST:
            state.rst_count += 1
        if flags & PSH:
            state.psh_count += 1
        if flags & (FIN | RST):
            state.closed = True

        events = []
        if state.closed:
            events.append(self._build_event(state))
            self._flows.pop(flow_id, None)
        return events

    def expire(self, now_ts: float) -> list[dict]:
        expired = [
            flow_id
            for flow_id, state in self._flows.items()
            if now_ts - state.last_ts >= self.idle_timeout_s
        ]
        events = []
        for flow_id in expired:
            events.append(self._build_event(self._flows.pop(flow_id)))
        return events

    def flush_all(self) -> list[dict]:
        events = [self._build_event(state) for state in self._flows.values()]
        self._flows.clear()
        return events

    def _build_event(self, state: FlowState) -> dict:
        return {
            "flow_id": state.flow_id,
            "first_ts": state.first_ts,
            "last_ts": state.last_ts,
            "src": state.client_ip or state.src,
            "dst": state.server_ip or state.dst,
            "sport": state.client_port or state.sport,
            "dport": state.server_port or state.dport,
            "proto": state.protocol,
            "app": state.app,
            "sni": state.sni,
            "blocked": state.blocked,
            "packet_count": state.fwd_packets + state.bwd_packets,
            "features": self._compute_features(state),
        }

    def _compute_features(self, state: FlowState) -> dict[str, float]:
        total_packets = state.fwd_packets + state.bwd_packets
        total_bytes = state.fwd_bytes + state.bwd_bytes
        duration = max(state.last_ts - state.first_ts, 0.0)
        sizes = state.sizes
        timestamps = sorted(state.timestamps)

        packet_size_mean = total_bytes / total_packets if total_packets else 0.0
        if len(sizes) > 1:
            variance = sum((size - packet_size_mean) ** 2 for size in sizes) / len(sizes)
            packet_size_std = math.sqrt(variance)
        else:
            packet_size_std = 0.0

        if len(timestamps) > 1:
            diffs = [
                timestamps[index + 1] - timestamps[index]
                for index in range(len(timestamps) - 1)
            ]
            iat_mean = sum(diffs) / len(diffs)
            iat_variance = sum((diff - iat_mean) ** 2 for diff in diffs) / len(diffs)
            iat_std = math.sqrt(iat_variance)
        else:
            iat_mean = 0.0
            iat_std = 0.0

        fwd_packet_size_mean = (
            state.fwd_bytes / state.fwd_packets if state.fwd_packets else 0.0
        )
        bwd_packet_size_mean = (
            state.bwd_bytes / state.bwd_packets if state.bwd_packets else 0.0
        )
        flow_packets_per_sec = total_packets / duration if duration > 0 else 0.0
        flow_bytes_per_sec = total_bytes / duration if duration > 0 else 0.0
        down_up_ratio = state.bwd_packets / max(state.fwd_packets, 1)
        syn_ratio = state.syn_count / max(total_packets, 1)
        dst_port = float(state.server_port or state.dport)

        return {
            "duration_s": duration,
            "fwd_packets": float(state.fwd_packets),
            "bwd_packets": float(state.bwd_packets),
            "total_packets": float(total_packets),
            "fwd_bytes": float(state.fwd_bytes),
            "bwd_bytes": float(state.bwd_bytes),
            "total_bytes": float(total_bytes),
            "fwd_packet_size_mean": fwd_packet_size_mean,
            "bwd_packet_size_mean": bwd_packet_size_mean,
            "packet_size_mean": packet_size_mean,
            "packet_size_std": packet_size_std,
            "syn_count": float(state.syn_count),
            "ack_count": float(state.ack_count),
            "fin_count": float(state.fin_count),
            "rst_count": float(state.rst_count),
            "psh_count": float(state.psh_count),
            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "flow_packets_per_sec": flow_packets_per_sec,
            "flow_bytes_per_sec": flow_bytes_per_sec,
            "down_up_ratio": down_up_ratio,
            "syn_ratio": syn_ratio,
            "dst_port": dst_port,
            "is_well_known_port": 1.0 if dst_port <= 1023 else 0.0,
        }
