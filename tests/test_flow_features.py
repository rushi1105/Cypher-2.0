from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.features import FEATURE_NAMES as TRAINING_FEATURES  # noqa: E402
from server.flow_features import FEATURE_NAMES as SERVING_FEATURES  # noqa: E402
from server.flow_features import FlowFeatureTracker  # noqa: E402


def packet(
    flow_id: int,
    ts: float,
    direction: str,
    src: str,
    dst: str,
    sport: int,
    dport: int,
    size: int,
    flags: int,
) -> dict:
    return {
        "flow_id": flow_id,
        "ts": ts,
        "direction": direction,
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "size": size,
        "flags": flags,
        "proto": "TCP",
        "app": "HTTPS",
        "sni": "",
        "blocked": False,
    }


def test_feature_contract_matches_training() -> None:
    assert SERVING_FEATURES == TRAINING_FEATURES


def test_flow_feature_values() -> None:
    tracker = FlowFeatureTracker()
    client = "192.168.1.100"
    server = "142.250.185.110"
    packets = [
        packet(1, 1000.0, "outbound", client, server, 50000, 443, 100, 0x02),
        packet(1, 1000.1, "inbound", server, client, 443, 50000, 80, 0x12),
        packet(1, 1000.2, "outbound", client, server, 50000, 443, 120, 0x18),
        packet(1, 1000.4, "inbound", server, client, 443, 50000, 60, 0x10),
    ]
    for item in packets:
        assert tracker.add_packet(item) == []

    events = tracker.flush_all()
    assert len(events) == 1
    event = events[0]
    features = event["features"]

    assert event["src"] == client
    assert event["dst"] == server
    assert event["sport"] == 50000
    assert event["dport"] == 443
    assert features["fwd_packets"] == 2
    assert features["bwd_packets"] == 2
    assert features["total_packets"] == 4
    assert features["fwd_bytes"] == 86 + 106
    assert features["bwd_bytes"] == 66 + 46
    assert features["total_bytes"] == 304
    assert features["packet_size_mean"] == pytest.approx(76.0)
    assert features["packet_size_std"] == pytest.approx(22.3607, rel=1e-3)
    assert features["syn_count"] == 2
    assert features["ack_count"] == 3
    assert features["psh_count"] == 1
    assert features["fin_count"] == 0
    assert features["rst_count"] == 0
    assert features["duration_s"] == pytest.approx(0.4)
    assert features["iat_mean"] == pytest.approx(0.133333, rel=1e-3)
    assert features["iat_std"] == pytest.approx(0.04714, rel=1e-2)
    assert features["flow_packets_per_sec"] == pytest.approx(10.0)
    assert features["flow_bytes_per_sec"] == pytest.approx(760.0)
    assert features["down_up_ratio"] == pytest.approx(1.0)
    assert features["syn_ratio"] == pytest.approx(0.5)
    assert features["dst_port"] == 443
    assert features["is_well_known_port"] == 1.0


def test_fin_closes_flow() -> None:
    tracker = FlowFeatureTracker()
    base = packet(2, 1000.0, "outbound", "10.0.0.1", "10.0.0.2", 50000, 80, 64, 0x02)
    assert tracker.add_packet(base) == []
    fin = packet(2, 1000.1, "outbound", "10.0.0.1", "10.0.0.2", 50000, 80, 54, 0x11)
    events = tracker.add_packet(fin)
    assert len(events) == 1
    assert tracker.flush_all() == []
