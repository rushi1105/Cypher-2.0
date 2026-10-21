from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server.rules import MITRE_TECHNIQUES, RULE_SPECS, RuleEngine  # noqa: E402


def packet(
    ts: float,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    sport: int = 50000,
    dport: int = 80,
    proto: str = "TCP",
    flags: int = 0x02,
    size: int = 64,
    direction: str = "outbound",
    app: str = "HTTPS",
    sni: str = "",
    blocked: bool = False,
) -> dict:
    return {
        "ts": ts,
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "proto": proto,
        "flags": flags,
        "size": size,
        "direction": direction,
        "app": app,
        "sni": sni,
        "blocked": blocked,
    }


def rule_ids(events: list[dict]) -> set[str]:
    return {event["rule"] for event in events}


def test_mitre_catalog_is_complete() -> None:
    for spec in RULE_SPECS:
        assert spec["mitre"] in MITRE_TECHNIQUES
    for technique in MITRE_TECHNIQUES.values():
        assert technique["id"].startswith("T")
        assert technique["url"].startswith("https://attack.mitre.org/")


def test_port_scan() -> None:
    engine = RuleEngine()
    events = []
    for index in range(20):
        events.extend(engine.process_packet(packet(
            1000.0 + index * 0.1,
            dport=10000 + index,
        )))
    assert "port_scan" in rule_ids(events)
    event = next(item for item in events if item["rule"] == "port_scan")
    assert event["severity"] == "high"
    assert event["mitre"]["id"] == "T1046"
    assert event["evidence"]["unique_ports"] == 20


def test_syn_flood() -> None:
    engine = RuleEngine()
    events = []
    for index in range(50):
        events.extend(engine.process_packet(packet(
            2000.0 + index * 0.05,
            dport=80,
            flags=0x02,
        )))
    assert "syn_flood" in rule_ids(events)
    event = next(item for item in events if item["rule"] == "syn_flood")
    assert event["mitre"]["id"] == "T1498"


def test_dns_flood() -> None:
    engine = RuleEngine()
    events = []
    for index in range(50):
        events.extend(engine.process_packet(packet(
            3000.0 + index * 0.05,
            dport=53,
            proto="UDP",
            flags=0,
            app="DNS",
        )))
    assert "dns_flood" in rule_ids(events)
    event = next(item for item in events if item["rule"] == "dns_flood")
    assert event["mitre"]["id"] == "T1498"


def test_suspicious_port_and_dedup() -> None:
    engine = RuleEngine()
    first = engine.process_packet(packet(4000.0, dport=4444))
    second = engine.process_packet(packet(4000.1, dport=4444))
    assert "suspicious_port" in rule_ids(first)
    assert "suspicious_port" not in rule_ids(second)
    event = next(item for item in first if item["rule"] == "suspicious_port")
    assert event["mitre"]["id"] == "T1571"


def test_brute_force() -> None:
    engine = RuleEngine()
    events = []
    for index in range(10):
        events.extend(engine.process_packet(packet(
            5000.0 + index,
            dport=22,
            flags=0x02,
        )))
    assert "brute_force" in rule_ids(events)
    assert "beaconing" not in rule_ids(events)
    event = next(item for item in events if item["rule"] == "brute_force")
    assert event["mitre"]["id"] == "T1110"


def test_beaconing() -> None:
    engine = RuleEngine()
    events = []
    for index in range(8):
        events.extend(engine.process_packet(packet(
            6000.0 + index * 5.0,
            dport=443,
            flags=0x18,
        )))
    assert "beaconing" in rule_ids(events)
    event = next(item for item in events if item["rule"] == "beaconing")
    assert event["mitre"]["id"] == "T1071"


def test_blocked_domain() -> None:
    engine = RuleEngine()
    events = engine.process_packet(packet(
        7000.0,
        dport=443,
        app="HTTPS",
        sni="blocked.example",
        blocked=True,
    ))
    assert "blocked_domain" in rule_ids(events)
    event = next(item for item in events if item["rule"] == "blocked_domain")
    assert event["mitre"]["id"] == "T1071.001"


def test_data_exfiltration_flow() -> None:
    engine = RuleEngine()
    flow = {
        "flow_id": 1,
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "dport": 443,
        "last_ts": 8000.0,
        "features": {"fwd_bytes": 10_000_000, "bwd_bytes": 1_000},
    }
    events = engine.process_flow(flow)
    assert rule_ids(events) == {"data_exfiltration"}
    assert events[0]["mitre"]["id"] == "T1048"


def test_dominant_talker() -> None:
    engine = RuleEngine()
    events = []
    for index in range(100):
        events.extend(engine.process_packet(packet(
            9000.0 + index * 0.3,
            src="10.0.0.9",
            dst="10.0.0.2",
            dport=443,
            flags=0x18,
            size=1500,
        )))
    for index in range(10):
        events.extend(engine.process_packet(packet(
            9000.0 + index * 0.3,
            src="10.0.0.10",
            dst="10.0.0.2",
            dport=443,
            flags=0x18,
            size=100,
        )))
    assert "dominant_talker" in rule_ids(events)
    event = next(item for item in events if item["rule"] == "dominant_talker")
    assert event["severity"] == "low"
    assert event["mitre"]["id"] == "T1498"
