import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "engine" / "dpi_simple.exe"
DEFAULT_PCAP = ROOT / "engine" / "test_dpi.pcap"

sys.path.insert(0, str(ROOT / "engine"))
import generate_test_pcap as gen  # noqa: E402


REQUIRED_KEYS = {
    "ts", "src", "dst", "sport", "dport", "proto", "app", "sni",
    "blocked", "size", "flags", "payload_len", "direction", "flow_id",
    "block_reason",
}


def run_engine(tmp_path: Path, pcap: Path = DEFAULT_PCAP, *args: str) -> list[dict]:
    if not ENGINE.exists():
        pytest.skip(f"Engine binary missing: {ENGINE}. Run scripts/build-engine.ps1 first.")
    output = tmp_path / "filtered.pcap"
    result = subprocess.run(
        [str(ENGINE), str(pcap), str(output), "--json", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    packets = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert packets, "engine emitted no JSON packets"
    return packets


def assert_contract(packets: list[dict]) -> None:
    for packet in packets:
        assert REQUIRED_KEYS <= packet.keys(), packet
        assert packet["direction"] in {"outbound", "inbound"}, packet
        assert packet["proto"] in {"TCP", "UDP", "OTHER"}, packet
        assert isinstance(packet["size"], int) and packet["size"] > 0, packet
        assert isinstance(packet["flags"], int) and packet["flags"] >= 0, packet
        assert isinstance(packet["payload_len"], int) and packet["payload_len"] >= 0, packet
        assert isinstance(packet["flow_id"], int) and packet["flow_id"] > 0, packet
        assert isinstance(packet["blocked"], bool), packet


def test_json_contract_and_bidirectional_flow(tmp_path: Path) -> None:
    packets = run_engine(tmp_path)
    assert len(packets) == 77
    assert_contract(packets)

    youtube = [p for p in packets if p["sni"] == "www.youtube.com" and p["proto"] == "TCP"]
    assert youtube, "YouTube TLS packet missing"
    client_hello = youtube[0]
    assert client_hello["app"] == "YouTube"
    assert client_hello["direction"] == "outbound"
    assert client_hello["payload_len"] > 0
    assert client_hello["flags"] & 0x10

    reverse = [
        p for p in packets
        if p["src"] == client_hello["dst"]
        and p["dst"] == client_hello["src"]
        and p["sport"] == client_hello["dport"]
        and p["dport"] == client_hello["sport"]
    ]
    assert reverse, "reverse-direction packet missing"
    assert all(p["flow_id"] == client_hello["flow_id"] for p in reverse)
    assert any(p["direction"] == "inbound" for p in reverse)

    netflix = [p for p in packets if p["sni"] == "www.netflix.com"]
    assert netflix and netflix[0]["app"] == "Netflix"
    twitter = [p for p in packets if p["sni"] == "twitter.com"]
    assert twitter and twitter[0]["app"] == "Twitter/X"


def test_dns_qname_extraction(tmp_path: Path) -> None:
    packets = run_engine(tmp_path)
    dns_packets = [p for p in packets if p["proto"] == "UDP" and p["dport"] == 53]
    assert len(dns_packets) == 4
    domains = {p["sni"] for p in dns_packets}
    assert domains == {
        "www.google.com",
        "www.youtube.com",
        "www.facebook.com",
        "api.twitter.com",
    }
    assert all(p["app"] == "DNS" for p in dns_packets)
    assert all(p["payload_len"] > 0 for p in dns_packets)


def test_block_app_youtube_blocks_tls_and_dns(tmp_path: Path) -> None:
    packets = run_engine(tmp_path, DEFAULT_PCAP, "--block-app", "YouTube")
    youtube = [p for p in packets if p["sni"] == "www.youtube.com"]
    assert len(youtube) == 2
    assert all(p["blocked"] for p in youtube)
    assert all(p["block_reason"] == "rule" for p in youtube)
    assert any(p["app"] == "YouTube" for p in youtube)
    assert any(p["app"] == "DNS" for p in youtube)


def test_block_domain_wildcard(tmp_path: Path) -> None:
    packets = run_engine(tmp_path, DEFAULT_PCAP, "--block-domain", "*.youtube.com")
    youtube = [p for p in packets if p["sni"] == "www.youtube.com"]
    assert youtube
    assert all(p["blocked"] for p in youtube)


def test_block_ip_blocks_both_endpoints(tmp_path: Path) -> None:
    packets = run_engine(tmp_path, DEFAULT_PCAP, "--block-ip", "192.168.1.50")
    blocked_source = [p for p in packets if p["src"] == "192.168.1.50"]
    assert len(blocked_source) == 5
    assert all(p["blocked"] for p in blocked_source)


def test_bidirectional_blocking_on_synthetic_flow(tmp_path: Path) -> None:
    pcap = tmp_path / "bidirectional.pcap"
    writer = gen.PCAPWriter(str(pcap))
    user_mac = "00:11:22:33:44:55"
    gateway_mac = "aa:bb:cc:dd:ee:ff"
    user_ip = "192.168.1.100"
    server_ip = "142.250.185.110"
    sport, dport = 50000, 443
    seq = 1000

    eth = gen.create_ethernet_header(user_mac, gateway_mac)
    tcp = gen.create_tcp_header(sport, dport, seq, 0, 0x02)
    ip = gen.create_ip_header(user_ip, server_ip, 6, len(tcp))
    writer.write_packet(eth + ip + tcp)

    eth = gen.create_ethernet_header(gateway_mac, user_mac)
    tcp = gen.create_tcp_header(dport, sport, seq + 1000, seq + 1, 0x12)
    ip = gen.create_ip_header(server_ip, user_ip, 6, len(tcp))
    writer.write_packet(eth + ip + tcp)

    eth = gen.create_ethernet_header(user_mac, gateway_mac)
    tcp = gen.create_tcp_header(sport, dport, seq + 1, seq + 1001, 0x10)
    ip = gen.create_ip_header(user_ip, server_ip, 6, len(tcp))
    writer.write_packet(eth + ip + tcp)

    tls = gen.create_tls_client_hello("www.youtube.com")
    eth = gen.create_ethernet_header(user_mac, gateway_mac)
    tcp = gen.create_tcp_header(sport, dport, seq + 1, seq + 1001, 0x18)
    ip = gen.create_ip_header(user_ip, server_ip, 6, len(tcp) + len(tls))
    writer.write_packet(eth + ip + tcp + tls)

    payload = b"hello"
    eth = gen.create_ethernet_header(gateway_mac, user_mac)
    tcp = gen.create_tcp_header(dport, sport, seq + 1001, seq + 1 + len(tls), 0x18)
    ip = gen.create_ip_header(server_ip, user_ip, 6, len(tcp) + len(payload))
    writer.write_packet(eth + ip + tcp + payload)
    writer.close()

    packets = run_engine(tmp_path, pcap, "--block-app", "YouTube")
    assert len(packets) == 5
    assert len({p["flow_id"] for p in packets}) == 1
    assert {p["direction"] for p in packets} == {"outbound", "inbound"}
    client_hello = [p for p in packets if p["sni"] == "www.youtube.com"][0]
    assert client_hello["blocked"] is True
    assert client_hello["block_reason"] == "rule"
    assert packets[-1]["direction"] == "inbound"
    assert packets[-1]["blocked"] is True
