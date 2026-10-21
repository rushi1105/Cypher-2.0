#!/usr/bin/env python3
"""Generate a small synthetic attack PCAP for rule-engine demos."""

from __future__ import annotations

import struct
from pathlib import Path

import generate_test_pcap as gen

OUTPUT = Path(__file__).resolve().parent / "test_attack.pcap"
BASE_TS = 1_700_000_000.0


class Writer:
    def __init__(self, path: Path) -> None:
        self.file = path.open("wb")
        self.file.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def write(self, data: bytes, offset_s: float) -> None:
        timestamp = BASE_TS + offset_s
        seconds = int(timestamp)
        microseconds = int((timestamp - seconds) * 1_000_000)
        self.file.write(struct.pack("<IIII", seconds, microseconds, len(data), len(data)))
        self.file.write(data)

    def close(self) -> None:
        self.file.close()


def frame(src_ip: str, dst_ip: str, sport: int, dport: int, flags: int,
          payload: bytes = b"", proto: int = 6) -> bytes:
    if proto == 6:
        transport = gen.create_tcp_header(sport, dport, 1000, 0, flags)
    else:
        transport = gen.create_udp_header(sport, dport, len(payload))
    ip = gen.create_ip_header(src_ip, dst_ip, proto, len(transport) + len(payload))
    eth = gen.create_ethernet_header("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff")
    return eth + ip + transport + payload


def main() -> int:
    writer = Writer(OUTPUT)

    for index in range(30):
        writer.write(
            frame("10.0.0.66", "192.168.1.10", 50000, 10000 + index, 0x02),
            index * 1.0,
        )

    for index in range(60):
        writer.write(
            frame("10.0.0.77", "192.168.1.10", 50001, 80, 0x02),
            index * 0.05,
        )

    for index in range(60):
        query = gen.create_dns_query("example.com")
        writer.write(
            frame("10.0.0.88", "8.8.8.8", 50002 + index, 53, 0, query, proto=17),
            index * 0.05,
        )

    writer.write(frame("10.0.0.99", "192.168.1.10", 50003, 4444, 0x02), 5.0)

    for index in range(12):
        writer.write(
            frame("10.0.0.111", "192.168.1.10", 50004, 22, 0x02),
            10.0 + index * 1.0,
        )

    for index in range(10):
        writer.write(
            frame("10.0.0.123", "203.0.113.5", 50005, 443, 0x18),
            20.0 + index * 5.0,
        )

    writer.close()
    print(f"Wrote {OUTPUT}")
    print("Expected detections: port_scan, syn_flood, dns_flood, suspicious_port, brute_force, beaconing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
