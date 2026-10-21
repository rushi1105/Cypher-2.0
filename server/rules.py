"""Deterministic rule detectors with MITRE ATT&CK mapping."""

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10

SUSPICIOUS_PORTS = {23, 4444, 6666, 13337, 31337}
AUTH_PORTS = {21, 22, 23, 3389}

MITRE_TECHNIQUES = {
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1498": {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1498/",
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1571": {
        "id": "T1571",
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1571/",
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "T1071.001": {
        "id": "T1071.001",
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "T1071.004": {
        "id": "T1071.004",
        "name": "DNS",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/004/",
    },
    "T1048": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1048/",
    },
    "T1595": {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/",
    },
}

RULE_SPECS = [
    {"id": "port_scan", "title": "Possible port scan", "severity": "high", "mitre": "T1046",
     "description": "One source contacted many unique destination ports in a short window."},
    {"id": "syn_flood", "title": "Possible SYN flood", "severity": "high", "mitre": "T1498",
     "description": "A source sent an unusually high number of SYN packets in a short window."},
    {"id": "dns_flood", "title": "Possible DNS flood", "severity": "medium", "mitre": "T1498",
     "description": "A source sent an unusually high number of DNS queries in a short window."},
    {"id": "brute_force", "title": "Possible authentication brute force", "severity": "high", "mitre": "T1110",
     "description": "Repeated connection attempts to an authentication service."},
    {"id": "suspicious_port", "title": "Traffic to a suspicious port", "severity": "high", "mitre": "T1571",
     "description": "Traffic used a port commonly associated with backdoors or non-standard C2."},
    {"id": "beaconing", "title": "Possible beaconing", "severity": "medium", "mitre": "T1071",
     "description": "Regular, low-variance connection intervals to the same destination."},
    {"id": "dominant_talker", "title": "Dominant talker", "severity": "low", "mitre": "T1498",
     "description": "One source dominates recent traffic volume."},
    {"id": "data_exfiltration", "title": "Possible data exfiltration", "severity": "high", "mitre": "T1048",
     "description": "A flow sent a large outbound payload relative to inbound traffic."},
    {"id": "blocked_domain", "title": "Blocked domain observed", "severity": "medium", "mitre": "T1071.001",
     "description": "Traffic matched a blocked domain or application rule."},
]


@dataclass
class PacketObservation:
    ts: float
    dport: int
    sport: int
    proto: str
    flags: int
    size: int
    direction: str
    src: str
    dst: str
    app: str
    sni: str
    blocked: bool


class RuleEngine:
    def __init__(
        self,
        port_scan_unique_ports: int = 20,
        port_scan_window_s: float = 60.0,
        syn_flood_count: int = 50,
        syn_flood_window_s: float = 5.0,
        dns_flood_count: int = 50,
        dns_flood_window_s: float = 5.0,
        brute_force_count: int = 10,
        brute_force_window_s: float = 60.0,
        dominant_min_packets: int = 100,
        dominant_window_s: float = 60.0,
        dominant_share: float = 0.50,
        beacon_min_samples: int = 8,
        beacon_max_cv: float = 0.20,
        beacon_min_interval_s: float = 0.5,
        beacon_max_interval_s: float = 300.0,
        suppression_s: float = 60.0,
    ) -> None:
        self.port_scan_unique_ports = port_scan_unique_ports
        self.port_scan_window_s = port_scan_window_s
        self.syn_flood_count = syn_flood_count
        self.syn_flood_window_s = syn_flood_window_s
        self.dns_flood_count = dns_flood_count
        self.dns_flood_window_s = dns_flood_window_s
        self.brute_force_count = brute_force_count
        self.brute_force_window_s = brute_force_window_s
        self.dominant_min_packets = dominant_min_packets
        self.dominant_window_s = dominant_window_s
        self.dominant_share = dominant_share
        self.beacon_min_samples = beacon_min_samples
        self.beacon_max_cv = beacon_max_cv
        self.beacon_min_interval_s = beacon_min_interval_s
        self.beacon_max_interval_s = beacon_max_interval_s
        self.suppression_s = suppression_s

        self._by_source: dict[str, deque[PacketObservation]] = defaultdict(deque)
        self._dominant: deque[PacketObservation] = deque()
        self._beacon: dict[tuple[str, str, int], deque[float]] = defaultdict(deque)
        self._last_emitted: dict[tuple[str, str], float] = {}

    def process_packet(self, packet: dict) -> list[dict]:
        observation = PacketObservation(
            ts=float(packet.get("ts", 0.0)),
            dport=int(packet.get("dport", 0)),
            sport=int(packet.get("sport", 0)),
            proto=str(packet.get("proto", "")),
            flags=int(packet.get("flags", 0)),
            size=int(packet.get("size", 0)),
            direction=str(packet.get("direction", "outbound")),
            src=str(packet.get("src", "")),
            dst=str(packet.get("dst", "")),
            app=str(packet.get("app", "")),
            sni=str(packet.get("sni", "")),
            blocked=bool(packet.get("blocked", False)),
        )

        events: list[dict] = []
        if observation.blocked and observation.sni:
            if self._allow("blocked_domain", f"{observation.src}|{observation.sni}", observation.ts):
                events.append(self._event(
                    "blocked_domain",
                    observation.ts,
                    observation.src,
                    observation.dst,
                    observation.dport,
                    observation,
                    {"sni": observation.sni, "app": observation.app, "blocked": True},
                ))

        if observation.direction == "outbound":
            if observation.dport in SUSPICIOUS_PORTS or observation.sport in SUSPICIOUS_PORTS:
                if self._allow("suspicious_port", f"{observation.src}|{observation.dst}|{observation.dport}", observation.ts):
                    events.append(self._event(
                        "suspicious_port",
                        observation.ts,
                        observation.src,
                        observation.dst,
                        observation.dport,
                        observation,
                        {"suspicious_ports": sorted(SUSPICIOUS_PORTS)},
                    ))

            source_history = self._by_source[observation.src]
            source_history.append(observation)
            self._prune(source_history, observation.ts - self.port_scan_window_s)

            ports = {
                item.dport for item in source_history
                if item.ts >= observation.ts - self.port_scan_window_s
                and item.direction == "outbound"
                and item.dport > 0
            }
            if len(ports) >= self.port_scan_unique_ports:
                if self._allow("port_scan", observation.src, observation.ts):
                    events.append(self._event(
                        "port_scan",
                        observation.ts,
                        observation.src,
                        observation.dst,
                        observation.dport,
                        observation,
                        {"unique_ports": len(ports), "sample_ports": sorted(ports)[:10],
                         "window_s": self.port_scan_window_s},
                    ))

            recent_syn = sum(
                1 for item in source_history
                if item.ts >= observation.ts - self.syn_flood_window_s
                and item.direction == "outbound"
                and item.flags & SYN
            )
            if recent_syn >= self.syn_flood_count:
                if self._allow("syn_flood", observation.src, observation.ts):
                    events.append(self._event(
                        "syn_flood",
                        observation.ts,
                        observation.src,
                        observation.dst,
                        observation.dport,
                        observation,
                        {"syn_count": recent_syn, "window_s": self.syn_flood_window_s},
                    ))

            recent_dns = sum(
                1 for item in source_history
                if item.ts >= observation.ts - self.dns_flood_window_s
                and item.direction == "outbound"
                and item.proto.upper() == "UDP"
                and (item.dport == 53 or item.sport == 53)
            )
            if recent_dns >= self.dns_flood_count:
                if self._allow("dns_flood", observation.src, observation.ts):
                    events.append(self._event(
                        "dns_flood",
                        observation.ts,
                        observation.src,
                        observation.dst,
                        observation.dport,
                        observation,
                        {"dns_count": recent_dns, "window_s": self.dns_flood_window_s},
                    ))

            recent_auth = sum(
                1 for item in source_history
                if item.ts >= observation.ts - self.brute_force_window_s
                and item.direction == "outbound"
                and item.flags & SYN
                and item.dport in AUTH_PORTS
            )
            if recent_auth >= self.brute_force_count:
                if self._allow("brute_force", f"{observation.src}|{observation.dport}", observation.ts):
                    events.append(self._event(
                        "brute_force",
                        observation.ts,
                        observation.src,
                        observation.dst,
                        observation.dport,
                        observation,
                        {"attempts": recent_auth, "port": observation.dport,
                         "window_s": self.brute_force_window_s},
                    ))

            beacon_key = (observation.src, observation.dst, observation.dport)
            beacon_history = self._beacon[beacon_key]
            beacon_history.append(observation.ts)
            self._prune_timestamps(beacon_history, observation.ts - self.beacon_max_interval_s)
            if len(beacon_history) >= self.beacon_min_samples and observation.dport not in AUTH_PORTS:
                diffs = [
                    beacon_history[index + 1] - beacon_history[index]
                    for index in range(len(beacon_history) - 1)
                ]
                mean_interval = sum(diffs) / len(diffs)
                if self.beacon_min_interval_s <= mean_interval <= self.beacon_max_interval_s:
                    variance = sum((value - mean_interval) ** 2 for value in diffs) / len(diffs)
                    cv = math.sqrt(variance) / mean_interval if mean_interval else 1.0
                    if cv <= self.beacon_max_cv:
                        if self._allow("beaconing", f"{observation.src}|{observation.dst}|{observation.dport}", observation.ts):
                            events.append(self._event(
                                "beaconing",
                                observation.ts,
                                observation.src,
                                observation.dst,
                                observation.dport,
                                observation,
                                {"samples": len(beacon_history), "mean_interval_s": round(mean_interval, 3),
                                 "interval_cv": round(cv, 3)},
                            ))

        self._dominant.append(observation)
        self._prune(self._dominant, observation.ts - self.dominant_window_s)
        if len(self._dominant) >= self.dominant_min_packets:
            totals: dict[str, int] = defaultdict(int)
            for item in self._dominant:
                totals[item.src] += item.size
            top_source, top_bytes = max(totals.items(), key=lambda item: item[1])
            total_bytes = sum(totals.values())
            share = top_bytes / total_bytes if total_bytes else 0.0
            if share >= self.dominant_share and top_source == observation.src:
                if self._allow("dominant_talker", top_source, observation.ts):
                    events.append(self._event(
                        "dominant_talker",
                        observation.ts,
                        top_source,
                        observation.dst,
                        observation.dport,
                        observation,
                        {"share": round(share, 3), "bytes": top_bytes,
                         "packets_in_window": len(self._dominant)},
                    ))

        return events

    def process_flow(self, flow_event: dict) -> list[dict]:
        features = flow_event.get("features", {})
        fwd_bytes = float(features.get("fwd_bytes", 0.0))
        bwd_bytes = float(features.get("bwd_bytes", 0.0))
        if fwd_bytes >= 5_000_000 and fwd_bytes / max(bwd_bytes, 1.0) >= 10.0:
            event = self._event(
                "data_exfiltration",
                float(flow_event.get("last_ts", 0.0)),
                str(flow_event.get("src", "")),
                str(flow_event.get("dst", "")),
                int(flow_event.get("dport", 0)),
                None,
                {"fwd_bytes": fwd_bytes, "bwd_bytes": bwd_bytes,
                 "ratio": round(fwd_bytes / max(bwd_bytes, 1.0), 2)},
            )
            event["flow_id"] = flow_event.get("flow_id")
            return [event]
        return []

    def _event(
        self,
        rule_id: str,
        timestamp: float,
        src: str,
        dst: str,
        dport: int,
        observation: Optional[PacketObservation],
        evidence: dict,
    ) -> dict:
        spec = next(item for item in RULE_SPECS if item["id"] == rule_id)
        technique = MITRE_TECHNIQUES[spec["mitre"]]
        return {
            "kind": "rule",
            "rule": rule_id,
            "title": spec["title"],
            "severity": spec["severity"],
            "description": spec["description"],
            "timestamp": timestamp,
            "src": src,
            "dst": dst,
            "dport": dport,
            "sport": observation.sport if observation else 0,
            "proto": observation.proto if observation else "",
            "app": observation.app if observation else "",
            "sni": observation.sni if observation else "",
            "evidence": evidence,
            "mitre": technique,
        }

    def _allow(self, rule_id: str, key: str, timestamp: float) -> bool:
        suppression_key = (rule_id, key)
        last = self._last_emitted.get(suppression_key)
        if last is not None and timestamp - last < self.suppression_s:
            return False
        self._last_emitted[suppression_key] = timestamp
        return True

    @staticmethod
    def _prune(observations: deque, cutoff: float) -> None:
        while observations and observations[0].ts < cutoff:
            observations.popleft()

    @staticmethod
    def _prune_timestamps(timestamps: deque, cutoff: float) -> None:
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()
