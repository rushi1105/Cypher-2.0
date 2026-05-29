"""
engine_shim.py
--------------
Pure-Python fallback engine that reads a .pcap file and emits NDJSON
to stdout — exactly matching the format of dpi_simple.exe --json.

Used when the C++ engine binary is unavailable or fails (e.g. missing DLL,
wrong platform). The server will auto-fall back to this shim.

Output format (one JSON object per line to stdout):
{
  "ts":      float,    -- UNIX timestamp
  "src":     str,      -- source IP
  "dst":     str,      -- destination IP
  "sport":   int,      -- source port
  "dport":   int,      -- destination port
  "proto":   str,      -- "TCP" | "UDP" | "ICMP" | "OTHER"
  "app":     str,      -- heuristic app label
  "sni":     str,      -- TLS SNI if extractable (empty string otherwise)
  "blocked": bool,     -- always false (shim doesn't block)
  "size":    int,      -- total packet size in bytes  ← Phase 3 field, provided here
  "flags":   int,      -- TCP flags byte              ← Phase 3 field, provided here
}

Usage:
  python engine_shim.py <input.pcap> [output.pcap]

Dependencies: only Python stdlib (struct, socket) — no scapy required.
"""

from __future__ import annotations

import json
import socket
import struct
import sys
from pathlib import Path


# ── Minimal PCAP parser (no dependencies) ─────────────────────────────────────

PCAP_GLOBAL_MAGIC  = 0xA1B2C3D4
PCAP_GLOBAL_MAGIC2 = 0xD4C3B2A1   # byte-swapped
PCAP_GLOBAL_HDR_FMT = "<IHHiIII"  # magic, major, minor, gmt_off, ts_acc, snaplen, linktype
PCAP_PKT_HDR_FMT    = "<IIII"     # ts_sec, ts_usec, incl_len, orig_len

ETH_HEADER_LEN = 14
IP_PROTO_TCP   = 6
IP_PROTO_UDP   = 17
IP_PROTO_ICMP  = 1

TLS_CONTENT_TYPE_HANDSHAKE = 22
TLS_HANDSHAKE_CLIENT_HELLO = 1

# Port → app label heuristics (mirrors the C++ engine's logic)
_PORT_APP: dict[int, str] = {
    80:   "HTTP",
    8080: "HTTP",
    443:  "HTTPS",
    8443: "HTTPS",
    53:   "DNS",
    25:   "SMTP",
    587:  "SMTP",
    465:  "SMTP",
    110:  "POP3",
    143:  "IMAP",
    22:   "SSH",
    21:   "FTP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017:"MongoDB",
}

# SNI domain → app label (mirrors sniToAppType() in C++)
_SNI_APP_MAP: list[tuple[str, str]] = [
    ("google",      "Google"),    ("youtube",     "YouTube"),
    ("gstatic",     "Google"),    ("googleapis",  "Google"),
    ("facebook",    "Facebook"),  ("fbcdn",       "Facebook"),
    ("instagram",   "Instagram"), ("cdninstagram","Instagram"),
    ("whatsapp",    "WhatsApp"),  ("twitter",     "Twitter/X"),
    ("twimg",       "Twitter/X"), ("x.com",       "Twitter/X"),
    ("netflix",     "Netflix"),   ("nflx",        "Netflix"),
    ("amazon",      "Amazon"),    ("amazonaws",   "Amazon"),
    ("microsoft",   "Microsoft"), ("office",      "Microsoft"),
    ("apple",       "Apple"),     ("icloud",      "Apple"),
    ("telegram",    "Telegram"),  ("tiktok",      "TikTok"),
    ("spotify",     "Spotify"),   ("scdn.co",     "Spotify"),
    ("zoom.us",     "Zoom"),      ("discord",     "Discord"),
    ("github",      "GitHub"),    ("cloudflare",  "Cloudflare"),
    ("reddit",      "Reddit"),    ("twitch",      "Twitch"),
    ("linkedin",    "LinkedIn"),  ("snapchat",    "Snapchat"),
    ("slack",       "Slack"),     ("notion",      "Notion"),
    ("figma",       "Figma"),     ("openai",      "OpenAI"),
    ("anthropic",   "Anthropic"), ("chatgpt",     "OpenAI"),
    ("huggingface", "HuggingFace"),
]


def _sni_to_app(sni: str) -> str:
    if not sni:
        return "HTTPS"
    lower = sni.lower()
    for pattern, label in _SNI_APP_MAP:
        if pattern in lower:
            return label
    return "HTTPS"


def _extract_sni(payload: bytes) -> str:
    """
    Extract TLS Server Name Indication from a ClientHello payload.
    Returns empty string if not found or payload is too short.
    """
    try:
        if len(payload) < 5:
            return ""
        # TLS record layer
        if payload[0] != TLS_CONTENT_TYPE_HANDSHAKE:
            return ""
        record_len = struct.unpack_from(">H", payload, 3)[0]
        if len(payload) < 5 + record_len:
            return ""
        # Handshake layer
        hs = payload[5:]
        if hs[0] != TLS_HANDSHAKE_CLIENT_HELLO:
            return ""
        hs_len = struct.unpack_from(">I", b"\x00" + hs[1:4])[0]
        if len(hs) < 4 + hs_len:
            return ""
        body = hs[4:]
        pos = 2 + 32  # skip version + random
        if pos >= len(body):
            return ""
        # Session ID
        sid_len = body[pos]
        pos += 1 + sid_len
        if pos + 2 > len(body):
            return ""
        # Cipher suites
        cs_len = struct.unpack_from(">H", body, pos)[0]
        pos += 2 + cs_len
        if pos >= len(body):
            return ""
        # Compression methods
        cm_len = body[pos]
        pos += 1 + cm_len
        if pos + 2 > len(body):
            return ""
        # Extensions
        ext_total = struct.unpack_from(">H", body, pos)[0]
        pos += 2
        end = pos + ext_total
        while pos + 4 <= end and pos + 4 <= len(body):
            ext_type = struct.unpack_from(">H", body, pos)[0]
            ext_len  = struct.unpack_from(">H", body, pos + 2)[0]
            pos += 4
            if ext_type == 0:   # SNI extension
                if pos + 5 > len(body):
                    break
                # server_name_list_length (2) + type (1) + name_length (2)
                name_len = struct.unpack_from(">H", body, pos + 3)[0]
                name_start = pos + 5
                if name_start + name_len <= len(body):
                    return body[name_start: name_start + name_len].decode("ascii", errors="ignore")
                break
            pos += ext_len
        return ""
    except Exception:
        return ""


def _format_ip(packed: bytes) -> str:
    return socket.inet_ntoa(packed)


def _parse_packet(data: bytes, ts: float) -> dict | None:
    """Parse a raw Ethernet frame and return a packet dict or None."""
    if len(data) < ETH_HEADER_LEN:
        return None

    # Ethernet: dst(6) src(6) ethertype(2)
    ethertype = struct.unpack_from(">H", data, 12)[0]

    # Skip 802.1Q VLAN tags
    while ethertype == 0x8100 and len(data) >= ETH_HEADER_LEN + 4:
        ethertype = struct.unpack_from(">H", data, ETH_HEADER_LEN + 2)[0]
        data = data[4:]

    if ethertype != 0x0800:   # only IPv4
        return None

    ip_start = ETH_HEADER_LEN
    if len(data) < ip_start + 20:
        return None

    ihl   = (data[ip_start] & 0x0F) * 4
    proto = data[ip_start + 9]
    src   = _format_ip(data[ip_start + 12: ip_start + 16])
    dst   = _format_ip(data[ip_start + 16: ip_start + 20])

    transport_start = ip_start + ihl
    sport = dport = 0
    tcp_flags = 0
    sni = ""
    proto_str = "OTHER"

    if proto == IP_PROTO_TCP and len(data) >= transport_start + 20:
        sport     = struct.unpack_from(">H", data, transport_start)[0]
        dport     = struct.unpack_from(">H", data, transport_start + 2)[0]
        tcp_offset= (data[transport_start + 12] >> 4) * 4
        tcp_flags = data[transport_start + 13]
        payload_start = transport_start + tcp_offset
        payload = data[payload_start:]
        proto_str = "TCP"
        # Try SNI extraction on HTTPS traffic
        if dport == 443 and len(payload) > 5:
            sni = _extract_sni(payload)

    elif proto == IP_PROTO_UDP and len(data) >= transport_start + 8:
        sport = struct.unpack_from(">H", data, transport_start)[0]
        dport = struct.unpack_from(">H", data, transport_start + 2)[0]
        proto_str = "UDP"

    elif proto == IP_PROTO_ICMP:
        proto_str = "ICMP"

    # App label
    if sni:
        app = _sni_to_app(sni)
    else:
        app = _PORT_APP.get(dport) or _PORT_APP.get(sport) or "Unknown"

    return {
        "ts":      round(ts, 6),
        "src":     src,
        "dst":     dst,
        "sport":   sport,
        "dport":   dport,
        "proto":   proto_str,
        "app":     app,
        "sni":     sni,
        "blocked": False,
        "size":    len(data),      # Phase 3 field
        "flags":   tcp_flags,      # Phase 3 field
    }


def stream_pcap(path: str) -> None:
    """Read a .pcap file and emit NDJSON to stdout."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            sys.stderr.write(f"[shim] File too short: {path}\n")
            return

        magic = struct.unpack_from("<I", hdr)[0]
        if magic == PCAP_GLOBAL_MAGIC2:
            sys.stderr.write("[shim] Byte-swapped PCAP format not supported\n")
            return
        if magic != PCAP_GLOBAL_MAGIC:
            sys.stderr.write(f"[shim] Not a PCAP file (magic=0x{magic:08X})\n")
            return

        count = 0
        while True:
            pkt_hdr = f.read(16)
            if not pkt_hdr:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(PCAP_PKT_HDR_FMT, pkt_hdr)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            ts = ts_sec + ts_usec / 1_000_000.0
            parsed = _parse_packet(pkt_data, ts)
            if parsed:
                sys.stdout.write(json.dumps(parsed) + "\n")
                sys.stdout.flush()
                count += 1

        sys.stderr.write(f"[shim] Emitted {count} packets\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write(f"Usage: {sys.argv[0]} <input.pcap> [output.pcap]\n")
        sys.exit(1)
    stream_pcap(sys.argv[1])
