// Cypher DPI Engine — modified from perryvegehan/Packet_analyzer
// Changes:  --json flag, suppressed terminal noise in json mode
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <iomanip>
#include <unordered_set>
#include <algorithm>
#include <sstream>
#include <tuple>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

// ── Flow ─────────────────────────────────────────────────────────────────────
struct Flow {
    FiveTuple tuple;
    AppType   app_type = AppType::UNKNOWN;
    std::string sni;
    std::string client_ip;
    std::string server_ip;
    uint16_t client_port = 0;
    uint16_t server_port = 0;
    uint32_t flow_id = 0;
    uint64_t packets = 0;
    uint64_t bytes   = 0;
    bool blocked     = false;
    std::string block_reason;
};

// ── Blocking rules ────────────────────────────────────────────────────────────
class BlockingRules {
public:
    std::unordered_set<uint32_t>   blocked_ips;
    std::unordered_set<AppType>    blocked_apps;
    std::vector<std::string>       blocked_domains;

    void blockIP(const std::string& ip) {
        blocked_ips.insert(parseIP(ip));
        std::cerr << "[Rules] Blocked IP: " << ip << "\n";
    }
    void blockApp(const std::string& app) {
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps.insert(static_cast<AppType>(i));
                std::cerr << "[Rules] Blocked app: " << app << "\n";
                return;
            }
        }
        std::cerr << "[Rules] Unknown app: " << app << "\n";
    }
    void blockDomain(const std::string& domain) {
        blocked_domains.push_back(domain);
        std::cerr << "[Rules] Blocked domain: " << domain << "\n";
    }
    bool isBlocked(uint32_t ip, AppType app, const std::string& sni) const {
        if (blocked_ips.count(ip)) return true;
        if (blocked_apps.count(app)) return true;
        if (!sni.empty()) {
            if (blocked_apps.count(sniToAppType(sni))) return true;
            std::string lower_sni = sni;
            std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            for (const auto& dom : blocked_domains) {
                std::string lower_dom = dom;
                std::transform(lower_dom.begin(), lower_dom.end(), lower_dom.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                if (domainMatches(lower_sni, lower_dom)) return true;
            }
        }
        return false;
    }

    static bool domainMatches(const std::string& domain, const std::string& pattern) {
        if (pattern.size() >= 2 && pattern[0] == '*' && pattern[1] == '.') {
            std::string suffix = pattern.substr(1);
            return (domain.size() >= suffix.size() &&
                    domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) == 0) ||
                   domain == pattern.substr(2);
        }
        return domain.find(pattern) != std::string::npos;
    }

private:
    static uint32_t parseIP(const std::string& ip) {
        uint32_t result = 0;
        int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.')      { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    }
};

// ── JSON helpers ──────────────────────────────────────────────────────────────
// Manually build JSON — no external library needed.

static std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if      (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else                out += c;
    }
    return out;
}

static FiveTuple canonicalTuple(const FiveTuple& t) {
    if (std::tie(t.src_ip, t.src_port) <= std::tie(t.dst_ip, t.dst_port)) {
        return t;
    }
    return t.reverse();
}

static bool packetPayload(const RawPacket& raw, const ParsedPacket& parsed,
                          size_t& offset, size_t& length) {
    if (raw.data.size() < 14) return false;

    size_t ip_offset = 14;
    uint8_t ip_ihl = raw.data[ip_offset] & 0x0F;
    if (ip_ihl < 5) return false;

    size_t transport_offset = ip_offset + ip_ihl * 4;
    if (transport_offset > raw.data.size()) return false;

    if (parsed.has_tcp) {
        if (transport_offset + 20 > raw.data.size()) return false;
        uint8_t tcp_offset = (raw.data[transport_offset + 12] >> 4) & 0x0F;
        if (tcp_offset < 5) return false;
        offset = transport_offset + tcp_offset * 4;
    } else if (parsed.has_udp) {
        offset = transport_offset + 8;
    } else {
        return false;
    }

    if (offset > raw.data.size()) return false;
    length = raw.data.size() - offset;
    return true;
}

static void initializeFlowEndpoints(Flow& flow, const ParsedPacket& parsed) {
    auto wellKnown = [](uint16_t port) {
        return port == 53 || port == 80 || port == 443 ||
               port == 8080 || port == 8443;
    };

    bool syn = (parsed.tcp_flags & 0x02) != 0;
    bool ack = (parsed.tcp_flags & 0x10) != 0;
    bool src_well_known = wellKnown(parsed.src_port);
    bool dst_well_known = wellKnown(parsed.dest_port);

    bool src_is_client = true;
    if (syn && !ack) {
        src_is_client = true;
    } else if (syn && ack) {
        src_is_client = false;
    } else if (dst_well_known && !src_well_known) {
        src_is_client = true;
    } else if (src_well_known && !dst_well_known) {
        src_is_client = false;
    }

    if (src_is_client) {
        flow.client_ip = parsed.src_ip;
        flow.client_port = parsed.src_port;
        flow.server_ip = parsed.dest_ip;
        flow.server_port = parsed.dest_port;
    } else {
        flow.client_ip = parsed.dest_ip;
        flow.client_port = parsed.dest_port;
        flow.server_ip = parsed.src_ip;
        flow.server_port = parsed.src_port;
    }
}

static bool isOutbound(const Flow& flow, const ParsedPacket& parsed) {
    return parsed.src_ip == flow.client_ip && parsed.src_port == flow.client_port;
}

// Emit one JSON line per packet to stdout.
// Format: {"ts":1234567.890123,"src":"1.2.3.4","dst":"5.6.7.8",
//          "sport":54321,"dport":443,"proto":"TCP",
//          "app":"YouTube","sni":"www.youtube.com","blocked":false,
//          "size":123,"flags":24,"payload_len":80,
//          "direction":"outbound","flow_id":1,"block_reason":""}
static void emitJSON(
    uint32_t ts_sec, uint32_t ts_usec,
    const std::string& src_ip, const std::string& dst_ip,
    uint16_t sport, uint16_t dport,
    uint8_t  protocol,
    AppType  app_type,
    const std::string& sni,
    bool     blocked,
    size_t   size,
    uint8_t  flags,
    size_t   payload_len,
    const std::string& direction,
    uint32_t flow_id,
    const std::string& block_reason)
{
    // Build timestamp as seconds.microseconds
    std::ostringstream ts_ss;
    ts_ss << ts_sec << "." << std::setfill('0') << std::setw(6) << ts_usec;

    const char* proto_str = (protocol == 6)  ? "TCP"  :
                            (protocol == 17) ? "UDP"  : "OTHER";

    std::cout << "{"
        << "\"ts\":"       << ts_ss.str()                         << ","
        << "\"src\":\""    << jsonEscape(src_ip)                  << "\","
        << "\"dst\":\""    << jsonEscape(dst_ip)                  << "\","
        << "\"sport\":"    << sport                               << ","
        << "\"dport\":"    << dport                               << ","
        << "\"proto\":\""  << proto_str                           << "\","
        << "\"app\":\""    << jsonEscape(appTypeToString(app_type))<< "\","
        << "\"sni\":\""    << jsonEscape(sni)                     << "\","
        << "\"blocked\":"  << (blocked ? "true" : "false")        << ","
        << "\"size\":"     << size                                << ","
        << "\"flags\":"    << static_cast<int>(flags)             << ","
        << "\"payload_len\":" << payload_len                      << ","
        << "\"direction\":\"" << jsonEscape(direction)            << "\","
        << "\"flow_id\":"  << flow_id                             << ","
        << "\"block_reason\":\"" << jsonEscape(block_reason)      << "\""
        << "}\n";
    std::cout.flush();  // important — FastAPI reads line-by-line
}

// ── Usage ─────────────────────────────────────────────────────────────────────
void printUsage(const char* prog) {
    std::cerr << R"(
Cypher DPI Engine
=================
Usage: )" << prog << R"( <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, TikTok, etc.)
  --block-domain <dom>   Block domain (substring match)
  --json                 Emit one JSON line per packet to stdout
                         (terminal report goes to stderr instead)

Examples:
  )" << prog << R"( capture.pcap filtered.pcap
  )" << prog << R"( capture.pcap filtered.pcap --json
  )" << prog << R"( capture.pcap filtered.pcap --json --block-app TikTok
)";
}

// ── main ──────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (argc < 3) { printUsage(argv[0]); return 1; }

    std::string input_file  = argv[1];
    std::string output_file = argv[2];

    BlockingRules rules;
    bool json_mode = false;   // ← new flag

    // Parse CLI options
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) {
            rules.blockIP(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
            rules.blockApp(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            rules.blockDomain(argv[++i]);
        } else if (arg == "--json") {
            json_mode = true;
        }
    }

    // In JSON mode all human-readable output goes to stderr so stdout stays
    // clean for the JSON stream that FastAPI will pipe-read.
    auto& log = json_mode ? std::cerr : std::cout;

    log << "\n╔══════════════════════════════════════════════════════════════╗\n";
    log <<   "║                   CYPHER DPI ENGINE v2.0                     ║\n";
    if (json_mode)
        log << "║                   [ JSON output mode ]                       ║\n";
    log <<   "╚══════════════════════════════════════════════════════════════╝\n\n";

    // Open input PCAP
    PcapReader reader;
    if (!reader.open(input_file, json_mode)) return 1;

    // Open output PCAP
    std::ofstream output(output_file, std::ios::binary);
    if (!output.is_open()) { std::cerr << "Error: Cannot open output file\n"; return 1; }

    const auto& header = reader.getGlobalHeader();
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));

    // Flow table
    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows;

    // Stats
    uint64_t total_packets = 0;
    uint64_t forwarded     = 0;
    uint64_t dropped       = 0;
    std::unordered_map<AppType, uint64_t> app_stats;

    RawPacket    raw;
    ParsedPacket parsed;

    log << "[DPI] Processing packets...\n";

    // Helper: parse dotted-decimal IP string → uint32
    auto parseIPStr = [](const std::string& ip) -> uint32_t {
        uint32_t result = 0;
        int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.')                  { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9')   octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    };

    while (reader.readNextPacket(raw)) {
        total_packets++;

        if (!PacketParser::parse(raw, parsed)) continue;
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;

        // Build five-tuple
        FiveTuple tuple;
        tuple.src_ip   = parseIPStr(parsed.src_ip);
        tuple.dst_ip   = parseIPStr(parsed.dest_ip);
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dest_port;
        tuple.protocol = parsed.protocol;

        FiveTuple key = canonicalTuple(tuple);
        bool new_flow = false;
        auto flow_it = flows.find(key);
        if (flow_it == flows.end()) {
            Flow fresh;
            fresh.tuple = key;
            fresh.flow_id = static_cast<uint32_t>(flows.size() + 1);
            initializeFlowEndpoints(fresh, parsed);
            flow_it = flows.emplace(key, std::move(fresh)).first;
            new_flow = true;
        }

        Flow& flow = flow_it->second;
        (void)new_flow;
        flow.packets++;
        flow.bytes += raw.data.size();

        bool outbound = isOutbound(flow, parsed);
        const char* direction = outbound ? "outbound" : "inbound";

        size_t payload_offset = 0;
        size_t payload_len = 0;
        bool has_payload = packetPayload(raw, parsed, payload_offset, payload_len);
        const uint8_t* payload = has_payload ? raw.data.data() + payload_offset : nullptr;

        if (outbound && flow.sni.empty() && flow.server_port == 443) {
            if (has_payload && payload_len > 5) {
                auto sni = SNIExtractor::extract(payload, payload_len);
                if (sni) {
                    flow.sni = *sni;
                    flow.app_type = sniToAppType(*sni);
                }
            }
        }

        if (outbound && flow.sni.empty() && flow.server_port == 80) {
            if (has_payload && payload_len > 0) {
                auto host = HTTPHostExtractor::extract(payload, payload_len);
                if (host) {
                    flow.sni = *host;
                    flow.app_type = sniToAppType(*host);
                }
            }
        }

        if (flow.server_port == 53 && flow.sni.empty()) {
            if (has_payload && payload_len > 12) {
                auto domain = DNSExtractor::extractQuery(payload, payload_len);
                if (domain) {
                    flow.sni = *domain;
                    flow.app_type = AppType::DNS;
                }
            }
        }

        if (flow.app_type == AppType::UNKNOWN) {
            if      (flow.server_port == 443 || flow.server_port == 8443) flow.app_type = AppType::HTTPS;
            else if (flow.server_port == 80  || flow.server_port == 8080) flow.app_type = AppType::HTTP;
            else if (flow.server_port == 53) flow.app_type = AppType::DNS;
        }

        if (!flow.blocked) {
            flow.blocked = rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni) ||
                           rules.isBlocked(tuple.dst_ip, flow.app_type, flow.sni);
            if (flow.blocked) {
                flow.block_reason = "rule";
                log << "[BLOCKED] " << parsed.src_ip << " -> " << parsed.dest_ip
                    << " (" << appTypeToString(flow.app_type);
                if (!flow.sni.empty()) log << ": " << flow.sni;
                log << ")\n";
            }
        }

        if (json_mode) {
            emitJSON(
                raw.header.ts_sec,
                raw.header.ts_usec,
                parsed.src_ip,
                parsed.dest_ip,
                parsed.src_port,
                parsed.dest_port,
                parsed.protocol,
                flow.app_type,
                flow.sni,
                flow.blocked,
                raw.data.size(),
                parsed.tcp_flags,
                payload_len,
                direction,
                flow.flow_id,
                flow.block_reason
            );
        }

        // ── Forward / drop ────────────────────────────────────────────────────
        app_stats[flow.app_type]++;

        if (flow.blocked) {
            dropped++;
        } else {
            forwarded++;
            PcapPacketHeader pkt_hdr;
            pkt_hdr.ts_sec   = raw.header.ts_sec;
            pkt_hdr.ts_usec  = raw.header.ts_usec;
            pkt_hdr.incl_len = raw.data.size();
            pkt_hdr.orig_len = raw.data.size();
            output.write(reinterpret_cast<const char*>(&pkt_hdr), sizeof(pkt_hdr));
            output.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
        }
    }

    reader.close();
    output.close();

    // ── Terminal report (always to stderr in json_mode, stdout otherwise) ─────
    log << "\n╔══════════════════════════════════════════════════════════════╗\n";
    log <<   "║                      PROCESSING REPORT                       ║\n";
    log <<   "╠══════════════════════════════════════════════════════════════╣\n";
    log << "║ Total Packets:      " << std::setw(10) << total_packets << "                             ║\n";
    log << "║ Forwarded:          " << std::setw(10) << forwarded     << "                             ║\n";
    log << "║ Dropped:            " << std::setw(10) << dropped       << "                             ║\n";
    log << "║ Active Flows:       " << std::setw(10) << flows.size()  << "                             ║\n";
    log <<   "╠══════════════════════════════════════════════════════════════╣\n";
    log <<   "║                    APPLICATION BREAKDOWN                     ║\n";
    log <<   "╠══════════════════════════════════════════════════════════════╣\n";

    std::vector<std::pair<AppType, uint64_t>> sorted_apps(app_stats.begin(), app_stats.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    for (const auto& [app, count] : sorted_apps) {
        double pct = 100.0 * count / total_packets;
        int bar_len = static_cast<int>(pct / 5);
        std::string bar(bar_len, '#');
        log << "║ " << std::setw(15) << std::left  << appTypeToString(app)
            << std::setw(8)          << std::right << count
            << " " << std::setw(5)   << std::fixed << std::setprecision(1) << pct << "% "
            << std::setw(20)         << std::left  << bar << "  ║\n";
    }
    log << "╚══════════════════════════════════════════════════════════════╝\n";

    log << "\n[Detected Applications/Domains]\n";
    std::unordered_map<std::string, AppType> unique_snis;
    for (const auto& [tuple, flow] : flows)
        if (!flow.sni.empty()) unique_snis[flow.sni] = flow.app_type;
    for (const auto& [sni, app] : unique_snis)
        log << "  - " << sni << " -> " << appTypeToString(app) << "\n";

    log << "\nOutput written to: " << output_file << "\n";
    return 0;
}
