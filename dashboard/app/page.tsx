"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Charts } from "@/components/Charts";
import { FlowPanel } from "@/components/FlowPanel";
import { PacketTable } from "@/components/PacketTable";
import { StatsCards } from "@/components/StatsCards";
import { ThreatPanel } from "@/components/ThreatPanel";
import { API_BASE } from "@/lib/api";
import { downloadCsv, downloadJson, mitreForCategory } from "@/lib/format";
import type {
  FlowEvent,
  Health,
  PacketEvent,
  RuleEvent,
  Summary,
  ThreatItem,
} from "@/lib/types";

const PCAPS = ["test_dpi.pcap", "test_attack.pcap"];

function ruleToThreat(event: RuleEvent): ThreatItem {
  return {
    id: `rule-${event.rule}-${event.src}-${event.dst}-${event.timestamp}`,
    kind: "rule",
    severity: event.severity,
    title: event.title,
    rule: event.rule,
    timestamp: event.timestamp,
    src: event.src,
    dst: event.dst,
    dport: event.dport,
    app: event.app,
    sni: event.sni,
    mitre: event.mitre,
    evidence: event.evidence,
  };
}

function flowToThreat(event: FlowEvent): ThreatItem | null {
  const prediction = event.prediction;
  if (!prediction.is_threat && !prediction.is_anomaly) return null;
  return {
    id: `ml-${event.flow_id}-${event.last_ts}`,
    kind: "ml",
    severity: prediction.is_threat ? "high" : "medium",
    title: prediction.is_threat
      ? `ML flagged ${prediction.category}`
      : "ML flow anomaly",
    rule: `ml_${prediction.category.toLowerCase()}`,
    timestamp: event.last_ts,
    src: event.src,
    dst: event.dst,
    dport: event.dport,
    app: event.app,
    sni: event.sni,
    mitre: mitreForCategory(prediction.category),
    evidence: {
      label: prediction.label,
      attack_probability: prediction.attack_probability,
      category: prediction.category,
      category_confidence: prediction.category_confidence,
      anomaly_score: prediction.anomaly_score,
      packet_count: event.packet_count,
    },
  };
}

export default function HomePage() {
  const [pcap, setPcap] = useState(PCAPS[0]);
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState("idle");
  const [health, setHealth] = useState<Health | null>(null);
  const [packets, setPackets] = useState<PacketEvent[]>([]);
  const [flows, setFlows] = useState<FlowEvent[]>([]);
  const [threats, setThreats] = useState<ThreatItem[]>([]);
  const [filter, setFilter] = useState("");
  const [protocol, setProtocol] = useState("All");
  const [blockedOnly, setBlockedOnly] = useState(false);
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const response = await fetch(`${API_BASE}/health`, { cache: "no-store" });
        if (!response.ok) throw new Error("health failed");
        const data = (await response.json()) as Health;
        if (!cancelled) setHealth(data);
      } catch {
        if (!cancelled) setHealth(null);
      }
    };
    load();
    const timer = setInterval(load, 5000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    return () => {
      sourceRef.current?.close();
    };
  }, []);

  const start = (targetPcap: string = pcap) => {
    sourceRef.current?.close();
    setPcap(targetPcap);
    setPackets([]);
    setFlows([]);
    setThreats([]);
    setRunning(true);
    setStatus("connecting");

    const source = new EventSource(
      `${API_BASE}/stream/live?pcap=${encodeURIComponent(targetPcap)}`,
    );
    sourceRef.current = source;

    source.onopen = () => setStatus("live");
    source.onerror = () => {
      source.close();
      sourceRef.current = null;
      setRunning(false);
      setStatus("ended");
    };
    source.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data) as PacketEvent | RuleEvent | FlowEvent;
        if (event.kind === "packet") {
          setPackets((current) => [event, ...current].slice(0, 500));
        } else if (event.kind === "rule") {
          setThreats((current) => [ruleToThreat(event), ...current].slice(0, 200));
        } else if (event.kind === "flow") {
          setFlows((current) => [event, ...current].slice(0, 300));
          const threat = flowToThreat(event);
          if (threat) {
            setThreats((current) => {
              if (current.some((item) => item.id === threat.id)) return current;
              return [threat, ...current].slice(0, 200);
            });
          }
        }
      } catch {
        // Ignore malformed SSE events.
      }
    };
  };

  const stop = () => {
    sourceRef.current?.close();
    sourceRef.current = null;
    setRunning(false);
    setStatus("idle");
  };

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const requested = params.get("pcap");
    const target = requested && PCAPS.includes(requested) ? requested : PCAPS[0];
    if (params.get("autostart") === "1") {
      start(target);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const summary = useMemo<Summary>(() => {
    const severityCounts = threats.reduce<Record<string, number>>((accumulator, threat) => {
      accumulator[threat.severity] = (accumulator[threat.severity] ?? 0) + 1;
      return accumulator;
    }, {});
    return {
      packets: packets.length,
      flows: flows.length,
      detections: threats.length,
      critical: severityCounts.critical ?? 0,
      high: severityCounts.high ?? 0,
      blocked: packets.filter((packet) => packet.blocked).length,
      apps: new Set(packets.map((packet) => packet.app)).size,
      mlThreats: threats.filter((threat) => threat.kind === "ml").length,
    };
  }, [packets, flows, threats]);

  const chartData = useMemo(() => {
    const protocolCounts = new Map<string, number>();
    const appCounts = new Map<string, number>();
    const severityCounts = new Map<string, number>([
      ["critical", 0],
      ["high", 0],
      ["medium", 0],
      ["low", 0],
    ]);
    const categoryCounts = new Map<string, number>();
    const timelineCounts = new Map<string, number>();

    for (const packet of packets) {
      protocolCounts.set(packet.proto, (protocolCounts.get(packet.proto) ?? 0) + 1);
      appCounts.set(packet.app, (appCounts.get(packet.app) ?? 0) + 1);
      const bucket = String(Math.floor(packet.ts));
      timelineCounts.set(bucket, (timelineCounts.get(bucket) ?? 0) + 1);
    }
    for (const threat of threats) {
      severityCounts.set(threat.severity, (severityCounts.get(threat.severity) ?? 0) + 1);
    }
    for (const flow of flows) {
      const category = flow.prediction.category || "Unknown";
      categoryCounts.set(category, (categoryCounts.get(category) ?? 0) + 1);
    }

    return {
      protocols: Array.from(protocolCounts, ([name, value]) => ({ name, value })),
      apps: Array.from(appCounts, ([name, value]) => ({ name, value }))
        .sort((left, right) => right.value - left.value)
        .slice(0, 8),
      severities: Array.from(severityCounts, ([name, value]) => ({ name, value })),
      flowCategories: Array.from(categoryCounts, ([name, value]) => ({ name, value }))
        .sort((left, right) => right.value - left.value)
        .slice(0, 6),
      timeline: Array.from(timelineCounts, ([bucket, value]) => ({
        name: new Date(Number(bucket) * 1000).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
        value,
      })).slice(-30),
    };
  }, [packets, flows, threats]);

  const statusLabel = running ? status : status === "ended" ? "replay ended" : "idle";
  const healthOk = health?.status === "ok";

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">C</span>
          <div>
            <div className="brand-name">CYPHER 2.0</div>
            <div className="brand-sub">deep packet analysis · threat visibility</div>
          </div>
        </div>

        <div className="controls">
          <select className="input" value={pcap} onChange={(event) => setPcap(event.target.value)} disabled={running}>
            {PCAPS.map((item) => (
              <option key={item} value={item}>{item}</option>
            ))}
          </select>
          <button className="button button-primary" onClick={running ? stop : () => start()}>
            {running ? "Stop replay" : "Start replay"}
          </button>
          <span className={`status-pill status-${status}`}>
            <span className="status-dot" />
            {statusLabel}
          </span>
        </div>
      </header>

      <section className="hero">
        <div>
          <h1>Network signals, mapped to ATT&CK.</h1>
          <p>
            C++ DPI engine, deterministic rules, and a 24-feature ML flow model streamed into one dashboard.
            Offline replay is the default; live capture is the next milestone.
          </p>
        </div>
        <div className="health-panel">
          <div className="health-row">
            <span>API</span>
            <strong className={healthOk ? "text-ok" : "text-danger"}>{healthOk ? "online" : "offline"}</strong>
          </div>
          <div className="health-row">
            <span>Engine</span>
            <strong className={health?.engine_ready ? "text-ok" : "text-warn"}>
              {health?.engine_ready ? "C++" : health?.shim_active ? "shim" : "unknown"}
            </strong>
          </div>
          <div className="health-row">
            <span>Flow model</span>
            <strong className={health?.flow_ml_loaded ? "text-ok" : "text-warn"}>
              {health?.flow_ml_loaded ? "loaded" : "not loaded"}
            </strong>
          </div>
          <div className="health-row">
            <span>Rules / ATT&CK</span>
            <strong>{health ? `${health.rule_count} / ${health.mitre_technique_count}` : "-"}</strong>
          </div>
        </div>
      </section>

      <div className="toolbar">
        <div className="toolbar-note">
          Showing <strong>{pcap}</strong>. {pcap === "test_attack.pcap"
            ? "Expect port scan, flood, brute-force, suspicious-port, and beaconing alerts."
            : "Normal browsing replay with one legacy ML window anomaly."}
        </div>
        <div className="toolbar-actions">
          <button
            className="button"
            onClick={() => downloadJson("cypher-packets.json", packets)}
            disabled={packets.length === 0}
          >
            Export packets JSON
          </button>
          <button
            className="button"
            onClick={() =>
              downloadCsv(
                "cypher-packets.csv",
                packets as unknown as Record<string, unknown>[],
              )
            }
            disabled={packets.length === 0}
          >
            Export CSV
          </button>
          <button
            className="button"
            onClick={() => downloadJson("cypher-alerts.json", threats)}
            disabled={threats.length === 0}
          >
            Export alerts
          </button>
        </div>
      </div>

      <StatsCards summary={summary} />
      <Charts {...chartData} />

      <section className="lower-grid">
        <PacketTable
          packets={packets}
          filter={filter}
          setFilter={setFilter}
          protocol={protocol}
          setProtocol={setProtocol}
          blockedOnly={blockedOnly}
          setBlockedOnly={setBlockedOnly}
        />
        <div className="side-column">
          <ThreatPanel threats={threats} />
          <FlowPanel flows={flows} />
        </div>
      </section>

      <footer className="footer">
        <span>Offline replay demo. Live capture is local/self-hosted. No payloads are stored.</span>
        <span>{health ? `API uptime ${health.uptime_s}s` : "API unavailable"}</span>
      </footer>
    </main>
  );
}
