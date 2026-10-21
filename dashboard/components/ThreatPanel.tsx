"use client";

import type { ThreatItem } from "@/lib/types";
import { formatTime, severityRank } from "@/lib/format";

export function ThreatPanel({ threats }: { threats: ThreatItem[] }) {
  const sorted = [...threats]
    .sort((left, right) => {
      const severity = severityRank(right.severity) - severityRank(left.severity);
      return severity !== 0 ? severity : right.timestamp - left.timestamp;
    })
    .slice(0, 60);

  return (
    <div className="card threat-card">
      <div className="table-header">
        <div>
          <div className="card-title">Threats and MITRE mappings</div>
          <div className="muted">{threats.length} alerts in this run</div>
        </div>
        <span className="pill pill-live">rule + ML</span>
      </div>

      <div className="threat-list">
        {sorted.map((threat) => (
          <article key={threat.id} className={`threat-item severity-${threat.severity}`}>
            <div className="threat-top">
              <span className={`severity-badge severity-${threat.severity}`}>
                {threat.severity}
              </span>
              <strong>{threat.title}</strong>
              <span className="muted threat-time">{formatTime(threat.timestamp)}</span>
            </div>
            <div className="threat-meta">
              <span className="mono">{threat.src} → {threat.dst}:{threat.dport}</span>
              {threat.app && <span>{threat.app}</span>}
              {threat.sni && <span className="mono">{threat.sni}</span>}
            </div>
            {threat.mitre && (
              <a className="mitre-link" href={threat.mitre.url} target="_blank" rel="noreferrer">
                {threat.mitre.id} · {threat.mitre.name} · {threat.mitre.tactic}
              </a>
            )}
            <div className="evidence">
              {Object.entries(threat.evidence).slice(0, 5).map(([key, value]) => (
                <span key={key} className="evidence-chip">
                  {key}: {typeof value === "object" ? JSON.stringify(value) : String(value)}
                </span>
              ))}
            </div>
          </article>
        ))}
        {sorted.length === 0 && (
          <div className="empty-row">No detections yet. Try the attack replay.</div>
        )}
      </div>
    </div>
  );
}
