"use client";

import type { FlowEvent } from "@/lib/types";
import { formatTime } from "@/lib/format";

export function FlowPanel({ flows }: { flows: FlowEvent[] }) {
  const recent = [...flows].reverse().slice(0, 12);

  return (
    <div className="card flow-card">
      <div className="table-header">
        <div>
          <div className="card-title">Flow-level ML predictions</div>
          <div className="muted">{flows.length} flows scored</div>
        </div>
        <span className="pill pill-ml">24 features</span>
      </div>
      <div className="flow-list">
        {recent.map((flow) => {
          const prediction = flow.prediction;
          const flagged = prediction.is_threat || prediction.is_anomaly;
          return (
            <div key={`${flow.flow_id}-${flow.last_ts}`} className={`flow-row ${flagged ? "flow-flagged" : ""}`}>
              <div className="flow-main">
                <strong>{flow.app || "Unknown"}</strong>
                <span className="mono muted">{flow.src}:{flow.sport} → {flow.dst}:{flow.dport}</span>
              </div>
              <div className="flow-meta">
                <span className={prediction.is_threat ? "text-danger" : "text-ok"}>
                  {prediction.label}
                </span>
                <span className="muted">{Math.round(prediction.attack_probability * 100)}%</span>
                <span>{prediction.category}</span>
                {prediction.is_anomaly && <span className="pill pill-anomaly">anomaly</span>}
                <span className="muted">{formatTime(flow.last_ts)}</span>
              </div>
            </div>
          );
        })}
        {recent.length === 0 && <div className="empty-row">No flows scored yet.</div>}
      </div>
    </div>
  );
}
