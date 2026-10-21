"use client";

import type { ReactNode } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

export interface ChartDatum {
  name: string;
  value: number;
}

const COLORS = ["#22d3ee", "#60a5fa", "#f59e0b", "#ef4444", "#a78bfa", "#34d399", "#f472b6"];
const TOOLTIP_STYLE = {
  background: "#0d1b2f",
  border: "1px solid #1e3a5f",
  borderRadius: "8px",
  color: "#e6f1ff",
};

function ChartCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="card chart-card">
      <div className="card-title">{title}</div>
      <div className="chart-body">{children}</div>
    </div>
  );
}

function ProtocolBars({ data }: { data: ChartDatum[] }) {
  const total = data.reduce((sum, item) => sum + item.value, 0);
  if (total === 0) {
    return <div className="empty-row">No protocol data yet.</div>;
  }
  return (
    <div className="protocol-bars">
      {data.map((item, index) => (
        <div key={item.name} className="protocol-row">
          <span className="protocol-dot" style={{ background: COLORS[index % COLORS.length] }} />
          <span className="protocol-name">{item.name}</span>
          <div className="protocol-track">
            <span
              className="protocol-fill"
              style={{
                width: `${Math.max((item.value / total) * 100, 3)}%`,
                background: COLORS[index % COLORS.length],
              }}
            />
          </div>
          <strong className="protocol-value">{item.value}</strong>
        </div>
      ))}
      <div className="protocol-total">{total.toLocaleString()} packets</div>
    </div>
  );
}

export function Charts({
  protocols,
  apps,
  severities,
  flowCategories,
  timeline,
}: {
  protocols: ChartDatum[];
  apps: ChartDatum[];
  severities: ChartDatum[];
  flowCategories: ChartDatum[];
  timeline: ChartDatum[];
}) {
  return (
    <div className="charts-grid">
      <ChartCard title="Protocol split">
        <ProtocolBars data={protocols} />
      </ChartCard>

      <ChartCard title="Top applications">
        <ResponsiveContainer width="100%" height={210}>
          <BarChart data={apps} layout="vertical" margin={{ left: 12, right: 16 }}>
            <CartesianGrid stroke="#1e3a5f" strokeDasharray="3 3" horizontal={false} />
            <XAxis type="number" hide />
            <YAxis type="category" dataKey="name" width={92} tick={{ fill: "#9fb3c8", fontSize: 12 }} />
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Bar dataKey="value" radius={[0, 4, 4, 0]} fill="#22d3ee" />
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>

      <ChartCard title="Detections by severity">
        <ResponsiveContainer width="100%" height={210}>
          <BarChart data={severities} margin={{ top: 8, right: 12 }}>
            <CartesianGrid stroke="#1e3a5f" strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="name" tick={{ fill: "#9fb3c8", fontSize: 12 }} />
            <YAxis allowDecimals={false} tick={{ fill: "#9fb3c8", fontSize: 12 }} />
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Bar dataKey="value" radius={[4, 4, 0, 0]}>
              {severities.map((entry, index) => (
                <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>

      <ChartCard title="Packets per second">
        <ResponsiveContainer width="100%" height={210}>
          <LineChart data={timeline} margin={{ top: 8, right: 16 }}>
            <CartesianGrid stroke="#1e3a5f" strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="name" tick={{ fill: "#9fb3c8", fontSize: 11 }} />
            <YAxis allowDecimals={false} tick={{ fill: "#9fb3c8", fontSize: 11 }} />
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Line type="monotone" dataKey="value" stroke="#34d399" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </ChartCard>

      <ChartCard title="ML flow categories">
        <ResponsiveContainer width="100%" height={210}>
          <BarChart data={flowCategories} margin={{ top: 8, right: 12 }}>
            <CartesianGrid stroke="#1e3a5f" strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="name" tick={{ fill: "#9fb3c8", fontSize: 11 }} />
            <YAxis allowDecimals={false} tick={{ fill: "#9fb3c8", fontSize: 11 }} />
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Bar dataKey="value" radius={[4, 4, 0, 0]} fill="#a78bfa" />
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>
    </div>
  );
}
