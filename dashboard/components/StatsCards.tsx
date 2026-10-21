import type { Summary } from "@/lib/types";

export function StatsCards({ summary }: { summary: Summary }) {
  const cards = [
    { label: "Packets", value: summary.packets.toLocaleString(), tone: "cyan" },
    { label: "Flows", value: summary.flows.toLocaleString(), tone: "blue" },
    { label: "Detections", value: summary.detections.toLocaleString(), tone: "amber" },
    { label: "High / Critical", value: `${summary.high} / ${summary.critical}`, tone: "red" },
    { label: "Blocked", value: summary.blocked.toLocaleString(), tone: "violet" },
    { label: "Applications", value: summary.apps.toLocaleString(), tone: "green" },
    { label: "ML alerts", value: summary.mlThreats.toLocaleString(), tone: "pink" },
  ];

  return (
    <div className="stats-grid">
      {cards.map((card) => (
        <div key={card.label} className={`card stat-card tone-${card.tone}`}>
          <span className="stat-label">{card.label}</span>
          <strong className="stat-value">{card.value}</strong>
        </div>
      ))}
    </div>
  );
}
