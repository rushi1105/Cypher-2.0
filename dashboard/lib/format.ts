import type { MitreTechnique, Severity } from "./types";

export function formatTime(ts: number): string {
  if (!Number.isFinite(ts) || ts <= 0) return "--:--:--";
  const date = new Date(ts * 1000);
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  const seconds = String(date.getSeconds()).padStart(2, "0");
  const millis = String(date.getMilliseconds()).padStart(3, "0");
  return `${hours}:${minutes}:${seconds}.${millis}`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function severityRank(severity: Severity): number {
  return { low: 0, medium: 1, high: 2, critical: 3 }[severity];
}

export function downloadJson(filename: string, data: unknown): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  download(filename, blob);
}

export function downloadCsv(filename: string, rows: Record<string, unknown>[]): void {
  if (rows.length === 0) return;
  const headers = Object.keys(rows[0]);
  const lines = [
    headers.join(","),
    ...rows.map((row) =>
      headers
        .map((header) => {
          const value = row[header] ?? "";
          return `"${String(value).replaceAll('"', '""')}"`;
        })
        .join(","),
    ),
  ];
  download(filename, new Blob([lines.join("\n")], { type: "text/csv" }));
}

function download(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

const CATEGORY_MITRE: Record<string, MitreTechnique> = {
  Scan: {
    id: "T1046",
    name: "Network Service Discovery",
    tactic: "Discovery",
    url: "https://attack.mitre.org/techniques/T1046/",
  },
  "DoS/DDoS": {
    id: "T1498",
    name: "Network Denial of Service",
    tactic: "Impact",
    url: "https://attack.mitre.org/techniques/T1498/",
  },
  "Brute Force": {
    id: "T1110",
    name: "Brute Force",
    tactic: "Credential Access",
    url: "https://attack.mitre.org/techniques/T1110/",
  },
  "Bot/C2": {
    id: "T1071",
    name: "Application Layer Protocol",
    tactic: "Command and Control",
    url: "https://attack.mitre.org/techniques/T1071/",
  },
  Infiltration: {
    id: "T1048",
    name: "Exfiltration Over Alternative Protocol",
    tactic: "Exfiltration",
    url: "https://attack.mitre.org/techniques/T1048/",
  },
};

export function mitreForCategory(category: string): MitreTechnique | undefined {
  return CATEGORY_MITRE[category];
}
