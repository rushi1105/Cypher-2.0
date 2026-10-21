export type Severity = "low" | "medium" | "high" | "critical";

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  url: string;
}

export interface PacketEvent {
  kind: "packet";
  ts: number;
  src: string;
  dst: string;
  sport: number;
  dport: number;
  proto: string;
  app: string;
  sni: string;
  blocked: boolean;
  size: number;
  flags: number;
  payload_len: number;
  direction: "outbound" | "inbound";
  flow_id: number;
  block_reason: string;
}

export interface FlowPrediction {
  label: "Normal" | "Attack" | "Unknown";
  attack_probability: number;
  is_threat: boolean;
  category: string;
  category_confidence: number;
  anomaly_score: number;
  is_anomaly: boolean;
  model_active: boolean;
  threshold: number;
}

export interface FlowEvent {
  kind: "flow";
  flow_id: number;
  first_ts: number;
  last_ts: number;
  src: string;
  dst: string;
  sport: number;
  dport: number;
  proto: string;
  app: string;
  sni: string;
  blocked: boolean;
  packet_count: number;
  features: Record<string, number>;
  prediction: FlowPrediction;
  rules: RuleEvent[];
}

export interface RuleEvent {
  kind: "rule";
  rule: string;
  title: string;
  severity: Severity;
  description: string;
  timestamp: number;
  src: string;
  dst: string;
  dport: number;
  sport: number;
  proto: string;
  app: string;
  sni: string;
  evidence: Record<string, unknown>;
  mitre: MitreTechnique;
}

export interface ThreatItem {
  id: string;
  kind: "rule" | "ml";
  severity: Severity;
  title: string;
  rule: string;
  timestamp: number;
  src: string;
  dst: string;
  dport: number;
  app?: string;
  sni?: string;
  mitre?: MitreTechnique;
  evidence: Record<string, unknown>;
}

export interface Health {
  status: string;
  engine_ready: boolean;
  shim_active: boolean;
  ml_loaded: boolean;
  flow_ml_loaded: boolean;
  rule_count: number;
  mitre_technique_count: number;
  uptime_s: number;
}

export interface Summary {
  packets: number;
  flows: number;
  detections: number;
  critical: number;
  high: number;
  blocked: number;
  apps: number;
  mlThreats: number;
}
