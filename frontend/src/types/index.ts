/**
 * CyberFlux — TypeScript Type Definitions
 * 
 * Mirrors backend Pydantic models exactly.
 */

// ─── Enums ───────────────────────────────────────────────────────────

export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'TLS' | 'QUIC' | 'HTTP' | 'OTHER';

export type ThreatClass =
  | 'BENIGN'
  | 'SYN_FLOOD'
  | 'UDP_REFLECTION'
  | 'BOTNET_C2'
  | 'DGA_DOMAIN'
  | 'DNS_TUNNELING'
  | 'MALWARE_TLS'
  | 'RECON_SCAN'
  | 'DATA_EXFILTRATION';

export type ThreatStatus = 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type SimulationState = 'IDLE' | 'RUNNING' | 'PAUSED' | 'DEMO_RUNNING' | 'DEMO_PAUSED';

export type SystemHealth = 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY';

// ─── Flow Event ──────────────────────────────────────────────────────

export interface FlowEvent {
  flow_id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: Protocol;

  duration: number;
  packets: number;
  bytes_total: number;

  packets_per_second: number;
  bytes_per_second: number;

  inbound_bytes: number;
  outbound_bytes: number;
  outbound_inbound_ratio: number;

  source_entropy: number;
  destination_fanout: number;
  port_fanout: number;

  mean_interarrival: number;
  interarrival_std: number;
  periodicity_score: number;

  dns_entropy: number;
  dns_query_length: number;
  dns_query_frequency: number;

  tls_version: string;
  tls_fingerprint: string;
  ja3: string;
  ja3s: string;
  ja4: string;

  packet_size_mean: number;
  packet_size_std: number;

  threat_class: ThreatClass;
  threat_status: ThreatStatus;
  confidence: number;
  severity: Severity;
  anomaly_score: number;

  evidence: string[];
  top_contributing_features: Record<string, number>;

  detection_latency_ms: number;
}

// ─── Alert ───────────────────────────────────────────────────────────

export interface Alert {
  alert_id: string;
  timestamp: string;
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  threat_class: ThreatClass;
  confidence: number;
  severity: Severity;
  anomaly_score: number;
  evidence: string[];
  top_contributing_features: Record<string, number>;
  detection_latency_ms: number;
}

// ─── Alert Summary ───────────────────────────────────────────────────

export interface AlertSummary {
  total_alerts: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  alerts_last_5min: number;
  threat_class_counts: Record<string, number>;
}

// ─── System Metrics ──────────────────────────────────────────────────

export interface SystemMetrics {
  timestamp: string;
  events_per_sec: number;
  flows_per_sec: number;
  active_flows: number;
  detection_latency_ms: number;
  processing_latency_ms: number;
  ws_latency_ms: number;
  dropped_events: number;
  active_connections: number;
  memory_usage_mb: number;
  system_health: SystemHealth;
  total_packets: number;
  total_bytes: number;
  current_traffic_rate_mbps: number;
}

// ─── Simulation ──────────────────────────────────────────────────────

export interface SimulationStatus {
  state: SimulationState;
  current_scenario: string;
  current_phase: string | null;
  phase_index: number;
  total_phases: number;
  events_generated: number;
  elapsed_seconds: number;
  event_rate: number;
  demo_phase: DemoPhaseInfo | null;
}

export interface DemoPhaseInfo {
  phase_name: string;
  phase_index: number;
  total_phases: number;
  description: string;
  expected_threats: string[];
}

// ─── Security Posture ────────────────────────────────────────────────

export interface SecurityPosture {
  monitoring_mode: string;
  traffic_direction: string;
  return_path: string;
  active_probing: string;
  payload_decryption: string;
}

// ─── WebSocket Event ─────────────────────────────────────────────────

export interface WSEvent<T = unknown> {
  type: 'traffic_update' | 'alert' | 'metrics_update' | 'demo_phase' | 'system_status' | 'heartbeat' | 'pong';
  data: T;
  timestamp: number;
}

// ─── Threat Category ─────────────────────────────────────────────────

export interface ThreatCategory {
  threat_class: ThreatClass;
  display_name: string;
  count: number;
  recent_flows: FlowEvent[];
}

// ─── Utility types ───────────────────────────────────────────────────

export const THREAT_CLASS_LABELS: Record<ThreatClass, string> = {
  BENIGN: 'Benign',
  SYN_FLOOD: 'SYN Flood',
  UDP_REFLECTION: 'UDP Reflection',
  BOTNET_C2: 'C2 Beaconing',
  DGA_DOMAIN: 'DGA Domain',
  DNS_TUNNELING: 'DNS Tunneling',
  MALWARE_TLS: 'TLS/QUIC Threat',
  RECON_SCAN: 'Reconnaissance',
  DATA_EXFILTRATION: 'Data Exfiltration',
};

export const SEVERITY_ORDER: Record<Severity, number> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};
