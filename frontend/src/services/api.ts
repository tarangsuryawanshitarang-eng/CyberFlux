/**
 * CyberFlux — REST API Client
 */

import { CONFIG } from '../utils/config';
import type { FlowEvent, Alert, SystemMetrics, SimulationStatus, ThreatCategory, SecurityPosture } from '../types';

async function fetchJSON<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${CONFIG.API_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    throw new Error(`API ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

export const api = {
  // Health
  health: () => fetchJSON<{ status: string; security_posture: SecurityPosture }>('/health'),
  securityPosture: () => fetchJSON<SecurityPosture>('/security-posture'),

  // Metrics
  metrics: () => fetchJSON<SystemMetrics>('/metrics'),
  metricsHistory: (limit = 60) => fetchJSON<SystemMetrics[]>(`/metrics/history?limit=${limit}`),

  // Flows
  flows: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return fetchJSON<FlowEvent[]>(`/flows${qs}`);
  },
  flow: (id: string) => fetchJSON<FlowEvent>(`/flows/${id}`),

  // Alerts
  alerts: (limit = 50) => fetchJSON<Alert[]>(`/alerts?limit=${limit}`),
  alertSummary: () => fetchJSON<Record<string, unknown>>('/alerts/summary'),

  // Threats
  threats: () => fetchJSON<ThreatCategory[]>('/threats'),

  // Simulation
  simulationStatus: () => fetchJSON<SimulationStatus>('/simulation/status'),
  startSimulation: (scenario = 'BENIGN', intensity = 1.0, eventRate = 50) =>
    fetchJSON<{ status: string }>(`/simulation/start?scenario=${scenario}&intensity=${intensity}&event_rate=${eventRate}`, { method: 'POST' }),
  stopSimulation: () => fetchJSON<{ status: string }>('/simulation/stop', { method: 'POST' }),
  pauseSimulation: () => fetchJSON<{ status: string }>('/simulation/pause', { method: 'POST' }),
  resumeSimulation: () => fetchJSON<{ status: string }>('/simulation/resume', { method: 'POST' }),

  // Demo
  startDemo: () => fetchJSON<{ status: string }>('/demo/start', { method: 'POST' }),
  stopDemo: () => fetchJSON<{ status: string }>('/demo/stop', { method: 'POST' }),
  pauseDemo: () => fetchJSON<{ status: string }>('/demo/pause', { method: 'POST' }),
  resumeDemo: () => fetchJSON<{ status: string }>('/demo/resume', { method: 'POST' }),

  // Detection
  detectionInfo: () => fetchJSON<{ detector_name: string; detector_type: string; note: string }>('/detection/info'),
};
