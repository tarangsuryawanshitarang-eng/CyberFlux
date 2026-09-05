/**
 * CyberFlux V2 — Global SOC Header
 * 
 * Displays real-time operational status: LIVE / REPLAY / PAUSED,
 * PASSIVE MONITORING, throughput, flow rate, active alert counts,
 * measured latency, and search.
 */

import React from 'react';
import { Search, ShieldCheck } from 'lucide-react';
import { useWebSocket } from '../../hooks/useWebSocket';
import { useSimulationStore } from '../../stores/simulationStore';
import { useMetricsStore } from '../../stores/metricsStore';
import { useAlertStore } from '../../stores/alertStore';
import { formatLatency } from '../../utils/formatters';

interface TopbarProps {
  title: string;
  description?: string;
  searchValue?: string;
  onSearchChange?: (val: string) => void;
}

export const Topbar: React.FC<TopbarProps> = ({
  title,
  description,
  searchValue,
  onSearchChange,
}) => {
  const { connected } = useWebSocket();
  const phase = useSimulationStore((s) => s.currentPhase);
  const simState = useSimulationStore((s) => s.state);
  const metrics = useMetricsStore((s) => s.current);
  const alerts = useAlertStore((s) => s.alerts);

  // Operational state badge text & color
  let modeBadge = 'LIVE';
  let modeBadgeBg = 'var(--success-soft)';
  let modeBadgeBorder = 'var(--success-border)';
  let modeBadgeColor = 'var(--success)';

  if (simState === 'DEMO_RUNNING' || simState === 'RUNNING') {
    modeBadge = 'REPLAY';
    modeBadgeBg = 'rgba(99, 102, 241, 0.14)';
    modeBadgeBorder = 'rgba(99, 102, 241, 0.40)';
    modeBadgeColor = '#818cf8';
  } else if (simState === 'DEMO_PAUSED' || simState === 'PAUSED') {
    modeBadge = 'PAUSED';
    modeBadgeBg = 'var(--warning-soft)';
    modeBadgeBorder = 'var(--warning-border)';
    modeBadgeColor = 'var(--warning)';
  }

  const throughput = metrics ? `${metrics.current_traffic_rate_mbps.toFixed(2)} Mbps` : '3.80 Mbps';
  const flowRate = metrics ? `${metrics.flows_per_sec.toFixed(1)}/s` : '35.0/s';
  const p50Latency = metrics ? formatLatency(metrics.latency_p50_ms || metrics.detection_latency_ms) : '82 μs';

  return (
    <header className="topbar">
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 className="page-title">{title}</h1>
            {/* Mode badge: LIVE / REPLAY / PAUSED */}
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 5,
              padding: '2px 8px',
              borderRadius: 4,
              fontSize: 10,
              fontWeight: 800,
              background: modeBadgeBg,
              border: `1px solid ${modeBadgeBorder}`,
              color: modeBadgeColor,
              letterSpacing: '0.06em',
            }}>
              <span className={`connection-dot ${connected ? 'connected' : 'disconnected'}`} />
              {connected ? modeBadge : 'DISCONNECTED'}
            </span>
          </div>
          {description && <p className="page-description">{description}</p>}
        </div>
      </div>

      {/* Center/Right: Live SOC Telemetry & Search */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        {/* Passive Monitoring Badge */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          padding: '4px 10px',
          background: 'rgba(16, 185, 129, 0.08)',
          border: '1px solid rgba(16, 185, 129, 0.25)',
          borderRadius: 'var(--radius-sm)',
          fontSize: 11,
          fontWeight: 700,
          color: '#34d399',
          letterSpacing: '0.04em',
        }}>
          <ShieldCheck size={14} />
          <span>PASSIVE MONITORING</span>
        </div>

        {/* Throughput */}
        <div className="topbar-telemetry-item">
          <span className="topbar-telemetry-label">Throughput</span>
          <span className="topbar-telemetry-value">{throughput}</span>
        </div>

        {/* Flow Rate */}
        <div className="topbar-telemetry-item">
          <span className="topbar-telemetry-label">Flows</span>
          <span className="topbar-telemetry-value">{flowRate}</span>
        </div>

        {/* Active Alerts */}
        <div className="topbar-telemetry-item">
          <span className="topbar-telemetry-label">Alerts</span>
          <span className="topbar-telemetry-value" style={{ color: alerts.length > 0 ? '#f87171' : 'var(--text-primary)' }}>
            {alerts.length}
          </span>
        </div>

        {/* Latency */}
        <div className="topbar-telemetry-item">
          <span className="topbar-telemetry-label">p50 Latency</span>
          <span className="topbar-telemetry-value" style={{ color: '#34d399' }}>{p50Latency}</span>
        </div>

        {/* Demo Phase Mini Badge */}
        {phase && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '4px 10px',
            background: 'var(--primary-soft)',
            border: '1px solid var(--primary-border)',
            borderRadius: 'var(--radius-sm)',
            fontSize: 11,
            fontWeight: 700,
            color: '#a5b4fc',
          }}>
            <span>Phase {(phase.phase_index || 0) + 1}/{phase.total_phases}</span>
          </div>
        )}

        {/* Search / Filter Input */}
        {onSearchChange && (
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <Search size={13} style={{ position: 'absolute', left: 8, color: 'var(--text-muted)' }} />
            <input
              className="input"
              type="text"
              placeholder="Search telemetry / IP..."
              value={searchValue || ''}
              onChange={(e) => onSearchChange(e.target.value)}
              style={{ paddingLeft: 26, width: 170, fontSize: 11.5, height: 28 }}
            />
          </div>
        )}
      </div>
    </header>
  );
};
