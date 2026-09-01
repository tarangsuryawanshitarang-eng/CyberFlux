/**
 * CyberFlux — SOC Dashboard (Main Page)
 * 
 * KPI cards, traffic chart, threat distribution, live alert feed, demo controls.
 */

import { useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity, AlertTriangle, Shield, Cpu, Zap, Timer, Wifi, Database,
  Play, Square, Pause,
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line,
} from 'recharts';

import { Topbar } from '../components/layout/Topbar';
import { MetricCard, SeverityBadge, SecurityBanner } from '../components/ui';
import { useAlertStore } from '../stores/alertStore';
import { useMetricsStore } from '../stores/metricsStore';
import { useSimulationStore } from '../stores/simulationStore';
import { formatNumber, formatRate, formatLatency, formatTimestamp, formatConfidence } from '../utils/formatters';
import { THREAT_CLASS_LABELS } from '../types';
import { api } from '../services/api';

const THREAT_COLORS: Record<string, string> = {
  SYN_FLOOD: '#ef4444',
  UDP_REFLECTION: '#f97316',
  BOTNET_C2: '#8b5cf6',
  DGA_DOMAIN: '#06b6d4',
  DNS_TUNNELING: '#3b82f6',
  MALWARE_TLS: '#ec4899',
  RECON_SCAN: '#eab308',
  DATA_EXFILTRATION: '#14b8a6',
};

function Dashboard() {
  const navigate = useNavigate();
  const alerts = useAlertStore((s) => s.alerts);
  const severityCounts = useAlertStore((s) => s.severityCounts);
  const threatCounts = useAlertStore((s) => s.threatCounts);
  const metrics = useMetricsStore((s) => s.current);
  const metricsHistory = useMetricsStore((s) => s.history);
  const simState = useSimulationStore((s) => s.state);
  const demoPhase = useSimulationStore((s) => s.currentPhase);

  // ─── Chart Data (memoized) ──────────────────────────────────────
  const trafficChartData = useMemo(() => {
    return metricsHistory.slice(-60).map((m, i) => ({
      time: i,
      events: m.events_per_sec,
      flows: m.flows_per_sec,
    }));
  }, [metricsHistory]);

  const latencyChartData = useMemo(() => {
    return metricsHistory.slice(-60).map((m, i) => ({
      time: i,
      latency: m.detection_latency_ms,
    }));
  }, [metricsHistory]);

  const threatPieData = useMemo(() => {
    return Object.entries(threatCounts)
      .filter(([_, count]) => count > 0)
      .map(([key, count]) => ({
        name: THREAT_CLASS_LABELS[key as keyof typeof THREAT_CLASS_LABELS] || key,
        value: count,
        color: THREAT_COLORS[key] || '#6d3df5',
      }));
  }, [threatCounts]);

  // ─── Demo Controls ─────────────────────────────────────────────
  const handleStartDemo = useCallback(async () => {
    try { await api.startDemo(); } catch (e) { console.error(e); }
  }, []);

  const handleStopDemo = useCallback(async () => {
    try { await api.stopDemo(); } catch (e) { console.error(e); }
  }, []);

  const handlePauseDemo = useCallback(async () => {
    try { await api.pauseDemo(); } catch (e) { console.error(e); }
  }, []);

  const handleResumeDemo = useCallback(async () => {
    try { await api.resumeDemo(); } catch (e) { console.error(e); }
  }, []);

  const isDemoActive = simState === 'DEMO_RUNNING' || simState === 'DEMO_PAUSED';

  return (
    <>
      <Topbar title="Security Operations Dashboard" description="Real-time AI threat detection in unidirectional IP traffic" />
      <div className="content">
        {/* Security Banner */}
        <SecurityBanner />

        {/* Demo Controls */}
        <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          {!isDemoActive ? (
            <button className="btn btn-primary btn-lg" onClick={handleStartDemo}>
              <Play size={16} /> START DEMO
            </button>
          ) : (
            <>
              {simState === 'DEMO_RUNNING' ? (
                <button className="btn btn-secondary" onClick={handlePauseDemo}>
                  <Pause size={14} /> Pause
                </button>
              ) : (
                <button className="btn btn-primary" onClick={handleResumeDemo}>
                  <Play size={14} /> Resume
                </button>
              )}
              <button className="btn btn-danger" onClick={handleStopDemo}>
                <Square size={14} /> Stop Demo
              </button>
            </>
          )}

          {demoPhase && (
            <div className="demo-banner" style={{ flex: 1 }}>
              <div>
                <div className="demo-banner-phase">
                  Phase {(demoPhase.phase_index || 0) + 1}/{demoPhase.total_phases}: {demoPhase.phase_name}
                </div>
                <div className="demo-banner-description">{demoPhase.description}</div>
              </div>
              <div className="demo-progress">
                {Array.from({ length: demoPhase.total_phases }).map((_, i) => (
                  <div
                    key={i}
                    className={`demo-progress-dot ${
                      i === demoPhase.phase_index ? 'active' : i < demoPhase.phase_index ? 'completed' : ''
                    }`}
                  />
                ))}
              </div>
            </div>
          )}
        </div>

        {/* KPI Metrics */}
        <div className="metric-grid" style={{ marginTop: 20 }}>
          <MetricCard
            label="Traffic Rate"
            value={metrics ? formatRate(metrics.events_per_sec) : '—'}
            icon={<Activity size={14} />}
            change={metrics ? `${metrics.current_traffic_rate_mbps.toFixed(2)} Mbps` : ''}
          />
          <MetricCard
            label="Active Flows"
            value={metrics ? formatNumber(metrics.active_flows) : '—'}
            icon={<Wifi size={14} />}
          />
          <MetricCard
            label="Alerts (5 min)"
            value={alerts.length > 0 ? alerts.filter(a => {
              const t = new Date(a.timestamp).getTime();
              return Date.now() - t < 300000;
            }).length.toString() : '0'}
            icon={<AlertTriangle size={14} />}
            color={severityCounts.CRITICAL > 0 ? 'var(--danger)' : undefined}
          />
          <MetricCard
            label="Critical Alerts"
            value={severityCounts.CRITICAL.toString()}
            icon={<Shield size={14} />}
            color={severityCounts.CRITICAL > 0 ? 'var(--danger)' : undefined}
          />
          <MetricCard
            label="Detection Latency"
            value={metrics ? formatLatency(metrics.detection_latency_ms) : '—'}
            icon={<Timer size={14} />}
            change="Measured, not simulated"
          />
          <MetricCard
            label="Flows/sec"
            value={metrics ? metrics.flows_per_sec.toFixed(1) : '—'}
            icon={<Zap size={14} />}
          />
          <MetricCard
            label="System Health"
            value={metrics?.system_health || 'HEALTHY'}
            icon={<Cpu size={14} />}
            color={metrics?.system_health === 'HEALTHY' ? 'var(--success)' : 'var(--warning)'}
          />
          <MetricCard
            label="Memory"
            value={metrics ? `${metrics.memory_usage_mb.toFixed(0)} MB` : '—'}
            icon={<Database size={14} />}
          />
        </div>

        {/* Charts Row */}
        <div className="dashboard-grid" style={{ marginTop: 20 }}>
          {/* Traffic Throughput */}
          <div className="span-8 card chart-card">
            <div className="card-header">
              <span className="card-title">Traffic Throughput</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Events/sec over time</span>
            </div>
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficChartData}>
                  <defs>
                    <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6d3df5" stopOpacity={0.15}/>
                      <stop offset="95%" stopColor="#6d3df5" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" tick={false} stroke="var(--border)" />
                  <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} stroke="var(--border)" />
                  <Tooltip
                    contentStyle={{
                      background: 'white',
                      border: '1px solid var(--border)',
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Area type="monotone" dataKey="events" stroke="#6d3df5" fill="url(#colorEvents)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Threat Distribution */}
          <div className="span-4 card chart-card">
            <div className="card-header">
              <span className="card-title">Threat Distribution</span>
            </div>
            <div className="chart-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              {threatPieData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={threatPieData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={80}
                      paddingAngle={2}
                    >
                      {threatPieData.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No threats detected</div>
              )}
            </div>
          </div>
        </div>

        {/* Detection Latency + Alert Feed */}
        <div className="dashboard-grid" style={{ marginTop: 16 }}>
          {/* Detection Latency Chart */}
          <div className="span-4 card chart-card">
            <div className="card-header">
              <span className="card-title">Detection Latency</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>ms (measured)</span>
            </div>
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={latencyChartData}>
                  <XAxis dataKey="time" tick={false} stroke="var(--border)" />
                  <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} stroke="var(--border)" />
                  <Tooltip
                    contentStyle={{
                      background: 'white',
                      border: '1px solid var(--border)',
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Line type="monotone" dataKey="latency" stroke="#16a34a" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Live Alert Feed */}
          <div className="span-8 card" style={{ maxHeight: 400, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
            <div className="card-header">
              <span className="card-title">Live Alert Feed</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{alerts.length} alerts</span>
            </div>
            <div style={{ overflow: 'auto', flex: 1 }}>
              {alerts.length === 0 ? (
                <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                  No alerts yet — start the demo or wait for threat detection
                </div>
              ) : (
                alerts.slice(0, 20).map((alert) => (
                  <div
                    key={alert.alert_id}
                    className="alert-item"
                    style={{ cursor: 'pointer' }}
                    onClick={() => navigate(`/flow/${alert.flow_id}`)}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
                      <SeverityBadge severity={alert.severity} />
                      <span style={{ fontSize: 13, fontWeight: 650 }}>
                        {THREAT_CLASS_LABELS[alert.threat_class] || alert.threat_class}
                      </span>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto', fontFamily: 'var(--font-mono)' }}>
                        {formatTimestamp(alert.timestamp)}
                      </span>
                    </div>
                    <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                      <span>{alert.src_ip}:{alert.src_port} → {alert.dst_ip}:{alert.dst_port}</span>
                      <span>Confidence: {formatConfidence(alert.confidence)}</span>
                    </div>
                    {alert.evidence.length > 0 && (
                      <div style={{ marginTop: 4, fontSize: 10, color: 'var(--text-muted)' }}>
                        {alert.evidence[0]}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

export default Dashboard;
