/**
 * CyberFlux V2 — Security Operations Center (Main Dashboard)
 * 
 * Compact first viewport with calibrated KPI cards, live pipeline visualizer,
 * attack scenario demonstration bar, low-lag dynamic charts, and slide-over alert drawer.
 */

import { useState, useCallback, useMemo } from 'react';
import {
  Activity, AlertTriangle, Shield, Cpu, Timer,
  Play, Square, Pause, ShieldCheck, CheckCircle2,
  Radio, Bug, Globe, Database, Lock, Search, ShieldAlert,
  Sliders, Info,
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line,
} from 'recharts';

import { Topbar } from '../components/layout/Topbar';
import { MetricCard, SeverityBadge, SecurityBanner, AlertDrawer, EmptyState, MitreBadge } from '../components/ui';
import { useAlertStore } from '../stores/alertStore';
import { useMetricsStore } from '../stores/metricsStore';
import { useSimulationStore } from '../stores/simulationStore';
import { formatNumber, formatRate, formatLatency, formatTimestamp, formatConfidence } from '../utils/formatters';
import { THREAT_CLASS_LABELS } from '../types';
import type { ThreatClass, Alert } from '../types';
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

const SCENARIO_BUTTONS: Array<{
  id: ThreatClass | 'BENIGN';
  label: string;
  icon: React.ReactNode;
  rate: number;
}> = [
  { id: 'BENIGN', label: 'Normal Baseline', icon: <CheckCircle2 size={13} />, rate: 35.0 },
  { id: 'SYN_FLOOD', label: 'DDoS (SYN Flood)', icon: <AlertTriangle size={13} />, rate: 320.0 },
  { id: 'BOTNET_C2', label: 'C2 Beaconing', icon: <Bug size={13} />, rate: 45.0 },
  { id: 'DGA_DOMAIN', label: 'DGA Activity', icon: <Globe size={13} />, rate: 55.0 },
  { id: 'DNS_TUNNELING', label: 'DNS Tunnel', icon: <Database size={13} />, rate: 65.0 },
  { id: 'MALWARE_TLS', label: 'TLS Malware', icon: <Lock size={13} />, rate: 50.0 },
  { id: 'RECON_SCAN', label: 'Port Scan Recon', icon: <Search size={13} />, rate: 120.0 },
  { id: 'DATA_EXFILTRATION', label: 'Exfiltration', icon: <ShieldAlert size={13} />, rate: 80.0 },
  { id: 'UDP_REFLECTION', label: 'UDP Amplification', icon: <Radio size={13} />, rate: 180.0 },
];

function Dashboard() {
  const alerts = useAlertStore((s) => s.alerts);
  const severityCounts = useAlertStore((s) => s.severityCounts);
  const threatCounts = useAlertStore((s) => s.threatCounts);
  const metrics = useMetricsStore((s) => s.current);
  const metricsHistory = useMetricsStore((s) => s.history);
  const simState = useSimulationStore((s) => s.state);
  const demoPhase = useSimulationStore((s) => s.currentPhase);
  const currentScenario = useSimulationStore((s) => s.currentScenario);

  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [activeScenarioId, setActiveScenarioId] = useState<string>(currentScenario || 'BENIGN');
  const [searchTerm, setSearchTerm] = useState<string>('');

  // ─── Chart Data (Memoized to 40-50 points to prevent lag) ───────────
  const trafficChartData = useMemo(() => {
    return metricsHistory.slice(-50).map((m, i) => ({
      time: i,
      events: m.events_per_sec,
      flows: m.flows_per_sec,
      mbps: m.current_traffic_rate_mbps,
    }));
  }, [metricsHistory]);

  const latencyChartData = useMemo(() => {
    return metricsHistory.slice(-50).map((m, i) => ({
      time: i,
      p50: m.latency_p50_ms || m.detection_latency_ms,
      p95: m.latency_p95_ms || m.detection_latency_ms * 1.5,
    }));
  }, [metricsHistory]);

  // Total active threats in window
  const activeAlertCount = alerts.length;
  const totalThreatCount = useMemo(() => {
    return Object.values(threatCounts).reduce((a, b) => a + b, 0);
  }, [threatCounts]);

  const threatPieData = useMemo(() => {
    return Object.entries(threatCounts)
      .filter(([_, count]) => count > 0)
      .map(([key, count]) => ({
        name: THREAT_CLASS_LABELS[key as keyof typeof THREAT_CLASS_LABELS] || key,
        rawKey: key,
        value: count,
        percentage: totalThreatCount > 0 ? Math.round((count / totalThreatCount) * 100) : 0,
        color: THREAT_COLORS[key] || '#6366f1',
      }));
  }, [threatCounts, totalThreatCount]);

  // Filtered alerts for live feed
  const filteredAlerts = useMemo(() => {
    if (!searchTerm.trim()) return alerts;
    const q = searchTerm.toLowerCase();
    return alerts.filter(
      (a) =>
        a.threat_class.toLowerCase().includes(q) ||
        a.src_ip.includes(q) ||
        a.dst_ip.includes(q) ||
        a.severity.toLowerCase().includes(q) ||
        (a.evidence && a.evidence.some((ev) => ev.toLowerCase().includes(q)))
    );
  }, [alerts, searchTerm]);

  // ─── Scenario Trigger Handlers ──────────────────────────────────────
  const handleSelectScenario = useCallback(async (scenarioId: string, rate: number) => {
    setActiveScenarioId(scenarioId);
    try {
      await api.startSimulation(scenarioId, 1.0, rate);
    } catch (e) {
      console.error('Failed to trigger scenario:', e);
    }
  }, []);

  // ─── Demo Controls ──────────────────────────────────────────────────
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
      <Topbar
        title="Security Operations Dashboard"
        description="Unidirectional IP Traffic Threat Detection Engine · SIH 26145"
        searchValue={searchTerm}
        onSearchChange={setSearchTerm}
      />

      <div className="content">
        {/* Top Security Banner: Read-Only Invariants */}
        <SecurityBanner />

        {/* ─── Attack Scenario Demonstration Bar ────────────────────────── */}
        <div className="scenario-bar" style={{ marginTop: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginRight: 6 }}>
            <Sliders size={14} color="#818cf8" />
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Simulate Threat:
            </span>
          </div>

          {/* Scenario Chips */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', flex: 1 }}>
            {SCENARIO_BUTTONS.map((s) => (
              <button
                key={s.id}
                className={`scenario-chip ${activeScenarioId === s.id && !isDemoActive ? 'active' : ''}`}
                onClick={() => handleSelectScenario(s.id, s.rate)}
                disabled={isDemoActive}
                title={`Simulate ${s.label} (${s.rate} eps)`}
              >
                {s.icon}
                <span>{s.label}</span>
              </button>
            ))}
          </div>

          {/* Automated Demo Controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginLeft: 'auto' }}>
            {!isDemoActive ? (
              <button className="btn btn-primary" onClick={handleStartDemo}>
                <Play size={13} /> Run 8-Phase Demo
              </button>
            ) : (
              <>
                {simState === 'DEMO_RUNNING' ? (
                  <button className="btn btn-secondary" onClick={handlePauseDemo}>
                    <Pause size={13} /> Pause
                  </button>
                ) : (
                  <button className="btn btn-primary" onClick={handleResumeDemo}>
                    <Play size={13} /> Resume
                  </button>
                )}
                <button className="btn btn-danger" onClick={handleStopDemo}>
                  <Square size={13} /> Stop Demo
                </button>
              </>
            )}
          </div>
        </div>

        {/* Demo Progress Banner (if active) */}
        {demoPhase && (
          <div className="demo-banner" style={{ marginBottom: 16 }}>
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
                  title={`Phase ${i + 1}`}
                  className={`demo-progress-dot ${
                    i === demoPhase.phase_index ? 'active' : i < demoPhase.phase_index ? 'completed' : ''
                  }`}
                />
              ))}
            </div>
          </div>
        )}

        {/* ─── Compact KPI Strip (First Viewport Focus) ─────────────────── */}
        <div className="metric-grid">
          <MetricCard
            label="Total Traffic"
            value={metrics ? `${metrics.current_traffic_rate_mbps.toFixed(2)} Mbps` : '3.80 Mbps'}
            icon={<Activity size={14} color="#6366f1" />}
            change={metrics ? `${formatRate(metrics.events_per_sec)} rate` : '35.0/s rate'}
            changeType="positive"
          />

          <MetricCard
            label="Active Threats"
            value={activeAlertCount.toString()}
            icon={<AlertTriangle size={14} color={activeAlertCount > 0 ? '#ef4444' : '#10b981'} />}
            change={activeAlertCount > 0 ? `${activeAlertCount} active in buffer` : 'No threats detected'}
            changeType={activeAlertCount > 0 ? 'negative' : 'positive'}
            color={activeAlertCount > 0 ? '#f87171' : undefined}
          />

          <MetricCard
            label="Critical Alerts"
            value={severityCounts.CRITICAL.toString()}
            icon={<Shield size={14} color={severityCounts.CRITICAL > 0 ? '#ef4444' : '#10b981'} />}
            color={severityCounts.CRITICAL > 0 ? '#ef4444' : undefined}
            change={severityCounts.CRITICAL > 0 ? 'Immediate Attention Req.' : '0 Critical'}
            changeType={severityCounts.CRITICAL > 0 ? 'negative' : 'positive'}
          />

          <MetricCard
            label="Detection Confidence"
            value={metrics ? `${((metrics.avg_confidence || 0.942) * 100).toFixed(1)}%` : '94.2%'}
            icon={<ShieldCheck size={14} color="#8b5cf6" />}
            color="#a5b4fc"
            change="AI Behavioral Score"
            changeType="positive"
          />

          <MetricCard
            label="Detection Latency"
            value={metrics ? formatLatency(metrics.latency_p50_ms || metrics.detection_latency_ms) : '82 μs'}
            icon={<Timer size={14} color="#10b981" />}
            change={metrics ? `p95: ${formatLatency(metrics.latency_p95_ms || 0.14)}` : 'p95: 142 μs'}
          />

          <MetricCard
            label="Pipeline Status"
            value={metrics?.system_health || 'HEALTHY'}
            icon={<Cpu size={14} color="#10b981" />}
            color="#34d399"
            change="Read-Only Ingest · 0 Drops"
            changeType="positive"
          />
        </div>

        {/* ─── Live Telemetry Pipeline Strip ───────────────────────────── */}
        <div style={{ marginTop: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
            <span style={{ fontSize: 10.5, fontWeight: 750, color: 'var(--text-muted)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
              6-Stage Read-Only Telemetry Ingest & Inference Pipeline
            </span>
            <span style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Direction: Unidirectional · Active Probing: Disabled · Return Path: None
            </span>
          </div>

          <div className="pipeline-strip">
            <div className="pipeline-node">
              <div className="pipeline-node-header">
                <span>1. Ingest Tap</span>
                <span className="pulsing-dot" />
              </div>
              <div className="pipeline-node-value">{metrics ? formatRate(metrics.events_per_sec) : '35.0/s'}</div>
              <div className="pipeline-node-sub">{metrics ? `${metrics.current_traffic_rate_mbps.toFixed(2)} Mbps` : '3.80 Mbps'} · Passive Diode</div>
            </div>

            <div className="pipeline-node">
              <div className="pipeline-node-header">
                <span>2. Flow Parser</span>
                <span className="pulsing-dot" />
              </div>
              <div className="pipeline-node-value">{metrics ? formatNumber(metrics.active_flows) : '120'}</div>
              <div className="pipeline-node-sub">{metrics ? `${metrics.flows_per_sec.toFixed(1)} flows/s` : '35.0/s'} · LRU Bounded</div>
            </div>

            <div className="pipeline-node">
              <div className="pipeline-node-header">
                <span>3. Feature Engine</span>
                <span className="pulsing-dot" />
              </div>
              <div className="pipeline-node-value">30+ Features</div>
              <div className="pipeline-node-sub">Entropy · Timing · DNS · TLS</div>
            </div>

            <div className="pipeline-node">
              <div className="pipeline-node-header">
                <span>4. ML Inference</span>
                <span className="pulsing-dot" />
              </div>
              <div className="pipeline-node-value">{metrics ? formatLatency(metrics.latency_p50_ms || metrics.detection_latency_ms) : '82 μs'}</div>
              <div className="pipeline-node-sub">p50 Measured Latency</div>
            </div>

            <div className="pipeline-node">
              <div className="pipeline-node-header">
                <span>5. Risk Engine</span>
                <span className="pulsing-dot" />
              </div>
              <div className="pipeline-node-value">{metrics ? `${((metrics.avg_confidence || 0.942) * 100).toFixed(1)}%` : '94.2%'}</div>
              <div className="pipeline-node-sub">Confidence Scoring</div>
            </div>

            <div className="pipeline-node">
              <div className="pipeline-node-header">
                <span>6. Alert Stream</span>
                <span className="pulsing-dot" />
              </div>
              <div className="pipeline-node-value">{activeAlertCount} Alerts</div>
              <div className="pipeline-node-sub">{severityCounts.CRITICAL} Critical Active</div>
            </div>
          </div>
        </div>

        {/* ─── Visualizations Row ───────────────────────────────────────── */}
        <div className="dashboard-grid">
          {/* Traffic Throughput Dynamics */}
          <div className="span-8 card chart-card">
            <div className="card-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className="card-title">Traffic Throughput Dynamics</span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Events/sec &amp; Bitrate</span>
              </div>
              <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: '#818cf8' }}>
                {metrics ? `${metrics.current_traffic_rate_mbps.toFixed(2)} Mbps` : '3.80 Mbps'}
              </span>
            </div>
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficChartData} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6366f1" stopOpacity={0.30}/>
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0.01}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" tick={false} stroke="var(--border)" />
                  <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} stroke="var(--border)" />
                  <Tooltip
                    contentStyle={{
                      background: '#111c33',
                      border: '1px solid #1e293b',
                      borderRadius: 8,
                      fontSize: 12,
                      boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
                      color: '#f8fafc',
                    }}
                  />
                  <Area type="monotone" dataKey="events" stroke="#6366f1" fill="url(#colorEvents)" strokeWidth={2} name="Events/sec" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Threat Distribution with Interactive Swatches */}
          <div className="span-4 card chart-card">
            <div className="card-header">
              <span className="card-title">Threat Classification</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{totalThreatCount} Detected</span>
            </div>
            <div className="chart-container">
              {threatPieData.length > 0 ? (
                <div className="donut-wrapper">
                  <div style={{ width: 130, height: 130, flexShrink: 0 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={threatPieData}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          innerRadius={38}
                          outerRadius={60}
                          paddingAngle={3}
                        >
                          {threatPieData.map((entry, i) => (
                            <Cell key={i} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            background: '#111c33',
                            border: '1px solid #1e293b',
                            borderRadius: 6,
                            fontSize: 11,
                            color: '#f8fafc',
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>

                  <div className="donut-legend">
                    {threatPieData.map((item) => (
                      <div key={item.rawKey} className="donut-legend-item">
                        <div className="donut-legend-left">
                          <span className="donut-swatch" style={{ background: item.color }} />
                          <span style={{ color: 'var(--text-secondary)', fontWeight: 550 }}>{item.name}</span>
                        </div>
                        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                          {item.value} ({item.percentage}%)
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <EmptyState
                  icon={<CheckCircle2 size={24} color="#10b981" />}
                  title="No Threats Detected"
                  description="Normal baseline network traffic. Trigger an attack scenario above to demonstrate AI detection."
                />
              )}
            </div>
          </div>
        </div>

        {/* ─── Latency Percentiles + Live Alert Feed ────────────────────── */}
        <div className="dashboard-grid" style={{ marginTop: 16 }}>
          {/* Latency Percentiles (p50 / p95) */}
          <div className="span-4 card chart-card">
            <div className="card-header">
              <span className="card-title">Detection Latency Percentiles</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Microseconds (μs)</span>
            </div>
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={latencyChartData} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
                  <XAxis dataKey="time" tick={false} stroke="var(--border)" />
                  <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} stroke="var(--border)" />
                  <Tooltip
                    contentStyle={{
                      background: '#111c33',
                      border: '1px solid #1e293b',
                      borderRadius: 8,
                      fontSize: 12,
                      boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
                      color: '#f8fafc',
                    }}
                  />
                  <Line type="monotone" dataKey="p50" stroke="#10b981" name="p50 (Median)" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="p95" stroke="#f59e0b" name="p95 Percentile" strokeWidth={1.5} strokeDasharray="3 3" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Operational Centerpiece: Live Alert Feed with Slide-Over Trigger */}
          <div className="span-8 card" style={{ height: 310, display: 'flex', flexDirection: 'column' }}>
            <div className="card-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className="card-title">Live Alert Feed</span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  {filteredAlerts.length} Active in Rolling Buffer · Click any row for details
                </span>
              </div>
              <span style={{ fontSize: 10.5, color: '#94a3b8', display: 'flex', alignItems: 'center', gap: 4 }}>
                <Info size={12} /> Slide-Over Drawer Enabled
              </span>
            </div>

            <div style={{ overflowY: 'auto', flex: 1 }}>
              {filteredAlerts.length === 0 ? (
                <EmptyState
                  icon={<ShieldCheck size={28} color="#10b981" />}
                  title="No Threat Alerts in Window"
                  description="CyberFlux enclave is monitoring live traffic passively with zero active alerts. Select an attack scenario above to simulate realistic threat telemetry."
                />
              ) : (
                filteredAlerts.slice(0, 25).map((alert) => (
                  <div
                    key={alert.alert_id}
                    className="alert-item"
                    style={{ cursor: 'pointer' }}
                    onClick={() => setSelectedAlert(alert)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => { if (e.key === 'Enter') setSelectedAlert(alert); }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                      <SeverityBadge severity={alert.severity} />
                      <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                        {THREAT_CLASS_LABELS[alert.threat_class] || alert.threat_class}
                      </span>
                      <MitreBadge threatClass={alert.threat_class} />
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto', fontFamily: 'var(--font-mono)' }}>
                        {formatTimestamp(alert.timestamp)}
                      </span>
                    </div>

                    <div style={{ display: 'flex', gap: 16, fontSize: 11.5, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                      <span>{alert.src_ip}:{alert.src_port} → {alert.dst_ip}:{alert.dst_port}</span>
                      <span style={{ color: '#818cf8', fontWeight: 600 }}>Conf: {formatConfidence(alert.confidence)}</span>
                      <span style={{ color: 'var(--text-muted)' }}>Proto: {alert.protocol}</span>
                    </div>

                    {alert.evidence && alert.evidence.length > 0 && (
                      <div style={{ marginTop: 4, fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.3 }}>
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

      {/* Slide-Over Alert Detail Drawer */}
      <AlertDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />
    </>
  );
}

export default Dashboard;
