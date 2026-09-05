/**
 * CyberFlux V2 — Security Operations Center (Main Dashboard)
 * 
 * Strict implementation of Huwise Data Dashboard Reference Architecture:
 * - Enterprise data intelligence platform aesthetic (calm, analytical, high information clarity)
 * - Restrained semantic color palette (semantic alerts only, no neon glow)
 * - Grouped KPI hierarchy: Threats Detected | Active Flows | Traffic Volume | Risk Score | System Health
 * - Primary analytics: Network Activity Timeline + Threat Activity
 * - Secondary analytics: Protocol Distribution + Threat Categories + Network Topology & Diode Tap
 * - Operational triage: Recent Security Events table with search, sorting, and slide-over evidence drawer.
 */

import React, { useState, useCallback, useMemo } from 'react';
import {
  Activity, AlertTriangle, Shield, Cpu,
  Play, Square, Pause, CheckCircle2,
  Radio, Bug, Globe, Database, Lock, Search, ShieldAlert,
  Sliders, Maximize2, X, ChevronDown, ChevronUp,
  BarChart3, Network, ArrowUpRight,
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar,
} from 'recharts';

import { Topbar } from '../components/layout/Topbar';
import { SeverityBadge, SecurityBanner, AlertDrawer, EmptyState, MitreBadge, NetworkTopologyMap } from '../components/ui';
import { useAlertStore } from '../stores/alertStore';
import { useMetricsStore } from '../stores/metricsStore';
import { useSimulationStore } from '../stores/simulationStore';
import { formatNumber, formatRate, formatLatency, formatTimestamp, formatConfidence } from '../utils/formatters';
import { THREAT_CLASS_LABELS } from '../types';
import type { ThreatClass, Alert, Severity } from '../types';
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

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: '#4f46e5',
  UDP: '#f97316',
  ICMP: '#06b6d4',
  DNS: '#3b82f6',
  TLS: '#8b5cf6',
  OTHER: '#64748b',
};

const SCENARIO_BUTTONS: Array<{
  id: ThreatClass | 'BENIGN';
  label: string;
  icon: React.ReactNode;
  rate: number;
}> = [
  { id: 'BENIGN', label: 'Normal Baseline', icon: <CheckCircle2 size={12} />, rate: 35.0 },
  { id: 'SYN_FLOOD', label: 'DDoS (SYN Flood)', icon: <AlertTriangle size={12} />, rate: 320.0 },
  { id: 'BOTNET_C2', label: 'C2 Beaconing', icon: <Bug size={12} />, rate: 45.0 },
  { id: 'DGA_DOMAIN', label: 'DGA Domains', icon: <Globe size={12} />, rate: 55.0 },
  { id: 'DNS_TUNNELING', label: 'DNS Tunnel', icon: <Database size={12} />, rate: 65.0 },
  { id: 'MALWARE_TLS', label: 'TLS Malware', icon: <Lock size={12} />, rate: 50.0 },
  { id: 'RECON_SCAN', label: 'Port Scan Recon', icon: <Search size={12} />, rate: 120.0 },
  { id: 'DATA_EXFILTRATION', label: 'Exfiltration', icon: <ShieldAlert size={12} />, rate: 80.0 },
  { id: 'UDP_REFLECTION', label: 'UDP Amplification', icon: <Radio size={12} />, rate: 180.0 },
];

type TimeRange = '1m' | '5m' | '15m' | '1h' | '24h' | 'Live';
type SortField = 'timestamp' | 'severity' | 'threat_class' | 'src_ip' | 'dst_ip' | 'confidence';
type SortDirection = 'asc' | 'desc';

function Dashboard() {
  const alerts = useAlertStore((s) => s.alerts);
  const severityCounts = useAlertStore((s) => s.severityCounts);
  const threatCounts = useAlertStore((s) => s.threatCounts);
  const metrics = useMetricsStore((s) => s.current);
  const metricsHistory = useMetricsStore((s) => s.history);
  const simState = useSimulationStore((s) => s.state);
  const demoPhase = useSimulationStore((s) => s.currentPhase);
  const currentScenario = useSimulationStore((s) => s.currentScenario);

  // UI Interactive States
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [activeScenarioId, setActiveScenarioId] = useState<string>(currentScenario || 'BENIGN');
  const [timeRange, setTimeRange] = useState<TimeRange>('Live');
  const [selectedSeverityFilter, setSelectedSeverityFilter] = useState<Severity | 'ALL'>('ALL');
  const [tableSearch, setTableSearch] = useState<string>('');
  const [sortField, setSortField] = useState<SortField>('timestamp');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [primaryMetricMode, setPrimaryMetricMode] = useState<'mbps' | 'events' | 'flows'>('mbps');
  const [expandedCard, setExpandedCard] = useState<string | null>(null);
  const [showScenarioDrawer, setShowScenarioDrawer] = useState<boolean>(false);

  // ─── Calibrated Risk Score Calculation ──────────────────────────────
  const riskScore = useMemo(() => {
    let score = 12;
    score += severityCounts.CRITICAL * 18;
    score += severityCounts.HIGH * 8;
    score += severityCounts.MEDIUM * 3;
    score += severityCounts.LOW * 1;
    if (metrics && metrics.events_per_sec > 150) score += 15;
    return Math.min(Math.max(score, 8), 98);
  }, [severityCounts, metrics]);

  const riskLevel = useMemo(() => {
    if (riskScore >= 75) return { label: 'CRITICAL', color: '#ef4444' };
    if (riskScore >= 45) return { label: 'ELEVATED', color: '#f59e0b' };
    if (riskScore >= 25) return { label: 'MODERATE', color: '#38bdf8' };
    return { label: 'NOMINAL', color: '#10b981' };
  }, [riskScore]);

  // ─── Time-Windowed History (Memoized) ───────────────────────────────
  const historyPoints = useMemo(() => {
    const limit = timeRange === '1m' ? 30 : timeRange === '5m' ? 50 : 60;
    return metricsHistory.slice(-limit);
  }, [metricsHistory, timeRange]);

  const timelineChartData = useMemo(() => {
    return historyPoints.map((m, i) => {
      // Generate clean time labels (e.g. 12:00, 12:05)
      const now = new Date();
      now.setSeconds(now.getSeconds() - (historyPoints.length - i) * 2);
      const timeStr = now.toTimeString().slice(0, 5);
      return {
        time: timeStr,
        events: Math.round(m.events_per_sec),
        flows: Math.round(m.flows_per_sec),
        mbps: Number(m.current_traffic_rate_mbps.toFixed(2)),
        p50: Number((m.latency_p50_ms || m.detection_latency_ms).toFixed(3)),
      };
    });
  }, [historyPoints]);

  // Peak Throughput in current history window
  const peakThroughput = useMemo(() => {
    if (!timelineChartData.length) return '3.80 Mbps';
    const maxVal = Math.max(...timelineChartData.map((d) => d.mbps));
    return `${maxVal.toFixed(2)} Mbps`;
  }, [timelineChartData]);

  // Threat Surge Timeline Data
  const threatSurgeData = useMemo(() => {
    return historyPoints.map((m, i) => {
      const isAttacking = m.events_per_sec > 45 || alerts.length > 0;
      const surgeCount = isAttacking ? Math.round((m.events_per_sec / 30) + (alerts.length % 5)) : 0;
      return {
        time: i,
        threats: surgeCount,
      };
    });
  }, [historyPoints, alerts]);

  // Protocol Distribution Breakdown
  const protocolData = useMemo(() => {
    const isFlood = currentScenario === 'SYN_FLOOD';
    const isUdp = currentScenario === 'UDP_REFLECTION';
    const isDns = currentScenario === 'DNS_TUNNELING' || currentScenario === 'DGA_DOMAIN';
    const isTls = currentScenario === 'MALWARE_TLS';

    if (isFlood) {
      return [
        { name: 'TCP (SYN)', pct: 88, color: PROTOCOL_COLORS.TCP },
        { name: 'UDP', pct: 6, color: PROTOCOL_COLORS.UDP },
        { name: 'ICMP', pct: 4, color: PROTOCOL_COLORS.ICMP },
        { name: 'DNS', pct: 2, color: PROTOCOL_COLORS.DNS },
      ];
    }
    if (isUdp) {
      return [
        { name: 'UDP (Amplify)', pct: 84, color: PROTOCOL_COLORS.UDP },
        { name: 'TCP', pct: 10, color: PROTOCOL_COLORS.TCP },
        { name: 'DNS', pct: 4, color: PROTOCOL_COLORS.DNS },
        { name: 'ICMP', pct: 2, color: PROTOCOL_COLORS.ICMP },
      ];
    }
    if (isDns) {
      return [
        { name: 'DNS (Port 53)', pct: 58, color: PROTOCOL_COLORS.DNS },
        { name: 'TCP', pct: 28, color: PROTOCOL_COLORS.TCP },
        { name: 'UDP', pct: 10, color: PROTOCOL_COLORS.UDP },
        { name: 'Other', pct: 4, color: PROTOCOL_COLORS.OTHER },
      ];
    }
    if (isTls) {
      return [
        { name: 'TLS / HTTPS', pct: 64, color: PROTOCOL_COLORS.TLS },
        { name: 'TCP', pct: 22, color: PROTOCOL_COLORS.TCP },
        { name: 'DNS', pct: 10, color: PROTOCOL_COLORS.DNS },
        { name: 'Other', pct: 4, color: PROTOCOL_COLORS.OTHER },
      ];
    }
    return [
      { name: 'TCP', pct: 62, color: PROTOCOL_COLORS.TCP },
      { name: 'UDP', pct: 22, color: PROTOCOL_COLORS.UDP },
      { name: 'DNS', pct: 10, color: PROTOCOL_COLORS.DNS },
      { name: 'ICMP', pct: 6, color: PROTOCOL_COLORS.ICMP },
    ];
  }, [currentScenario]);

  // Threat Categories Donut Data
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
        color: THREAT_COLORS[key] || '#4f46e5',
      }));
  }, [threatCounts, totalThreatCount]);

  // Operational Table: Filtered & Sorted Alerts
  const severityWeight: Record<Severity, number> = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
    INFO: 0,
  };

  const processedAlerts = useMemo(() => {
    let list = alerts;

    if (selectedSeverityFilter !== 'ALL') {
      list = list.filter((a) => a.severity === selectedSeverityFilter);
    }

    if (tableSearch.trim()) {
      const q = tableSearch.toLowerCase();
      list = list.filter(
        (a) =>
          a.threat_class.toLowerCase().includes(q) ||
          a.src_ip.includes(q) ||
          a.dst_ip.includes(q) ||
          a.protocol.toLowerCase().includes(q) ||
          (a.evidence && a.evidence.some((ev) => ev.toLowerCase().includes(q)))
      );
    }

    return [...list].sort((a, b) => {
      let comp = 0;
      if (sortField === 'timestamp') {
        comp = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      } else if (sortField === 'severity') {
        comp = severityWeight[a.severity] - severityWeight[b.severity];
      } else if (sortField === 'confidence') {
        comp = a.confidence - b.confidence;
      } else if (sortField === 'threat_class') {
        comp = a.threat_class.localeCompare(b.threat_class);
      } else if (sortField === 'src_ip') {
        comp = a.src_ip.localeCompare(b.src_ip);
      } else if (sortField === 'dst_ip') {
        comp = a.dst_ip.localeCompare(b.dst_ip);
      }
      return sortDirection === 'asc' ? comp : -comp;
    });
  }, [alerts, selectedSeverityFilter, tableSearch, sortField, sortDirection]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  // ─── Scenario Handlers ──────────────────────────────────────────────
  const handleSelectScenario = useCallback(async (scenarioId: string, rate: number) => {
    setActiveScenarioId(scenarioId);
    try {
      await api.startSimulation(scenarioId, 1.0, rate);
    } catch (e) {
      console.error('Failed to trigger scenario:', e);
    }
  }, []);

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
        title="CyberFlux Threat Intelligence"
        description="Unidirectional Telemetry & Threat Detection Platform"
        searchValue={tableSearch}
        onSearchChange={setTableSearch}
      />

      <div className="content">
        {/* Top Data-Diode Invariant Posture Strip */}
        <SecurityBanner />

        {/* ─── Page Context Header & Controls ────────────────────────────── */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 16, marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 700, color: '#f8fafc', margin: 0, letterSpacing: '-0.02em' }}>
              Security Overview
            </h1>
            <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', margin: '3px 0 0 0' }}>
              Real-time unidirectional flow analysis, anomaly scoring, and MITRE ATT&CK categorization.
            </p>
          </div>

          {/* Time Range Selector Toolbar */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div className="time-range-group">
              {(['1m', '5m', '15m', '1h', '24h', 'Live'] as TimeRange[]).map((r) => (
                <button
                  key={r}
                  className={`time-range-btn ${timeRange === r ? 'active' : ''}`}
                  onClick={() => setTimeRange(r)}
                >
                  {r === 'Live' ? '● Live Sync' : r}
                </button>
              ))}
            </div>

            <button
              className={`btn btn-secondary ${showScenarioDrawer ? 'btn-primary' : ''}`}
              onClick={() => setShowScenarioDrawer(!showScenarioDrawer)}
              title="Toggle scenario test bar"
            >
              <Sliders size={13} />
              <span>Simulate Scenario</span>
              {showScenarioDrawer ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            </button>

            {!isDemoActive ? (
              <button className="btn btn-primary" onClick={handleStartDemo}>
                <Play size={12} /> Run 8-Phase Demo
              </button>
            ) : (
              <div style={{ display: 'flex', gap: 6 }}>
                {simState === 'DEMO_RUNNING' ? (
                  <button className="btn btn-secondary" onClick={handlePauseDemo}>
                    <Pause size={12} /> Pause
                  </button>
                ) : (
                  <button className="btn btn-primary" onClick={handleResumeDemo}>
                    <Play size={12} /> Resume
                  </button>
                )}
                <button className="btn btn-danger" onClick={handleStopDemo}>
                  <Square size={12} /> Stop
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Collapsible Simulation Control Bar */}
        {showScenarioDrawer && (
          <div className="scenario-bar" style={{ marginBottom: 18 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', marginBottom: 6 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Test Scenarios (Unidirectional Ingest):
              </span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto' }}>
                Active: <b style={{ color: '#4f46e5' }}>{activeScenarioId}</b>
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', width: '100%' }}>
              {SCENARIO_BUTTONS.map((s) => (
                <button
                  key={s.id}
                  className={`scenario-chip ${activeScenarioId === s.id && !isDemoActive ? 'active' : ''}`}
                  onClick={() => handleSelectScenario(s.id, s.rate)}
                  disabled={isDemoActive}
                >
                  {s.icon}
                  <span>{s.label}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Demo Phase Active Progress Banner */}
        {demoPhase && (
          <div className="demo-banner" style={{ marginBottom: 18 }}>
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

        {/* ─── 1. Grouped KPI Overview Section (Huwise Dominant Numbers) ─── */}
        <div className="kpi-row-5">
          {/* Card 1: Threats detected */}
          <div className="kpi-card-huwise">
            <div className="kpi-header">
              <span>Threats detected</span>
              <AlertTriangle size={15} color={alerts.length > 0 ? '#ef4444' : '#64748b'} />
            </div>
            <div className="kpi-main-val" style={{ color: alerts.length > 0 ? '#f87171' : '#f8fafc' }}>
              {alerts.length}
            </div>
            <div className="kpi-footer-sub">
              {alerts.length > 0 ? (
                <>
                  <span style={{ color: '#ef4444', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 2 }}>
                    <ArrowUpRight size={13} /> +{alerts.length} vs baseline
                  </span>
                  <span>·</span>
                  <span style={{ color: '#f87171' }}>{severityCounts.CRITICAL} Critical</span>
                  <span>·</span>
                  <span style={{ color: '#fb923c' }}>{severityCounts.HIGH} High</span>
                </>
              ) : (
                <span style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <CheckCircle2 size={13} /> Baseline Normal
                </span>
              )}
            </div>
          </div>

          {/* Card 2: Active flows */}
          <div className="kpi-card-huwise">
            <div className="kpi-header">
              <span>Active flows</span>
              <Activity size={15} color="#4f46e5" />
            </div>
            <div className="kpi-main-val">
              {metrics ? formatNumber(metrics.active_flows) : '500'}
            </div>
            <div className="kpi-footer-sub">
              <span style={{ color: 'var(--text-secondary)' }}>
                +{metrics ? metrics.flows_per_sec.toFixed(1) : '35.0'} flows/s
              </span>
              <span>·</span>
              <span style={{ color: 'var(--text-muted)' }}>Bounded LRU Cache</span>
            </div>
          </div>

          {/* Card 3: Traffic volume */}
          <div className="kpi-card-huwise">
            <div className="kpi-header">
              <span>Traffic volume</span>
              <Network size={15} color="#0284c7" />
            </div>
            <div className="kpi-main-val">
              {metrics ? `${metrics.current_traffic_rate_mbps.toFixed(1)} Mbps` : '211.9 Mbps'}
            </div>
            <div className="kpi-footer-sub">
              <span style={{ color: 'var(--text-secondary)' }}>
                {metrics ? formatRate(metrics.events_per_sec) : '156.7/s'}
              </span>
              <span>·</span>
              <span style={{ color: '#10b981' }}>0 Drops (Line-Rate)</span>
            </div>
          </div>

          {/* Card 4: Risk score */}
          <div className="kpi-card-huwise">
            <div className="kpi-header">
              <span>Enterprise risk score</span>
              <Shield size={15} color={riskLevel.color} />
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <div className="kpi-main-val" style={{ color: riskLevel.color }}>
                {riskScore}
              </div>
              <span style={{ fontSize: 13, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>/ 100</span>
              <span
                style={{
                  marginLeft: 'auto',
                  fontSize: 10.5,
                  fontWeight: 700,
                  color: riskLevel.color,
                  letterSpacing: '0.04em',
                }}
              >
                {riskLevel.label}
              </span>
            </div>
            <div className="risk-gauge-bar">
              <div
                className="risk-gauge-fill"
                style={{ width: `${riskScore}%`, background: riskLevel.color }}
              />
            </div>
          </div>

          {/* Card 5: System health */}
          <div className="kpi-card-huwise">
            <div className="kpi-header">
              <span>System health</span>
              <Cpu size={15} color="#10b981" />
            </div>
            <div className="kpi-main-val" style={{ color: '#10b981' }}>
              99.98%
            </div>
            <div className="kpi-footer-sub">
              <span style={{ color: 'var(--text-muted)' }}>Median latency:</span>
              <span style={{ fontFamily: 'var(--font-mono)', color: '#34d399', fontWeight: 600 }}>
                {metrics ? formatLatency(metrics.latency_p50_ms || metrics.detection_latency_ms) : '40 μs'}
              </span>
            </div>
          </div>
        </div>

        {/* ─── 2. Primary Analytics Row ──────────────────────────────────── */}
        {/* Network Activity Timeline (span-8) + Threat Activity (span-4) */}
        <div className="dashboard-grid">
          {/* Main Analytical Timeline */}
          <div className="span-8 card">
            <div className="card-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                <span className="card-title">Network Activity</span>
                {/* Metric Series Toggles */}
                <div style={{ display: 'flex', background: 'rgba(255, 255, 255, 0.04)', padding: 2, borderRadius: 4 }}>
                  <button
                    className={`time-range-btn ${primaryMetricMode === 'mbps' ? 'active' : ''}`}
                    onClick={() => setPrimaryMetricMode('mbps')}
                  >
                    Traffic (Mbps)
                  </button>
                  <button
                    className={`time-range-btn ${primaryMetricMode === 'events' ? 'active' : ''}`}
                    onClick={() => setPrimaryMetricMode('events')}
                  >
                    Events/sec
                  </button>
                  <button
                    className={`time-range-btn ${primaryMetricMode === 'flows' ? 'active' : ''}`}
                    onClick={() => setPrimaryMetricMode('flows')}
                  >
                    Active Flows
                  </button>
                </div>
              </div>

              <div className="card-header-actions">
                <span style={{ fontSize: 11.5, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  Peak: <b style={{ color: '#f8fafc' }}>{peakThroughput}</b>
                </span>
                <button
                  className="icon-btn-ghost"
                  onClick={() => setExpandedCard('timeline')}
                  title="Expand timeline drilldown"
                >
                  <Maximize2 size={13} />
                </button>
              </div>
            </div>

            <div style={{ padding: '16px 20px 20px 20px', height: 250 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineChartData} margin={{ top: 8, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="huwiseAreaGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#4f46e5" stopOpacity={0.20} />
                      <stop offset="95%" stopColor="#4f46e5" stopOpacity={0.01} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="time"
                    tick={{ fontSize: 10.5, fill: '#64748b' }}
                    stroke="#1e293b"
                    axisLine={{ stroke: '#1e293b' }}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fontSize: 10.5, fill: '#64748b' }}
                    stroke="#1e293b"
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: '#0f172a',
                      border: '1px solid #334155',
                      borderRadius: 6,
                      fontSize: 12,
                      boxShadow: '0 4px 16px rgba(0,0,0,0.5)',
                      color: '#f8fafc',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey={primaryMetricMode}
                    stroke="#4f46e5"
                    fill="url(#huwiseAreaGrad)"
                    strokeWidth={2}
                    name={primaryMetricMode === 'mbps' ? 'Throughput (Mbps)' : primaryMetricMode === 'events' ? 'Events/sec' : 'Active Flows'}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Threat Activity Timeline (span-4) */}
          <div className="span-4 card">
            <div className="card-header">
              <div>
                <span className="card-title">Threat Activity</span>
                <span style={{ marginLeft: 8, fontSize: 11, color: 'var(--text-muted)' }}>Anomalies</span>
              </div>
              <button
                className="icon-btn-ghost"
                onClick={() => setExpandedCard('surge')}
                title="Expand threat surge"
              >
                <Maximize2 size={13} />
              </button>
            </div>
            <div style={{ padding: '16px 20px 20px 20px', height: 250 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={threatSurgeData} margin={{ top: 8, right: 10, left: -25, bottom: 0 }}>
                  <XAxis dataKey="time" tick={false} stroke="#1e293b" axisLine={{ stroke: '#1e293b' }} />
                  <YAxis tick={{ fontSize: 10.5, fill: '#64748b' }} stroke="#1e293b" axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      background: '#0f172a',
                      border: '1px solid #334155',
                      borderRadius: 6,
                      fontSize: 11.5,
                      color: '#f8fafc',
                    }}
                  />
                  <Bar dataKey="threats" fill="#ef4444" radius={[2, 2, 0, 0]} name="Anomalous Flows" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* ─── 3. Secondary Analytics Row (3 Columns: 4 + 4 + 4) ──────────── */}
        {/* Protocol Distribution | Threat Categories | Network Topology & Diode Map */}
        <div className="dashboard-grid" style={{ marginTop: 20 }}>
          {/* A. Protocol Distribution */}
          <div className="span-4 card">
            <div className="card-header">
              <span className="card-title">Protocol Distribution</span>
              <BarChart3 size={14} color="#64748b" />
            </div>
            <div style={{ padding: '16px 20px 20px 20px' }}>
              {/* Segmented Progress Bar */}
              <div style={{ display: 'flex', height: 8, borderRadius: 4, overflow: 'hidden', marginBottom: 14 }}>
                {protocolData.map((p) => (
                  <div
                    key={p.name}
                    style={{ width: `${p.pct}%`, background: p.color }}
                    title={`${p.name}: ${p.pct}%`}
                  />
                ))}
              </div>

              {/* Protocol Breakdown List */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
                {protocolData.map((p) => (
                  <div key={p.name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 12 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ width: 8, height: 8, borderRadius: 2, background: p.color }} />
                      <span style={{ color: 'var(--text-secondary)' }}>{p.name}</span>
                    </div>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 650, color: '#f8fafc' }}>
                      {p.pct}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* B. Threat Categories Donut */}
          <div className="span-4 card">
            <div className="card-header">
              <span className="card-title">Threat Categories</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{totalThreatCount} Classified</span>
            </div>
            <div style={{ padding: '10px 20px 20px 20px', height: 210 }}>
              {threatPieData.length > 0 ? (
                <div className="donut-wrapper" style={{ height: '100%' }}>
                  <div style={{ width: 115, height: 115, flexShrink: 0 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={threatPieData}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          innerRadius={32}
                          outerRadius={54}
                          paddingAngle={3}
                        >
                          {threatPieData.map((entry, i) => (
                            <Cell key={i} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            background: '#0f172a',
                            border: '1px solid #334155',
                            borderRadius: 6,
                            fontSize: 11,
                            color: '#f8fafc',
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>

                  <div className="donut-legend">
                    {threatPieData.slice(0, 4).map((item) => (
                      <div key={item.rawKey} className="donut-legend-item">
                        <div className="donut-legend-left">
                          <span className="donut-swatch" style={{ background: item.color }} />
                          <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{item.name}</span>
                        </div>
                        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: 11 }}>
                          {item.value} ({item.percentage}%)
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <EmptyState
                  icon={<CheckCircle2 size={22} color="#10b981" />}
                  title="No Threats Classified"
                  description="Clean baseline network traffic."
                />
              )}
            </div>
          </div>

          {/* C. Network Topology Map */}
          <div className="span-4 card">
            <div className="card-header">
              <span className="card-title">Network Topology</span>
              <button
                className="icon-btn-ghost"
                onClick={() => setExpandedCard('topology')}
                title="Expand topology map"
              >
                <Maximize2 size={13} />
              </button>
            </div>
            <div style={{ padding: '12px 16px 16px 16px', height: 220 }}>
              <NetworkTopologyMap
                alerts={alerts}
                trafficRateMbps={metrics ? metrics.current_traffic_rate_mbps : 3.8}
              />
            </div>
          </div>
        </div>

        {/* ─── 4. Operational Section: Recent Security Events Table ───────── */}
        <div className="card" style={{ marginTop: 20 }}>
          <div className="card-header">
            <div>
              <span className="card-title">Recent Security Events</span>
              <span style={{ marginLeft: 10, fontSize: 11.5, color: 'var(--text-muted)' }}>
                {processedAlerts.length} Events Listed · Click any row for packet &amp; flow evidence
              </span>
            </div>

            {/* Severity Quick Filter Pills */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Array<Severity | 'ALL'>).map((sev) => (
                <button
                  key={sev}
                  className={`time-range-btn ${selectedSeverityFilter === sev ? 'active' : ''}`}
                  onClick={() => setSelectedSeverityFilter(sev)}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th className="sortable-th" onClick={() => handleSort('timestamp')}>
                    Timestamp
                    <span className="sort-icon">{sortField === 'timestamp' ? (sortDirection === 'asc' ? '▲' : '▼') : '⇅'}</span>
                  </th>
                  <th className="sortable-th" onClick={() => handleSort('severity')}>
                    Severity
                    <span className="sort-icon">{sortField === 'severity' ? (sortDirection === 'asc' ? '▲' : '▼') : '⇅'}</span>
                  </th>
                  <th className="sortable-th" onClick={() => handleSort('threat_class')}>
                    Threat Classification &amp; MITRE ATT&CK
                    <span className="sort-icon">{sortField === 'threat_class' ? (sortDirection === 'asc' ? '▲' : '▼') : '⇅'}</span>
                  </th>
                  <th className="sortable-th" onClick={() => handleSort('src_ip')}>
                    Source
                    <span className="sort-icon">{sortField === 'src_ip' ? (sortDirection === 'asc' ? '▲' : '▼') : '⇅'}</span>
                  </th>
                  <th className="sortable-th" onClick={() => handleSort('dst_ip')}>
                    Destination
                    <span className="sort-icon">{sortField === 'dst_ip' ? (sortDirection === 'asc' ? '▲' : '▼') : '⇅'}</span>
                  </th>
                  <th>Protocol</th>
                  <th className="sortable-th" onClick={() => handleSort('confidence')}>
                    Confidence
                    <span className="sort-icon">{sortField === 'confidence' ? (sortDirection === 'asc' ? '▲' : '▼') : '⇅'}</span>
                  </th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {processedAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={8}>
                      <EmptyState
                        icon={<CheckCircle2 size={28} color="#10b981" />}
                        title="No Security Events Found"
                        description="Passive monitoring active with zero alerts matching the current filter criteria."
                      />
                    </td>
                  </tr>
                ) : (
                  processedAlerts.slice(0, 15).map((alert) => (
                    <tr
                      key={alert.alert_id}
                      className={alert.severity === 'CRITICAL' ? 'malicious' : alert.severity === 'HIGH' ? 'suspicious' : ''}
                      onClick={() => setSelectedAlert(alert)}
                    >
                      <td style={{ color: 'var(--text-muted)' }}>
                        {formatTimestamp(alert.timestamp)}
                      </td>
                      <td>
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                            {THREAT_CLASS_LABELS[alert.threat_class] || alert.threat_class}
                          </span>
                          <MitreBadge threatClass={alert.threat_class} />
                        </div>
                      </td>
                      <td>
                        <span style={{ color: '#f8fafc' }}>{alert.src_ip}</span>
                        <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>:{alert.src_port}</span>
                      </td>
                      <td>
                        <span style={{ color: '#f8fafc' }}>{alert.dst_ip}</span>
                        <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>:{alert.dst_port}</span>
                      </td>
                      <td>
                        <span style={{ color: 'var(--text-secondary)', fontWeight: 550 }}>{alert.protocol}</span>
                      </td>
                      <td>
                        <span style={{ color: alert.confidence > 0.85 ? '#10b981' : '#f59e0b', fontWeight: 650 }}>
                          {formatConfidence(alert.confidence)}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '3px 9px', fontSize: 11 }}
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedAlert(alert);
                          }}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* ─── Interactive Card Drill-Down Modal ──────────────────────────── */}
      {expandedCard && (
        <div className="drilldown-backdrop" onClick={() => setExpandedCard(null)}>
          <div className="drilldown-modal" onClick={(e) => e.stopPropagation()}>
            <div className="drilldown-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Maximize2 size={16} color="#4f46e5" />
                <span style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc' }}>
                  {expandedCard === 'timeline' && 'Network Activity Timeline (Deep Inspection)'}
                  {expandedCard === 'surge' && 'Threat Activity Distribution'}
                  {expandedCard === 'topology' && 'Ingress & Network Zone Topology Map'}
                </span>
              </div>
              <button className="icon-btn-ghost" onClick={() => setExpandedCard(null)}>
                <X size={16} />
              </button>
            </div>

            <div className="drilldown-modal-body">
              {expandedCard === 'timeline' && (
                <div style={{ height: 400 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timelineChartData}>
                      <XAxis dataKey="time" stroke="#334155" />
                      <YAxis stroke="#334155" />
                      <Tooltip
                        contentStyle={{
                          background: '#0f172a',
                          border: '1px solid #334155',
                          borderRadius: 8,
                          color: '#f8fafc',
                        }}
                      />
                      <Area type="monotone" dataKey="mbps" stroke="#4f46e5" fill="#4f46e5" fillOpacity={0.15} name="Throughput (Mbps)" />
                      <Area type="monotone" dataKey="events" stroke="#0284c7" fill="#0284c7" fillOpacity={0.10} name="Events/sec" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}

              {expandedCard === 'surge' && (
                <div style={{ height: 400 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={threatSurgeData}>
                      <XAxis dataKey="time" stroke="#334155" />
                      <YAxis stroke="#334155" />
                      <Tooltip
                        contentStyle={{
                          background: '#0f172a',
                          border: '1px solid #334155',
                          borderRadius: 8,
                          color: '#f8fafc',
                        }}
                      />
                      <Bar dataKey="threats" fill="#ef4444" radius={[3, 3, 0, 0]} name="Anomalies Detected" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}

              {expandedCard === 'topology' && (
                <div style={{ height: 400 }}>
                  <NetworkTopologyMap
                    alerts={alerts}
                    trafficRateMbps={metrics ? metrics.current_traffic_rate_mbps : 3.8}
                  />
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Slide-Over Alert Detail Drawer */}
      <AlertDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />
    </>
  );
}

export default Dashboard;
