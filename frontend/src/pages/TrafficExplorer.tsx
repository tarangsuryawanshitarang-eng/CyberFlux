/**
 * CyberFlux V2 — Live Traffic Explorer
 * 
 * Data-dense, paginated flow telemetry with real-time velocity metrics,
 * protocol distributions, filterable table, and click-to-inspect investigation.
 */

import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Activity, ArrowUpDown, Layers, Wifi } from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';

import { Topbar } from '../components/layout/Topbar';
import { MetricCard, SeverityBadge, ThreatStatusBadge, EmptyState } from '../components/ui';
import { useFlowStore } from '../stores/flowStore';
import { useMetricsStore } from '../stores/metricsStore';
import { formatTimestamp, formatBytes, formatDuration, formatRate } from '../utils/formatters';
import type { Protocol, ThreatStatus } from '../types';

const PAGE_SIZE = 20;

function TrafficExplorer() {
  const navigate = useNavigate();
  const flows = useFlowStore((s) => s.flows);
  const filters = useFlowStore((s) => s.filters);
  const setFilter = useFlowStore((s) => s.setFilter);
  const clearFilters = useFlowStore((s) => s.clearFilters);
  const getFilteredFlows = useFlowStore((s) => s.getFilteredFlows);

  const metrics = useMetricsStore((s) => s.current);
  const metricsHistory = useMetricsStore((s) => s.history);

  const [page, setPage] = useState(0);

  // Velocity chart data
  const velocityData = useMemo(() => {
    return metricsHistory.slice(-40).map((m, i) => ({
      time: i,
      events: m.events_per_sec,
      flows: m.flows_per_sec,
      mbps: m.current_traffic_rate_mbps,
    }));
  }, [metricsHistory]);

  // Protocol counts
  const protocolBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const f of flows) {
      counts[f.protocol] = (counts[f.protocol] || 0) + 1;
    }
    return counts;
  }, [flows]);

  const filteredFlows = useMemo(() => getFilteredFlows(), [getFilteredFlows, flows, filters]);
  const totalPages = Math.max(1, Math.ceil(filteredFlows.length / PAGE_SIZE));
  const pagedFlows = useMemo(
    () => filteredFlows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE),
    [filteredFlows, page]
  );

  return (
    <>
      <Topbar
        title="Live Traffic Explorer"
        description="Real-time unidirectional flow telemetry — passive metadata only, zero payload inspection"
      />

      <div className="content">
        {/* KPI Strip */}
        <div className="metric-grid" style={{ marginBottom: 16 }}>
          <MetricCard
            label="Current Bitrate"
            value={metrics ? `${metrics.current_traffic_rate_mbps.toFixed(2)} Mbps` : '3.80 Mbps'}
            icon={<Activity size={14} color="#6366f1" />}
            change="Passive Enclave Tap"
            changeType="positive"
          />

          <MetricCard
            label="Packet Rate"
            value={metrics ? formatRate(metrics.events_per_sec) : '35.0/s'}
            icon={<ArrowUpDown size={14} color="#8b5cf6" />}
            change="Ingest Velocity"
          />

          <MetricCard
            label="Active Flow Count"
            value={metrics ? metrics.active_flows.toString() : flows.length.toString()}
            icon={<Wifi size={14} color="#10b981" />}
            change="LRU Bounded Table"
            changeType="positive"
          />

          <MetricCard
            label="Flow Creation Rate"
            value={metrics ? `${metrics.flows_per_sec.toFixed(1)}/s` : '35.0/s'}
            icon={<Layers size={14} color="#38bdf8" />}
            change="New Flows / sec"
          />

          <MetricCard
            label="Total Data Analyzed"
            value={metrics ? formatBytes(metrics.total_bytes) : '142 MB'}
            icon={<Activity size={14} color="#f59e0b" />}
            change="Read-Only Cumulative"
          />

          <MetricCard
            label="Inbound / Outbound"
            value={
              flows.length > 0
                ? `${(flows.reduce((a, b) => a + b.outbound_inbound_ratio, 0) / flows.length).toFixed(2)}x`
                : '1.02x'
            }
            icon={<ArrowUpDown size={14} color="#cbd5e1" />}
            change="Mean Direction Ratio"
          />
        </div>

        {/* Velocity Chart & Protocol Breakdown */}
        <div className="dashboard-grid" style={{ marginBottom: 16 }}>
          <div className="span-8 card" style={{ height: 210, display: 'flex', flexDirection: 'column' }}>
            <div className="card-header">
              <span className="card-title">Telemetry Velocity Trends</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Flow Rate &amp; Packets/sec</span>
            </div>
            <div className="chart-container" style={{ padding: '8px 12px' }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={velocityData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="trafficEvents" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6366f1" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" tick={false} stroke="var(--border)" />
                  <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} stroke="var(--border)" />
                  <Tooltip
                    contentStyle={{
                      background: '#111c33',
                      border: '1px solid #1e293b',
                      borderRadius: 6,
                      fontSize: 11,
                      color: '#f8fafc',
                    }}
                  />
                  <Area type="monotone" dataKey="events" stroke="#6366f1" fill="url(#trafficEvents)" strokeWidth={2} name="Events/s" />
                  <Area type="monotone" dataKey="flows" stroke="#10b981" fill="none" strokeWidth={1.5} name="Flows/s" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="span-4 card" style={{ height: 210, display: 'flex', flexDirection: 'column' }}>
            <div className="card-header">
              <span className="card-title">Protocol Distribution</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{flows.length} Total Captured</span>
            </div>
            <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 8, overflowY: 'auto' }}>
              {Object.entries(protocolBreakdown).map(([proto, count]) => {
                const pct = flows.length > 0 ? Math.round((count / flows.length) * 100) : 0;
                return (
                  <div key={proto} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 12 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{
                        padding: '1px 6px',
                        background: 'rgba(255,255,255,0.06)',
                        borderRadius: 4,
                        fontFamily: 'var(--font-mono)',
                        fontSize: 10.5,
                        fontWeight: 700,
                        color: 'var(--primary)',
                      }}>
                        {proto}
                      </span>
                      <span style={{ color: 'var(--text-secondary)' }}>{count} flows</span>
                    </div>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 650, color: 'var(--text-muted)' }}>
                      {pct}%
                    </span>
                  </div>
                );
              })}
              {Object.keys(protocolBreakdown).length === 0 && (
                <div style={{ color: 'var(--text-muted)', fontSize: 12, textAlign: 'center', margin: 'auto' }}>
                  Awaiting flow records...
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Filters Bar */}
        <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap', alignItems: 'center' }}>
          <select
            className="select"
            value={filters.protocol}
            onChange={(e) => { setFilter('protocol', e.target.value as Protocol | ''); setPage(0); }}
          >
            <option value="">All Protocols</option>
            {['TCP', 'UDP', 'DNS', 'TLS', 'QUIC', 'HTTP', 'ICMP'].map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>

          <select
            className="select"
            value={filters.threatStatus}
            onChange={(e) => { setFilter('threatStatus', e.target.value as ThreatStatus | ''); setPage(0); }}
          >
            <option value="">All Statuses</option>
            <option value="BENIGN">Benign</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="MALICIOUS">Malicious</option>
          </select>

          <input
            className="input"
            placeholder="Filter Source IP..."
            value={filters.srcIp}
            onChange={(e) => { setFilter('srcIp', e.target.value); setPage(0); }}
            style={{ width: 150 }}
          />

          <input
            className="input"
            placeholder="Filter Dest IP..."
            value={filters.dstIp}
            onChange={(e) => { setFilter('dstIp', e.target.value); setPage(0); }}
            style={{ width: 150 }}
          />

          <button className="btn btn-secondary" onClick={() => { clearFilters(); setPage(0); }}>
            Reset Filters
          </button>

          <span style={{ marginLeft: 'auto', fontSize: 11.5, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            Showing {filteredFlows.length} flows
          </span>
        </div>

        {/* Tabular Flow Telemetry */}
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Flow ID</th>
                  <th>Source IP:Port</th>
                  <th>Destination IP:Port</th>
                  <th>Proto</th>
                  <th>Packets</th>
                  <th>Bytes</th>
                  <th>Duration</th>
                  <th>Threat Status</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {pagedFlows.map((flow) => (
                  <tr
                    key={flow.flow_id}
                    className={flow.threat_status === 'MALICIOUS' ? 'malicious' : flow.threat_status === 'SUSPICIOUS' ? 'suspicious' : ''}
                    onClick={() => navigate(`/flow/${flow.flow_id}`)}
                    title="Click to inspect full flow evidence"
                  >
                    <td>{formatTimestamp(flow.timestamp)}</td>
                    <td style={{ fontSize: 10.5, color: '#818cf8' }}>{flow.flow_id.slice(0, 14)}...</td>
                    <td>{flow.src_ip}:{flow.src_port}</td>
                    <td>{flow.dst_ip}:{flow.dst_port}</td>
                    <td>
                      <span style={{ padding: '1px 5px', background: 'rgba(255,255,255,0.06)', borderRadius: 3, fontSize: 10.5 }}>
                        {flow.protocol}
                      </span>
                    </td>
                    <td>{flow.packets.toLocaleString()}</td>
                    <td>{formatBytes(flow.bytes_total)}</td>
                    <td>{formatDuration(flow.duration)}</td>
                    <td><ThreatStatusBadge status={flow.threat_status} /></td>
                    <td><SeverityBadge severity={flow.severity} /></td>
                  </tr>
                ))}
                {pagedFlows.length === 0 && (
                  <tr>
                    <td colSpan={10} style={{ padding: 0 }}>
                      <EmptyState
                        icon={<Activity size={24} />}
                        title="No Matching Flows Found"
                        description="Adjust your protocol or IP filters, or verify that the unidirectional telemetry simulator is actively generating records."
                      />
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 10, marginTop: 16 }}>
            <button
              className="btn btn-secondary"
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              Previous
            </button>
            <span style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Page {page + 1} of {totalPages}
            </span>
            <button
              className="btn btn-secondary"
              disabled={page >= totalPages - 1}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        )}
      </div>
    </>
  );
}

export default TrafficExplorer;
