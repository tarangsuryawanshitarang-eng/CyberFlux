/**
 * CyberFlux — Live Traffic Explorer
 * 
 * Paginated, filterable traffic table with click-to-inspect.
 */

import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Topbar } from '../components/layout/Topbar';
import { SeverityBadge, ThreatStatusBadge } from '../components/ui';
import { useFlowStore } from '../stores/flowStore';
import { formatTimestamp, formatBytes, formatDuration } from '../utils/formatters';
import type { Protocol, ThreatStatus } from '../types';

const PAGE_SIZE = 25;

function TrafficExplorer() {
  const navigate = useNavigate();
  const flows = useFlowStore((s) => s.flows);
  const filters = useFlowStore((s) => s.filters);
  const setFilter = useFlowStore((s) => s.setFilter);
  const clearFilters = useFlowStore((s) => s.clearFilters);
  const getFilteredFlows = useFlowStore((s) => s.getFilteredFlows);
  const [page, setPage] = useState(0);

  const filteredFlows = useMemo(() => getFilteredFlows(), [getFilteredFlows, flows, filters]);
  const totalPages = Math.max(1, Math.ceil(filteredFlows.length / PAGE_SIZE));
  const pagedFlows = useMemo(
    () => filteredFlows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE),
    [filteredFlows, page]
  );

  return (
    <>
      <Topbar title="Live Traffic" description="Real-time flow monitoring — metadata only, no payload content" />
      <div className="content">
        {/* Filters */}
        <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
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
            <option value="">All Status</option>
            <option value="BENIGN">Benign</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="MALICIOUS">Malicious</option>
          </select>

          <input
            className="input"
            placeholder="Source IP"
            value={filters.srcIp}
            onChange={(e) => { setFilter('srcIp', e.target.value); setPage(0); }}
            style={{ width: 160 }}
          />

          <input
            className="input"
            placeholder="Destination IP"
            value={filters.dstIp}
            onChange={(e) => { setFilter('dstIp', e.target.value); setPage(0); }}
            style={{ width: 160 }}
          />

          <button className="btn btn-secondary" onClick={() => { clearFilters(); setPage(0); }}>
            Clear
          </button>

          <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)' }}>
            {filteredFlows.length} flows
          </span>
        </div>

        {/* Table */}
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Flow ID</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Proto</th>
                  <th>Packets</th>
                  <th>Bytes</th>
                  <th>Duration</th>
                  <th>Status</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {pagedFlows.map((flow) => (
                  <tr
                    key={flow.flow_id}
                    className={flow.threat_status === 'MALICIOUS' ? 'malicious' : flow.threat_status === 'SUSPICIOUS' ? 'suspicious' : ''}
                    onClick={() => navigate(`/flow/${flow.flow_id}`)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>{formatTimestamp(flow.timestamp)}</td>
                    <td style={{ fontSize: 10 }}>{flow.flow_id}</td>
                    <td>{flow.src_ip}:{flow.src_port}</td>
                    <td>{flow.dst_ip}:{flow.dst_port}</td>
                    <td>{flow.protocol}</td>
                    <td>{flow.packets.toLocaleString()}</td>
                    <td>{formatBytes(flow.bytes_total)}</td>
                    <td>{formatDuration(flow.duration)}</td>
                    <td><ThreatStatusBadge status={flow.threat_status} /></td>
                    <td><SeverityBadge severity={flow.severity} /></td>
                  </tr>
                ))}
                {pagedFlows.length === 0 && (
                  <tr>
                    <td colSpan={10} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
                      No flows match the current filters
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16 }}>
            <button className="btn btn-secondary" disabled={page === 0} onClick={() => setPage(p => p - 1)}>
              Previous
            </button>
            <span style={{ display: 'flex', alignItems: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
              Page {page + 1} of {totalPages}
            </span>
            <button className="btn btn-secondary" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>
              Next
            </button>
          </div>
        )}
      </div>
    </>
  );
}

export default TrafficExplorer;
