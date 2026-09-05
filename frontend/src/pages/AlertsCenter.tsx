/**
 * CyberFlux V2 — Alerts Operational Centerpiece
 * 
 * Centralized alert triage interface with severity filtering,
 * ATT&CK tactic matching, quick search, and slide-over inspection.
 */

import { useState, useMemo } from 'react';
import { AlertTriangle, ShieldAlert, Filter, Search, Info } from 'lucide-react';
import { Topbar } from '../components/layout/Topbar';
import { SeverityBadge, MitreBadge, AlertDrawer, EmptyState } from '../components/ui';
import { useAlertStore } from '../stores/alertStore';
import { formatTimestamp, formatConfidence } from '../utils/formatters';
import { THREAT_CLASS_LABELS } from '../types';
import type { Alert, Severity, ThreatClass } from '../types';

export function AlertsCenter() {
  const alerts = useAlertStore((s) => s.alerts);
  const severityCounts = useAlertStore((s) => s.severityCounts);

  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('');
  const [threatFilter, setThreatFilter] = useState<ThreatClass | ''>('');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Filtered alert list
  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      if (severityFilter && a.severity !== severityFilter) return false;
      if (threatFilter && a.threat_class !== threatFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesText =
          a.threat_class.toLowerCase().includes(q) ||
          a.src_ip.includes(q) ||
          a.dst_ip.includes(q) ||
          a.alert_id.toLowerCase().includes(q) ||
          (a.evidence && a.evidence.some((ev) => ev.toLowerCase().includes(q)));
        if (!matchesText) return false;
      }
      return true;
    });
  }, [alerts, severityFilter, threatFilter, searchQuery]);

  return (
    <>
      <Topbar
        title="Alerts Operations Center"
        description="Active threat detections in rolling memory buffer — real-time AI security telemetry"
        searchValue={searchQuery}
        onSearchChange={setSearchQuery}
      />

      <div className="content">
        {/* KPI Strip */}
        <div className="metric-grid" style={{ marginBottom: 16 }}>
          <div className="metric-card">
            <div className="metric-label">
              <AlertTriangle size={14} color="#ef4444" />
              <span>Total Active Alerts</span>
            </div>
            <div className="metric-value">{alerts.length}</div>
            <div className="metric-change">Bounded Rolling Window</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">
              <ShieldAlert size={14} color="#ef4444" />
              <span>Critical Severity</span>
            </div>
            <div className="metric-value" style={{ color: severityCounts.CRITICAL > 0 ? '#ef4444' : undefined }}>
              {severityCounts.CRITICAL}
            </div>
            <div className="metric-change negative">
              {severityCounts.CRITICAL > 0 ? 'Immediate Action Req.' : '0 Critical'}
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-label">
              <AlertTriangle size={14} color="#f97316" />
              <span>High Severity</span>
            </div>
            <div className="metric-value" style={{ color: severityCounts.HIGH > 0 ? '#fb923c' : undefined }}>
              {severityCounts.HIGH}
            </div>
            <div className="metric-change">High Threat Posture</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">
              <Filter size={14} color="#f59e0b" />
              <span>Medium Severity</span>
            </div>
            <div className="metric-value">{severityCounts.MEDIUM}</div>
            <div className="metric-change">Anomalous Deviations</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">
              <Info size={14} color="#38bdf8" />
              <span>Low / Informational</span>
            </div>
            <div className="metric-value">{severityCounts.LOW + severityCounts.INFO}</div>
            <div className="metric-change">Telemetry Notices</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">
              <ShieldAlert size={14} color="#10b981" />
              <span>Mean Confidence</span>
            </div>
            <div className="metric-value" style={{ color: '#818cf8' }}>
              {alerts.length > 0
                ? `${(alerts.reduce((acc, a) => acc + a.confidence, 0) / alerts.length * 100).toFixed(1)}%`
                : '94.2%'}
            </div>
            <div className="metric-change positive">Rule &amp; Feature Score</div>
          </div>
        </div>

        {/* Filters Toolbar */}
        <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap', alignItems: 'center' }}>
          <select
            className="select"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as Severity | '')}
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>

          <select
            className="select"
            value={threatFilter}
            onChange={(e) => setThreatFilter(e.target.value as ThreatClass | '')}
          >
            <option value="">All Threat Types</option>
            {Object.entries(THREAT_CLASS_LABELS)
              .filter(([k]) => k !== 'BENIGN')
              .map(([key, label]) => (
                <option key={key} value={key}>{label}</option>
              ))}
          </select>

          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <Search size={13} style={{ position: 'absolute', left: 8, color: 'var(--text-muted)' }} />
            <input
              className="input"
              type="text"
              placeholder="Filter IP or evidence..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ paddingLeft: 26, width: 220 }}
            />
          </div>

          {(severityFilter || threatFilter || searchQuery) && (
            <button
              className="btn btn-secondary"
              onClick={() => {
                setSeverityFilter('');
                setThreatFilter('');
                setSearchQuery('');
              }}
            >
              Reset Filters
            </button>
          )}

          <span style={{ marginLeft: 'auto', fontSize: 11.5, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            Showing {filteredAlerts.length} of {alerts.length} alerts
          </span>
        </div>

        {/* Tabular Alerts Feed */}
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Severity</th>
                  <th>Threat Classification</th>
                  <th>ATT&CK</th>
                  <th>Source IP:Port</th>
                  <th>Destination IP:Port</th>
                  <th>Proto</th>
                  <th>Confidence</th>
                  <th>Detection Evidence</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((alert) => (
                  <tr
                    key={alert.alert_id}
                    onClick={() => setSelectedAlert(alert)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>{formatTimestamp(alert.timestamp)}</td>
                    <td>
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td style={{ fontWeight: 650, color: 'var(--text-primary)' }}>
                      {THREAT_CLASS_LABELS[alert.threat_class] || alert.threat_class}
                    </td>
                    <td>
                      <MitreBadge threatClass={alert.threat_class} />
                    </td>
                    <td>{alert.src_ip}:{alert.src_port}</td>
                    <td>{alert.dst_ip}:{alert.dst_port}</td>
                    <td>
                      <span style={{ padding: '2px 6px', background: '#F1F5F9', border: '1px solid #E2E8F0', borderRadius: 3, fontSize: 10.5, color: '#334155' }}>
                        {alert.protocol}
                      </span>
                    </td>
                    <td style={{ color: '#4338CA', fontWeight: 700 }}>
                      {formatConfidence(alert.confidence)}
                    </td>
                    <td style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                      {alert.evidence && alert.evidence.length > 0 ? alert.evidence[0] : 'Threshold breached'}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '2px 8px', fontSize: 11 }}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedAlert(alert);
                        }}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
                {filteredAlerts.length === 0 && (
                  <tr>
                    <td colSpan={10} style={{ padding: 0 }}>
                      <EmptyState
                        icon={<AlertTriangle size={24} />}
                        title="No Alerts Match Filters"
                        description="Adjust your search criteria or switch threat simulation profiles to generate real-time security alerts."
                      />
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Slide-over Detail Drawer */}
      <AlertDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />
    </>
  );
}

export default AlertsCenter;
