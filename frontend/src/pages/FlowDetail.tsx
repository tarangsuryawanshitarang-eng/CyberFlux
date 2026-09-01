/**
 * CyberFlux — Flow Detail View
 * 
 * Full investigation view for a single flow.
 */

import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { Topbar } from '../components/layout/Topbar';
import { SeverityBadge, ThreatStatusBadge, FeatureBar } from '../components/ui';
import { useFlowStore } from '../stores/flowStore';
import { api } from '../services/api';
import { formatBytes, formatTimestamp, formatDuration, formatRate, formatConfidence, formatLatency } from '../utils/formatters';
import { THREAT_CLASS_LABELS } from '../types';
import type { FlowEvent } from '../types';

function FlowDetail() {
  const { flowId } = useParams<{ flowId: string }>();
  const navigate = useNavigate();
  const flows = useFlowStore((s) => s.flows);
  const [flow, setFlow] = useState<FlowEvent | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Try client store first
    const cached = flows.find((f) => f.flow_id === flowId);
    if (cached) {
      setFlow(cached);
      setLoading(false);
      return;
    }
    // Fallback to API
    if (flowId) {
      api.flow(flowId)
        .then(setFlow)
        .catch(() => setFlow(null))
        .finally(() => setLoading(false));
    }
  }, [flowId, flows]);

  if (loading) {
    return (
      <>
        <Topbar title="Flow Detail" />
        <div className="content">
          <div className="skeleton" style={{ height: 400 }} />
        </div>
      </>
    );
  }

  if (!flow) {
    return (
      <>
        <Topbar title="Flow Detail" />
        <div className="content">
          <div className="card" style={{ padding: 40, textAlign: 'center' }}>
            <p style={{ color: 'var(--text-muted)' }}>Flow not found</p>
            <button className="btn btn-primary" onClick={() => navigate(-1)} style={{ marginTop: 16 }}>
              Go Back
            </button>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <Topbar title="Flow Investigation" description={`Flow ${flow.flow_id}`} />
      <div className="content">
        <button
          className="btn btn-secondary"
          onClick={() => navigate(-1)}
          style={{ marginBottom: 16 }}
        >
          <ArrowLeft size={14} /> Back
        </button>

        {/* Detection Result Banner */}
        {flow.threat_status !== 'BENIGN' && (
          <div style={{
            padding: '16px 20px',
            background: flow.severity === 'CRITICAL' || flow.severity === 'HIGH' ? 'var(--danger-soft)' : 'var(--warning-soft)',
            border: `1px solid ${flow.severity === 'CRITICAL' || flow.severity === 'HIGH' ? '#fecaca' : '#fde68a'}`,
            borderRadius: 'var(--radius-lg)',
            marginBottom: 16,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <SeverityBadge severity={flow.severity} />
              <span style={{ fontSize: 16, fontWeight: 700 }}>
                {THREAT_CLASS_LABELS[flow.threat_class] || flow.threat_class}
              </span>
              <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                Confidence: {formatConfidence(flow.confidence)}
              </span>
            </div>
            {flow.evidence.length > 0 && (
              <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                {flow.evidence.map((e, i) => (
                  <div key={i}>• {e}</div>
                ))}
              </div>
            )}
          </div>
        )}

        <div className="dashboard-grid">
          {/* Identity */}
          <div className="span-6 card">
            <div className="card-header">
              <span className="card-title">Flow Identity</span>
            </div>
            <div className="card-body">
              <DetailGrid items={[
                ['Flow ID', flow.flow_id],
                ['Timestamp', formatTimestamp(flow.timestamp)],
                ['Source IP', flow.src_ip],
                ['Destination IP', flow.dst_ip],
                ['Source Port', flow.src_port],
                ['Destination Port', flow.dst_port],
                ['Protocol', flow.protocol],
                ['Duration', formatDuration(flow.duration)],
              ]} />
            </div>
          </div>

          {/* Statistics */}
          <div className="span-6 card">
            <div className="card-header">
              <span className="card-title">Flow Statistics</span>
            </div>
            <div className="card-body">
              <DetailGrid items={[
                ['Packets', flow.packets.toLocaleString()],
                ['Total Bytes', formatBytes(flow.bytes_total)],
                ['Packets/sec', formatRate(flow.packets_per_second).replace('/s', '')],
                ['Bytes/sec', formatRate(flow.bytes_per_second).replace('/s', '')],
                ['Inbound Bytes', formatBytes(flow.inbound_bytes)],
                ['Outbound Bytes', formatBytes(flow.outbound_bytes)],
                ['Out/In Ratio', flow.outbound_inbound_ratio.toFixed(2)],
                ['Detection Latency', formatLatency(flow.detection_latency_ms)],
              ]} />
            </div>
          </div>

          {/* Behavioral Features */}
          <div className="span-6 card">
            <div className="card-header">
              <span className="card-title">Behavioral Features</span>
            </div>
            <div className="card-body">
              <DetailGrid items={[
                ['Source Entropy', flow.source_entropy.toFixed(2)],
                ['Dest Fanout', flow.destination_fanout],
                ['Port Fanout', flow.port_fanout],
                ['Inter-arrival Mean', `${flow.mean_interarrival.toFixed(3)}s`],
                ['Inter-arrival Std', flow.interarrival_std.toFixed(3)],
                ['Periodicity Score', flow.periodicity_score.toFixed(3)],
                ['DNS Entropy', flow.dns_entropy.toFixed(3)],
                ['DNS Query Length', flow.dns_query_length],
                ['DNS Query Freq', flow.dns_query_frequency.toFixed(1)],
                ['TLS Version', flow.tls_version || 'N/A'],
                ['JA3', flow.ja3 || 'N/A'],
                ['Pkt Size Mean', flow.packet_size_mean.toFixed(1)],
                ['Pkt Size Std', flow.packet_size_std.toFixed(1)],
              ]} />
            </div>
          </div>

          {/* Model Result */}
          <div className="span-6 card">
            <div className="card-header">
              <span className="card-title">Detection Result</span>
              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>Rule-based prototype detector</span>
            </div>
            <div className="card-body">
              <div style={{ display: 'flex', gap: 16, marginBottom: 20 }}>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Threat Class</div>
                  <span style={{ fontSize: 14, fontWeight: 700 }}>
                    {THREAT_CLASS_LABELS[flow.threat_class] || flow.threat_class}
                  </span>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Status</div>
                  <ThreatStatusBadge status={flow.threat_status} />
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Severity</div>
                  <SeverityBadge severity={flow.severity} />
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Confidence</div>
                  <span style={{ fontSize: 14, fontWeight: 700 }}>{formatConfidence(flow.confidence)}</span>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Anomaly Score</div>
                  <span style={{ fontSize: 14, fontWeight: 700 }}>{(flow.anomaly_score * 100).toFixed(1)}%</span>
                </div>
              </div>

              {/* Top Contributing Features */}
              {Object.keys(flow.top_contributing_features).length > 0 && (
                <>
                  <div style={{ fontSize: 12, fontWeight: 650, marginBottom: 10 }}>
                    Top Contributing Features
                  </div>
                  <FeatureBar features={flow.top_contributing_features} />
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

function DetailGrid({ items }: { items: [string, string | number][] }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 24px' }}>
      {items.map(([label, value]) => (
        <div key={label}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            {label}
          </div>
          <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
            {value}
          </div>
        </div>
      ))}
    </div>
  );
}

export default FlowDetail;
