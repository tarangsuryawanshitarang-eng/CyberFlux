/**
 * CyberFlux V2 — Slide-Over Alert Detail Drawer
 * 
 * Non-disruptive deep inspection view displaying ATT&CK mapping,
 * flow identity, detection evidence, feature contributions, and pipeline telemetry.
 * Clean light enterprise aesthetic.
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import { X, ExternalLink, ShieldAlert, Cpu, Terminal, ArrowRight, Activity, Clock } from 'lucide-react';
import type { Alert } from '../../types';
import { THREAT_CLASS_LABELS, MITRE_ATTACK_MAPPING } from '../../types';
import { SeverityBadge, FeatureBar } from './index';
import { formatTimestamp, formatConfidence, formatLatency } from '../../utils/formatters';

interface AlertDrawerProps {
  alert: Alert | null;
  onClose: () => void;
}

export const AlertDrawer: React.FC<AlertDrawerProps> = ({ alert, onClose }) => {
  const navigate = useNavigate();

  if (!alert) return null;

  const mitre = MITRE_ATTACK_MAPPING[alert.threat_class] || {
    tactic: 'Unknown',
    techniqueId: 'N/A',
    techniqueName: 'General Threat',
  };

  const handleDeepInspect = () => {
    onClose();
    navigate(`/flow/${alert.flow_id}`);
  };

  return (
    <>
      {/* Dimmed backdrop */}
      <div className="drawer-backdrop" onClick={onClose} />

      {/* Slide-over panel */}
      <aside className="drawer-panel" role="dialog" aria-modal="true" aria-label="Alert Details">
        {/* Header */}
        <div className="drawer-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 34,
              height: 34,
              borderRadius: 8,
              background: '#FEF2F2',
              border: '1px solid #FECACA',
              display: 'grid',
              placeItems: 'center',
              color: '#DC2626',
            }}>
              <ShieldAlert size={18} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 14.5, fontWeight: 700, color: '#0F172A' }}>
                  {THREAT_CLASS_LABELS[alert.threat_class] || alert.threat_class}
                </span>
                <SeverityBadge severity={alert.severity} />
              </div>
              <div style={{ fontSize: 11, color: '#64748B', fontFamily: 'var(--font-mono)' }}>
                ID: {alert.alert_id}
              </div>
            </div>
          </div>

          <button
            className="btn btn-secondary"
            onClick={onClose}
            style={{ padding: 6, borderRadius: '50%' }}
            aria-label="Close drawer"
          >
            <X size={16} />
          </button>
        </div>

        {/* Content Body */}
        <div className="drawer-body">
          {/* Top Summary Banner */}
          <div style={{
            padding: '12px 14px',
            background: '#EEF2FF',
            border: '1px solid #C7D2FE',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}>
            <div>
              <div style={{ fontSize: 10.5, textTransform: 'uppercase', color: '#4338CA', fontWeight: 650 }}>
                AI Confidence Score
              </div>
              <div style={{ fontSize: 18, fontWeight: 800, color: '#312E81', fontFamily: 'var(--font-mono)' }}>
                {formatConfidence(alert.confidence)}
              </div>
            </div>

            <div>
              <div style={{ fontSize: 10.5, textTransform: 'uppercase', color: '#64748B', fontWeight: 650 }}>
                Detection Latency
              </div>
              <div style={{ fontSize: 14, fontWeight: 700, color: '#0F172A', fontFamily: 'var(--font-mono)' }}>
                {formatLatency(alert.detection_latency_ms)}
              </div>
            </div>

            <div>
              <div style={{ fontSize: 10.5, textTransform: 'uppercase', color: '#64748B', fontWeight: 650 }}>
                Timestamp
              </div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#475569', fontFamily: 'var(--font-mono)' }}>
                {formatTimestamp(alert.timestamp)}
              </div>
            </div>
          </div>

          {/* MITRE ATT&CK Classification */}
          <div className="drawer-section">
            <div className="drawer-section-title">
              <Terminal size={14} color="#4F46E5" />
              MITRE ATT&CK Classification
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', padding: '8px 10px', borderRadius: 6 }}>
                <span style={{ fontSize: 10, color: '#64748B', textTransform: 'uppercase', display: 'block', fontWeight: 600 }}>
                  Tactic
                </span>
                <span style={{ fontSize: 12, fontWeight: 650, color: '#4338CA' }}>
                  {mitre.tactic}
                </span>
              </div>

              <div style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', padding: '8px 10px', borderRadius: 6 }}>
                <span style={{ fontSize: 10, color: '#64748B', textTransform: 'uppercase', display: 'block', fontWeight: 600 }}>
                  Technique
                </span>
                <span className="mitre-badge" style={{ marginTop: 2 }}>
                  {mitre.techniqueId} · {mitre.techniqueName}
                </span>
              </div>
            </div>
          </div>

          {/* Network Endpoint Identity */}
          <div className="drawer-section">
            <div className="drawer-section-title">
              <Activity size={14} color="#0284C7" />
              Network Flow Identity
            </div>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '10px 12px',
              background: '#F8FAFC',
              border: '1px solid #E2E8F0',
              borderRadius: 6,
              fontFamily: 'var(--font-mono)',
              fontSize: 12,
            }}>
              <div>
                <span style={{ fontSize: 10, color: '#64748B', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>Source</span>
                <span style={{ color: '#0F172A', fontWeight: 600 }}>{alert.src_ip}</span>
                <span style={{ color: '#64748B' }}>:{alert.src_port}</span>
              </div>

              <div style={{ color: '#4F46E5', display: 'flex', alignItems: 'center', padding: '0 8px' }}>
                <ArrowRight size={16} />
              </div>

              <div style={{ textAlign: 'right' }}>
                <span style={{ fontSize: 10, color: '#64748B', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>Destination</span>
                <span style={{ color: '#0F172A', fontWeight: 600 }}>{alert.dst_ip}</span>
                <span style={{ color: '#64748B' }}>:{alert.dst_port}</span>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10, fontSize: 11.5 }}>
              <span style={{ color: '#64748B' }}>Protocol:</span>
              <span style={{ fontWeight: 700, color: '#0F172A', fontFamily: 'var(--font-mono)' }}>{alert.protocol}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, fontSize: 11.5 }}>
              <span style={{ color: '#64748B' }}>Underlying Flow ID:</span>
              <span style={{ color: '#475569', fontFamily: 'var(--font-mono)' }}>{alert.flow_id}</span>
            </div>
          </div>

          {/* Empirical Detection Evidence */}
          <div className="drawer-section">
            <div className="drawer-section-title">
              <Cpu size={14} color="#D97706" />
              Behavioral & Statistical Evidence
            </div>
            {alert.evidence && alert.evidence.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {alert.evidence.map((ev, i) => (
                  <div
                    key={i}
                    style={{
                      padding: '8px 12px',
                      background: '#F8FAFC',
                      border: '1px solid #E2E8F0',
                      borderLeft: '3px solid #4F46E5',
                      borderRadius: '0 4px 4px 0',
                      fontSize: 12,
                      color: '#334155',
                      lineHeight: 1.4,
                    }}
                  >
                    {ev}
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ fontSize: 12, color: '#64748B', fontStyle: 'italic' }}>
                Rule-based behavioral threshold breached.
              </div>
            )}
          </div>

          {/* Top Contributing Features */}
          {alert.top_contributing_features && Object.keys(alert.top_contributing_features).length > 0 && (
            <div className="drawer-section">
              <div className="drawer-section-title">
                <Clock size={14} color="#16A34A" />
                Feature Weights & Contributions
              </div>
              <FeatureBar features={alert.top_contributing_features} />
            </div>
          )}

          {/* Read-Only Architecture Callout */}
          <div style={{
            padding: '10px 14px',
            background: '#F0FDF4',
            border: '1px solid #BBF7D0',
            borderRadius: 'var(--radius-sm)',
            fontSize: 11,
            color: '#166534',
            lineHeight: 1.5,
          }}>
            <div style={{ fontWeight: 700, color: '#16A34A', marginBottom: 2 }}>
              READ-ONLY ENCLAVE ANALYSIS
            </div>
            Detection generated via metadata telemetry without payload decryption or active network probing.
          </div>
        </div>

        {/* Footer with Deep Link */}
        <div className="drawer-footer">
          <button className="btn btn-secondary" onClick={onClose}>
            Dismiss
          </button>
          <button className="btn btn-primary" onClick={handleDeepInspect}>
            <ExternalLink size={14} /> Inspect Full Flow
          </button>
        </div>
      </aside>
    </>
  );
};
