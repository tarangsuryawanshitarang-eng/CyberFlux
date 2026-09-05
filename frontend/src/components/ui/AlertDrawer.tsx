/**
 * CyberFlux V2 — Slide-Over Alert Detail Drawer
 * 
 * Non-disruptive deep inspection view displaying ATT&CK mapping,
 * flow identity, detection evidence, feature contributions, and pipeline telemetry.
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
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid rgba(239, 68, 68, 0.35)',
              display: 'grid',
              placeItems: 'center',
              color: 'var(--danger)',
            }}>
              <ShieldAlert size={18} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
                  {THREAT_CLASS_LABELS[alert.threat_class] || alert.threat_class}
                </span>
                <SeverityBadge severity={alert.severity} />
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
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
            background: 'rgba(99, 102, 241, 0.08)',
            border: '1px solid rgba(99, 102, 241, 0.25)',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}>
            <div>
              <div style={{ fontSize: 10.5, textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700 }}>
                AI Confidence Score
              </div>
              <div style={{ fontSize: 18, fontWeight: 800, color: '#818cf8', fontFamily: 'var(--font-mono)' }}>
                {formatConfidence(alert.confidence)}
              </div>
            </div>

            <div>
              <div style={{ fontSize: 10.5, textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700 }}>
                Detection Latency
              </div>
              <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                {formatLatency(alert.detection_latency_ms)}
              </div>
            </div>

            <div>
              <div style={{ fontSize: 10.5, textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700 }}>
                Timestamp
              </div>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                {formatTimestamp(alert.timestamp)}
              </div>
            </div>
          </div>

          {/* MITRE ATT&CK Classification */}
          <div className="drawer-section">
            <div className="drawer-section-title">
              <Terminal size={14} color="#8b5cf6" />
              MITRE ATT&CK Classification
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div style={{ background: 'rgba(0,0,0,0.2)', padding: '8px 10px', borderRadius: 6 }}>
                <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block' }}>
                  Tactic
                </span>
                <span style={{ fontSize: 12, fontWeight: 650, color: '#c4b5fd' }}>
                  {mitre.tactic}
                </span>
              </div>

              <div style={{ background: 'rgba(0,0,0,0.2)', padding: '8px 10px', borderRadius: 6 }}>
                <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block' }}>
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
              <Activity size={14} color="#38bdf8" />
              Network Flow Identity
            </div>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '10px 12px',
              background: 'rgba(0,0,0,0.2)',
              borderRadius: 6,
              fontFamily: 'var(--font-mono)',
              fontSize: 12,
            }}>
              <div>
                <span style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase' }}>Source</span>
                <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{alert.src_ip}</span>
                <span style={{ color: 'var(--text-muted)' }}>:{alert.src_port}</span>
              </div>

              <div style={{ color: 'var(--primary)', display: 'flex', alignItems: 'center', padding: '0 8px' }}>
                <ArrowRight size={16} />
              </div>

              <div style={{ textAlign: 'right' }}>
                <span style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase' }}>Destination</span>
                <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{alert.dst_ip}</span>
                <span style={{ color: 'var(--text-muted)' }}>:{alert.dst_port}</span>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10, fontSize: 11.5 }}>
              <span style={{ color: 'var(--text-muted)' }}>Protocol:</span>
              <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{alert.protocol}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, fontSize: 11.5 }}>
              <span style={{ color: 'var(--text-muted)' }}>Underlying Flow ID:</span>
              <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{alert.flow_id}</span>
            </div>
          </div>

          {/* Empirical Detection Evidence */}
          <div className="drawer-section">
            <div className="drawer-section-title">
              <Cpu size={14} color="#f59e0b" />
              Behavioral & Statistical Evidence
            </div>
            {alert.evidence && alert.evidence.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {alert.evidence.map((ev, i) => (
                  <div
                    key={i}
                    style={{
                      padding: '7px 10px',
                      background: 'rgba(255, 255, 255, 0.03)',
                      borderLeft: '3px solid #6366f1',
                      borderRadius: '0 4px 4px 0',
                      fontSize: 12,
                      color: 'var(--text-secondary)',
                      lineHeight: 1.4,
                    }}
                  >
                    {ev}
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                Rule-based behavioral threshold breached.
              </div>
            )}
          </div>

          {/* Top Contributing Features */}
          {alert.top_contributing_features && Object.keys(alert.top_contributing_features).length > 0 && (
            <div className="drawer-section">
              <div className="drawer-section-title">
                <Clock size={14} color="#10b981" />
                Feature Weights & Contributions
              </div>
              <FeatureBar features={alert.top_contributing_features} />
            </div>
          )}

          {/* Read-Only Architecture Callout */}
          <div style={{
            padding: '10px 14px',
            background: 'rgba(0, 0, 0, 0.25)',
            border: '1px dashed var(--border)',
            borderRadius: 'var(--radius-sm)',
            fontSize: 11,
            color: 'var(--text-muted)',
            lineHeight: 1.5,
          }}>
            <div style={{ fontWeight: 700, color: '#34d399', marginBottom: 2 }}>
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
