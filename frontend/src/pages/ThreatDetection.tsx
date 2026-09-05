/**
 * CyberFlux V2 — Threat Detection & MITRE ATT&CK View
 * 
 * Threat classification hierarchy:
 * Threat Category ↓ MITRE Tactic ↓ Technique ID ↓ Evidence ↓ Generated Alert
 * Includes on-demand scenario simulation triggers and slide-over alert inspection.
 */

import React, { useMemo, useState } from 'react';
import {
  ShieldAlert, AlertTriangle, Bug, Globe, Lock, Search, Database, Radio,
  Play, Terminal, ArrowRight,
} from 'lucide-react';
import { Topbar } from '../components/layout/Topbar';
import { SeverityBadge, AlertDrawer } from '../components/ui';
import { useAlertStore } from '../stores/alertStore';
import { useFlowStore } from '../stores/flowStore';
import { THREAT_CLASS_LABELS, MITRE_ATTACK_MAPPING } from '../types';
import type { ThreatClass, Alert } from '../types';
import { formatConfidence } from '../utils/formatters';
import { api } from '../services/api';

const THREAT_ICONS: Record<string, React.ReactNode> = {
  SYN_FLOOD: <AlertTriangle size={18} />,
  UDP_REFLECTION: <Radio size={18} />,
  BOTNET_C2: <Bug size={18} />,
  DGA_DOMAIN: <Globe size={18} />,
  DNS_TUNNELING: <Database size={18} />,
  MALWARE_TLS: <Lock size={18} />,
  RECON_SCAN: <Search size={18} />,
  DATA_EXFILTRATION: <ShieldAlert size={18} />,
};

const THREAT_DESCRIPTIONS: Record<string, string> = {
  SYN_FLOOD: 'High packet rate with spoofed sources targeting specific ports. Detected via SYN rate, source entropy, and packet size uniformity.',
  UDP_REFLECTION: 'Amplification attack using open resolvers. Detected via inbound/outbound byte ratio and packet size.',
  BOTNET_C2: 'Periodic beaconing to command & control servers. Detected via inter-arrival regularity and destination concentration.',
  DGA_DOMAIN: 'Algorithmically generated domain names for C2 resolution. Detected via character entropy and domain length.',
  DNS_TUNNELING: 'Data exfiltration through DNS queries. Detected via query length, entropy, and frequency.',
  MALWARE_TLS: 'Suspicious encrypted traffic patterns (metadata only — PAYLOAD DECRYPTION: DISABLED). Detected via TLS fingerprints and timing.',
  RECON_SCAN: 'Network reconnaissance via port/host scanning. Detected via destination and port fanout.',
  DATA_EXFILTRATION: 'Large sustained outbound data transfers. Detected via outbound volume and asymmetric data ratio.',
};

const THREAT_RATES: Record<string, number> = {
  SYN_FLOOD: 320.0,
  UDP_REFLECTION: 180.0,
  BOTNET_C2: 45.0,
  DGA_DOMAIN: 55.0,
  DNS_TUNNELING: 65.0,
  MALWARE_TLS: 50.0,
  RECON_SCAN: 120.0,
  DATA_EXFILTRATION: 80.0,
};

const THREAT_CATEGORIES: ThreatClass[] = [
  'SYN_FLOOD', 'UDP_REFLECTION', 'BOTNET_C2', 'DGA_DOMAIN',
  'DNS_TUNNELING', 'MALWARE_TLS', 'RECON_SCAN', 'DATA_EXFILTRATION',
];

function ThreatDetection() {
  const threatCounts = useAlertStore((s) => s.threatCounts);
  const alerts = useAlertStore((s) => s.alerts);
  const flows = useFlowStore((s) => s.flows);

  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [simulatingThreat, setSimulatingThreat] = useState<string | null>(null);

  const categories = useMemo(() => {
    return THREAT_CATEGORIES.map((tc) => {
      const count = threatCounts[tc] || 0;
      const recentAlerts = alerts.filter((a) => a.threat_class === tc).slice(0, 3);
      const recentFlows = flows.filter((f) => f.threat_class === tc).slice(0, 3);
      const mitre = MITRE_ATTACK_MAPPING[tc];

      return {
        threat_class: tc,
        label: THREAT_CLASS_LABELS[tc],
        description: THREAT_DESCRIPTIONS[tc],
        icon: THREAT_ICONS[tc],
        mitre,
        count,
        recentAlerts,
        recentFlows,
        rate: THREAT_RATES[tc] || 60.0,
      };
    });
  }, [threatCounts, alerts, flows]);

  const handleSimulate = async (scenario: string, rate: number) => {
    try {
      setSimulatingThreat(scenario);
      await api.startSimulation(scenario, 1.0, rate);
      setTimeout(() => setSimulatingThreat(null), 2500);
    } catch (e) {
      console.error(e);
      setSimulatingThreat(null);
    }
  };

  return (
    <>
      <Topbar
        title="Threat Classification &amp; MITRE ATT&CK"
        description="Behavioral detection rules and empirical feature indicators — read-only telemetry"
      />

      <div className="content">
        {/* MITRE ATT&CK Relationship Flow Banner */}
        <div style={{
          padding: '12px 18px',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-md)',
          marginBottom: 18,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
          flexWrap: 'wrap',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Terminal size={16} color="#8b5cf6" />
            <span style={{ fontSize: 11.5, fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              ATT&CK Mapping Hierarchy:
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11.5, color: 'var(--text-secondary)' }}>
            <span style={{ padding: '2px 8px', background: 'rgba(99, 102, 241, 0.15)', borderRadius: 4, color: '#a5b4fc', fontWeight: 650 }}>
              Threat Category
            </span>
            <ArrowRight size={13} color="var(--text-muted)" />
            <span style={{ padding: '2px 8px', background: 'rgba(139, 92, 246, 0.15)', borderRadius: 4, color: '#c4b5fd', fontWeight: 650 }}>
              MITRE Tactic
            </span>
            <ArrowRight size={13} color="var(--text-muted)" />
            <span style={{ padding: '2px 8px', background: 'rgba(56, 189, 248, 0.15)', borderRadius: 4, color: '#7dd3fc', fontWeight: 650 }}>
              Technique ID
            </span>
            <ArrowRight size={13} color="var(--text-muted)" />
            <span style={{ padding: '2px 8px', background: 'rgba(245, 158, 11, 0.15)', borderRadius: 4, color: '#fde68a', fontWeight: 650 }}>
              Empirical Evidence
            </span>
            <ArrowRight size={13} color="var(--text-muted)" />
            <span style={{ padding: '2px 8px', background: 'rgba(239, 68, 68, 0.15)', borderRadius: 4, color: '#fca5a5', fontWeight: 650 }}>
              Enclave Alert
            </span>
          </div>
        </div>

        {/* Threat Categories Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(370px, 1fr))', gap: 16 }}>
          {categories.map((cat) => (
            <div key={cat.threat_class} className="card" style={{ display: 'flex', flexDirection: 'column' }}>
              <div className="card-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div style={{
                    width: 32, height: 32, borderRadius: 8,
                    display: 'grid', placeItems: 'center',
                    background: cat.count > 0 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(255, 255, 255, 0.05)',
                    color: cat.count > 0 ? '#f87171' : 'var(--text-muted)',
                    border: `1px solid ${cat.count > 0 ? 'rgba(239, 68, 68, 0.35)' : 'var(--border)'}`,
                  }}>
                    {cat.icon}
                  </div>
                  <div>
                    <div className="card-title">{cat.label}</div>
                    <div style={{ fontSize: 10.5, color: '#a5b4fc', fontFamily: 'var(--font-mono)' }}>
                      {cat.mitre.tactic} · {cat.mitre.techniqueId}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {cat.count > 0 ? (
                    <span style={{
                      fontSize: 18, fontWeight: 800, color: '#f87171',
                      fontFamily: 'var(--font-mono)',
                    }}>
                      {cat.count}
                    </span>
                  ) : (
                    <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>0 active</span>
                  )}
                </div>
              </div>

              <div className="card-body" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                <p style={{ fontSize: 11.5, color: 'var(--text-secondary)', lineHeight: 1.45, margin: '0 0 12px 0' }}>
                  {cat.description}
                </p>

                {/* MITRE Pill Box */}
                <div style={{
                  padding: '7px 10px',
                  background: 'rgba(0,0,0,0.25)',
                  borderRadius: 6,
                  marginBottom: 12,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  fontSize: 11,
                }}>
                  <span style={{ color: 'var(--text-muted)' }}>Technique:</span>
                  <span className="mitre-badge">
                    {cat.mitre.techniqueId} · {cat.mitre.techniqueName}
                  </span>
                </div>

                {/* Recent Alerts under this category */}
                {cat.recentAlerts.length > 0 && (
                  <div style={{ marginTop: 'auto', marginBottom: 12 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Recent Detections (Click to inspect)
                    </div>
                    {cat.recentAlerts.map((alert) => (
                      <div
                        key={alert.alert_id}
                        onClick={() => setSelectedAlert(alert)}
                        style={{
                          padding: '5px 6px',
                          borderRadius: 4,
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6,
                          fontSize: 11,
                          transition: 'background 100ms ease',
                          marginBottom: 2,
                        }}
                        className="hover:bg-slate-800"
                      >
                        <SeverityBadge severity={alert.severity} />
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                          {alert.src_ip} → {alert.dst_ip}
                        </span>
                        <span style={{ marginLeft: 'auto', color: '#818cf8', fontWeight: 600 }}>
                          {formatConfidence(alert.confidence)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {cat.count === 0 && (
                  <div style={{ margin: 'auto 0 12px 0', textAlign: 'center', padding: '10px 0', color: 'var(--text-muted)', fontSize: 11 }}>
                    Monitoring baseline — zero active alerts
                  </div>
                )}

                {/* Direct Simulation Trigger Button */}
                <button
                  className="btn btn-secondary"
                  onClick={() => handleSimulate(cat.threat_class, cat.rate)}
                  disabled={simulatingThreat === cat.threat_class}
                  style={{ width: '100%', justifyContent: 'center', marginTop: 'auto' }}
                >
                  <Play size={12} color="#818cf8" />
                  <span>
                    {simulatingThreat === cat.threat_class ? 'Simulating Telemetry...' : `Simulate ${cat.label}`}
                  </span>
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Slide-over Drawer for alert inspection */}
      <AlertDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />
    </>
  );
}

export default ThreatDetection;
