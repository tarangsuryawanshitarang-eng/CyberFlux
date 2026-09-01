/**
 * CyberFlux — Threat Detection View
 * 
 * Threat categories with counts, severity distribution, and recent flows.
 */

import React, { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, AlertTriangle, Bug, Globe, Lock, Search, Database, Radio } from 'lucide-react';
import { Topbar } from '../components/layout/Topbar';
import { SeverityBadge } from '../components/ui';
import { useAlertStore } from '../stores/alertStore';
import { useFlowStore } from '../stores/flowStore';
import { THREAT_CLASS_LABELS } from '../types';
import type { ThreatClass } from '../types';
import { formatConfidence } from '../utils/formatters';

const THREAT_ICONS: Record<string, React.ReactNode> = {
  SYN_FLOOD: <AlertTriangle size={20} />,
  UDP_REFLECTION: <Radio size={20} />,
  BOTNET_C2: <Bug size={20} />,
  DGA_DOMAIN: <Globe size={20} />,
  DNS_TUNNELING: <Database size={20} />,
  MALWARE_TLS: <Lock size={20} />,
  RECON_SCAN: <Search size={20} />,
  DATA_EXFILTRATION: <ShieldAlert size={20} />,
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

const THREAT_CATEGORIES: ThreatClass[] = [
  'SYN_FLOOD', 'UDP_REFLECTION', 'BOTNET_C2', 'DGA_DOMAIN',
  'DNS_TUNNELING', 'MALWARE_TLS', 'RECON_SCAN', 'DATA_EXFILTRATION',
];

function ThreatDetection() {
  const navigate = useNavigate();
  const threatCounts = useAlertStore((s) => s.threatCounts);
  const alerts = useAlertStore((s) => s.alerts);
  const flows = useFlowStore((s) => s.flows);

  const categories = useMemo(() => {
    return THREAT_CATEGORIES.map((tc) => {
      const count = threatCounts[tc] || 0;
      const recentAlerts = alerts.filter((a) => a.threat_class === tc).slice(0, 3);
      const recentFlows = flows.filter((f) => f.threat_class === tc).slice(0, 3);

      return {
        threat_class: tc,
        label: THREAT_CLASS_LABELS[tc],
        description: THREAT_DESCRIPTIONS[tc],
        icon: THREAT_ICONS[tc],
        count,
        recentAlerts,
        recentFlows,
      };
    });
  }, [threatCounts, alerts, flows]);

  return (
    <>
      <Topbar title="Threat Detection" description="Real-time threat classification and analysis — rule-based prototype detector" />
      <div className="content">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))', gap: 16 }}>
          {categories.map((cat) => (
            <div key={cat.threat_class} className="card">
              <div className="card-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div style={{
                    width: 36, height: 36, borderRadius: 8,
                    display: 'grid', placeItems: 'center',
                    background: cat.count > 0 ? 'var(--danger-soft)' : 'var(--bg-surface-soft)',
                    color: cat.count > 0 ? 'var(--danger)' : 'var(--text-muted)',
                  }}>
                    {cat.icon}
                  </div>
                  <div>
                    <div className="card-title">{cat.label}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {cat.count} detection{cat.count !== 1 ? 's' : ''}
                    </div>
                  </div>
                </div>
                {cat.count > 0 && (
                  <span style={{
                    fontSize: 24, fontWeight: 700, color: 'var(--danger)',
                    fontFamily: 'var(--font-mono)',
                  }}>
                    {cat.count}
                  </span>
                )}
              </div>

              <div className="card-body">
                <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5, margin: '0 0 12px' }}>
                  {cat.description}
                </p>

                {cat.recentAlerts.length > 0 && (
                  <div style={{ fontSize: 11 }}>
                    <div style={{ fontWeight: 650, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Recent Detections
                    </div>
                    {cat.recentAlerts.map((alert) => (
                      <div
                        key={alert.alert_id}
                        onClick={() => navigate(`/flow/${alert.flow_id}`)}
                        style={{
                          padding: '6px 0',
                          borderBottom: '1px solid var(--border-light)',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 8,
                        }}
                      >
                        <SeverityBadge severity={alert.severity} />
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                          {alert.src_ip} → {alert.dst_ip}
                        </span>
                        <span style={{ marginLeft: 'auto', color: 'var(--text-muted)' }}>
                          {formatConfidence(alert.confidence)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {cat.count === 0 && (
                  <div style={{ textAlign: 'center', padding: '12px 0', color: 'var(--text-muted)', fontSize: 12 }}>
                    No detections — monitoring
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

export default ThreatDetection;
