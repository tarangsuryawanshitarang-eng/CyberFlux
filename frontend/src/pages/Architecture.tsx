/**
 * CyberFlux — Architecture Visualization
 */

import { Topbar } from '../components/layout/Topbar';
import { SecurityBanner } from '../components/ui';
import { ArrowDown, Shield, ShieldOff, Eye, Cpu, BarChart3, Bell, Monitor } from 'lucide-react';

const PIPELINE_STAGES = [
  { icon: <Eye size={20} />, title: 'One-Way Traffic Source', desc: 'Synthetic / replay telemetry (production: network tap / mirror port)', color: '#6d3df5' },
  { icon: <Shield size={20} />, title: 'Read-Only Ingestion', desc: 'No return path — monitoring enclave receives packets unidirectionally', color: '#16a34a' },
  { icon: <BarChart3 size={20} />, title: 'Flow Engine', desc: 'Aggregates raw events into flow records with running statistics', color: '#2563eb' },
  { icon: <Cpu size={20} />, title: 'Feature Engine', desc: 'Extracts 30+ behavioral features: entropy, timing, DNS, TLS metadata', color: '#8b5cf6' },
  { icon: <ShieldOff size={20} />, title: 'AI / Detection Engine', desc: 'Rule-based prototype detector (future: Random Forest, XGBoost, Isolation Forest)', color: '#ef4444' },
  { icon: <BarChart3 size={20} />, title: 'Risk Engine', desc: 'Confidence scoring + severity derivation from threat class + feature magnitudes', color: '#f59e0b' },
  { icon: <Bell size={20} />, title: 'Alert Engine', desc: 'Generates alerts with evidence and top contributing features', color: '#ec4899' },
  { icon: <Monitor size={20} />, title: 'SOC Dashboard', desc: 'Real-time WebSocket streaming to React frontend', color: '#14b8a6' },
];

function Architecture() {
  return (
    <>
      <Topbar title="System Architecture" description="Unidirectional monitoring architecture — NO return path to monitored network" />
      <div className="content">
        <SecurityBanner />

        <div style={{ maxWidth: 600, margin: '32px auto' }}>
          {PIPELINE_STAGES.map((stage, i) => (
            <div key={i}>
              {/* Stage */}
              <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '16px 20px' }}>
                <div style={{
                  width: 44, height: 44, borderRadius: 10,
                  display: 'grid', placeItems: 'center',
                  background: `${stage.color}15`, color: stage.color,
                  border: `1px solid ${stage.color}30`,
                  flexShrink: 0,
                }}>
                  {stage.icon}
                </div>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 650 }}>{stage.title}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>{stage.desc}</div>
                </div>
              </div>

              {/* Arrow */}
              {i < PIPELINE_STAGES.length - 1 && (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '8px 0' }}>
                  <ArrowDown size={20} color="var(--text-muted)" />
                </div>
              )}

              {/* NO RETURN PATH marker after ingestion */}
              {i === 1 && (
                <div style={{
                  display: 'flex', justifyContent: 'center', padding: '4px 0',
                }}>
                  <div style={{
                    padding: '4px 12px',
                    background: 'var(--danger-soft)',
                    border: '1px solid #fecaca',
                    borderRadius: 6,
                    fontSize: 10,
                    fontWeight: 700,
                    color: 'var(--danger)',
                    letterSpacing: '0.06em',
                  }}>
                    ⛔ NO RETURN PATH — DATA FLOWS ONE WAY ONLY
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Security Constraints */}
        <div className="card" style={{ maxWidth: 600, margin: '24px auto' }}>
          <div className="card-header">
            <span className="card-title">Security Constraints</span>
          </div>
          <div className="card-body">
            <div style={{ display: 'grid', gap: 12, fontSize: 13 }}>
              {[
                { label: 'Send traffic back to source', status: 'NEVER' },
                { label: 'Probe source/destination systems', status: 'NEVER' },
                { label: 'Complete network handshakes', status: 'NEVER' },
                { label: 'Active reconnaissance', status: 'NEVER' },
                { label: 'Blocking/mitigation commands', status: 'NEVER' },
                { label: 'Decrypt application payloads', status: 'NEVER' },
                { label: 'Expose payload contents', status: 'NEVER' },
                { label: 'Offensive attack functionality', status: 'NEVER' },
              ].map((item) => (
                <div key={item.label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                  <span style={{
                    fontSize: 10, fontWeight: 700, color: 'var(--danger)',
                    padding: '2px 8px', background: 'var(--danger-soft)', borderRadius: 4,
                  }}>
                    {item.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

export default Architecture;
