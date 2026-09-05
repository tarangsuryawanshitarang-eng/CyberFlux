/**
 * CyberFlux V2 — Sidebar Navigation
 * 
 * Grouped navigation hierarchy with active states, threat counts,
 * and pinned data-diode security constraints.
 */

import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  Network,
  Shield,
  Layers,
  AlertTriangle,
  BarChart3,
} from 'lucide-react';
import { useAlertStore } from '../../stores/alertStore';

export function Sidebar() {
  const alerts = useAlertStore((s) => s.alerts);
  const criticalCount = alerts.filter((a) => a.severity === 'CRITICAL').length;

  const NAV_SECTIONS = [
    {
      section: 'OVERVIEW',
      items: [
        { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
      ],
    },
    {
      section: 'MONITOR',
      items: [
        { to: '/traffic', icon: Activity, label: 'Live Traffic' },
        { to: '/flows', icon: Layers, label: 'Flow Explorer' },
      ],
    },
    {
      section: 'DETECT',
      items: [
        {
          to: '/alerts',
          icon: AlertTriangle,
          label: 'Alerts Center',
          badge: alerts.length > 0 ? alerts.length : undefined,
          isCritical: criticalCount > 0,
        },
        { to: '/threats', icon: ShieldAlert, label: 'Threats & ATT&CK' },
      ],
    },
    {
      section: 'ANALYZE',
      items: [
        { to: '/analytics', icon: BarChart3, label: 'Telemetry Analytics' },
      ],
    },
    {
      section: 'SYSTEM',
      items: [
        { to: '/architecture', icon: Network, label: 'Pipeline Architecture' },
      ],
    },
  ];

  return (
    <aside className="sidebar">
      {/* Brand Header */}
      <div className="sidebar-brand">
        <div className="sidebar-brand-icon">
          <Shield size={18} />
        </div>
        <div>
          <div className="sidebar-brand-title">CyberFlux</div>
          <div className="sidebar-brand-subtitle">AI SOC</div>
        </div>
      </div>

      {/* Grouped Navigation */}
      <nav style={{ padding: '6px 0', flex: 1, overflowY: 'auto' }}>
        {NAV_SECTIONS.map((section) => (
          <div key={section.section}>
            <div className="nav-section">{section.section}</div>
            {section.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `nav-item ${isActive ? 'active' : ''}`
                }
                end={item.to === '/'}
              >
                <span className="nav-item-icon">
                  <item.icon size={15} />
                </span>
                <span>{item.label}</span>
                {item.badge !== undefined && (
                  <span
                    className="nav-item-badge"
                    style={item.isCritical ? undefined : {
                      background: '#EEF2FF',
                      color: '#4338CA',
                      border: '1px solid #C7D2FE',
                    }}
                  >
                    {item.badge}
                  </span>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Security Posture Footer (Passive Data Diode Constraints) */}
      <div className="sidebar-footer">
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 5 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#10B981' }} />
          <span style={{ fontWeight: 600, color: '#0F172A' }}>INGEST:</span>
          <span style={{ color: '#16A34A', fontWeight: 600 }}>READ-ONLY</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 5 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#EF4444' }} />
          <span style={{ fontWeight: 600, color: '#0F172A' }}>RETURN PATH:</span>
          <span style={{ color: '#DC2626', fontWeight: 600 }}>BLOCKED</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 5 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#F59E0B' }} />
          <span style={{ fontWeight: 600, color: '#0F172A' }}>PROBING:</span>
          <span style={{ color: '#D97706', fontWeight: 600 }}>DISABLED</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#94A3B8' }} />
          <span style={{ fontWeight: 600, color: '#0F172A' }}>DECRYPT:</span>
          <span style={{ color: '#64748B', fontWeight: 600 }}>DISABLED</span>
        </div>
      </div>
    </aside>
  );
}
