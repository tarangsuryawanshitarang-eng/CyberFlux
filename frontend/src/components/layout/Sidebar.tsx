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
          <div className="sidebar-brand-subtitle">AI SOC V2 · UNIDIRECTIONAL</div>
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
                      background: 'rgba(99, 102, 241, 0.2)',
                      color: '#a5b4fc',
                      borderColor: 'rgba(99, 102, 241, 0.3)',
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
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#10b981' }} />
          <span>MODE: READ-ONLY INGEST</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444' }} />
          <span>RETURN PATH: BLOCKED</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#f59e0b' }} />
          <span>ACTIVE PROBING: DISABLED</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#64748b' }} />
          <span>PAYLOAD DECRYPT: DISABLED</span>
        </div>
      </div>
    </aside>
  );
}
