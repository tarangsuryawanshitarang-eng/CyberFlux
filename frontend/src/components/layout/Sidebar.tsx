/**
 * CyberFlux — Sidebar Navigation
 */

import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  Network,
  Shield,
} from 'lucide-react';

const NAV_ITEMS = [
  {
    section: 'OVERVIEW',
    items: [
      { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
      { to: '/traffic', icon: Activity, label: 'Live Traffic' },
      { to: '/threats', icon: ShieldAlert, label: 'Threat Detection' },
    ],
  },
  {
    section: 'SYSTEM',
    items: [
      { to: '/architecture', icon: Network, label: 'Architecture' },
    ],
  },
];

export function Sidebar() {
  return (
    <aside className="sidebar">
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="sidebar-brand-icon">
          <Shield size={20} color="#6d3df5" />
        </div>
        <div>
          <div className="sidebar-brand-title">CyberFlux</div>
          <div className="sidebar-brand-subtitle">AI THREAT DETECTION · SIH 2026</div>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ padding: '8px 0', flex: 1 }}>
        {NAV_ITEMS.map((section) => (
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
                  <item.icon size={18} />
                </span>
                <span>{item.label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Security Posture Footer */}
      <div style={{
        padding: '16px',
        borderTop: '1px solid rgba(255,255,255,0.07)',
        fontSize: '9px',
        color: '#71808e',
        letterSpacing: '0.05em',
        lineHeight: 1.6,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#16a34a' }} />
          <span>MONITORING: READ-ONLY</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444' }} />
          <span>RETURN PATH: BLOCKED</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#f59e0b' }} />
          <span>PAYLOAD DECRYPT: DISABLED</span>
        </div>
      </div>
    </aside>
  );
}
