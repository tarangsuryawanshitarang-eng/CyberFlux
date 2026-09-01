/**
 * CyberFlux — Reusable UI Components
 */

import React from 'react';
import type { Severity, ThreatStatus } from '../../types';

// ─── Severity Badge ──────────────────────────────────────────────────

export const SeverityBadge = React.memo(function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`severity severity-${severity.toLowerCase()}`}>
      {severity}
    </span>
  );
});

// ─── Threat Status ───────────────────────────────────────────────────

export const ThreatStatusBadge = React.memo(function ThreatStatusBadge({ status }: { status: ThreatStatus }) {
  const classMap: Record<ThreatStatus, string> = {
    BENIGN: 'secure',
    SUSPICIOUS: 'warning',
    MALICIOUS: 'critical',
  };
  return (
    <span className={`status ${classMap[status]}`}>
      <span className="status-dot" />
      {status}
    </span>
  );
});

// ─── Metric Card ─────────────────────────────────────────────────────

interface MetricCardProps {
  label: string;
  value: string | number;
  icon?: React.ReactNode;
  change?: string;
  changeType?: 'positive' | 'negative';
  color?: string;
}

export const MetricCard = React.memo(function MetricCard({
  label, value, icon, change, changeType, color,
}: MetricCardProps) {
  return (
    <div className="card metric-card">
      <div className="metric-label">
        {icon}
        {label}
      </div>
      <div className="metric-value" style={color ? { color } : undefined}>
        {value}
      </div>
      {change && (
        <div className={`metric-change ${changeType || ''}`}>
          {change}
        </div>
      )}
    </div>
  );
});

// ─── Feature Bar ─────────────────────────────────────────────────────

interface FeatureBarProps {
  features: Record<string, number>;
}

export const FeatureBar = React.memo(function FeatureBar({ features }: FeatureBarProps) {
  const sorted = Object.entries(features)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return (
    <div className="feature-bar-container">
      {sorted.map(([name, value]) => (
        <div key={name} className="feature-bar">
          <span className="feature-bar-label">{name}</span>
          <div className="feature-bar-track">
            <div
              className="feature-bar-fill"
              style={{ width: `${Math.min(value * 100, 100)}%` }}
            />
          </div>
          <span className="feature-bar-value">{(value * 100).toFixed(0)}%</span>
        </div>
      ))}
    </div>
  );
});

// ─── Security Banner ─────────────────────────────────────────────────

export function SecurityBanner() {
  const items = [
    { label: 'MONITORING MODE', value: 'READ-ONLY', className: '' },
    { label: 'TRAFFIC DIRECTION', value: 'UNIDIRECTIONAL', className: '' },
    { label: 'RETURN PATH', value: 'BLOCKED', className: 'blocked' },
    { label: 'ACTIVE PROBING', value: 'DISABLED', className: 'disabled' },
    { label: 'PAYLOAD DECRYPTION', value: 'DISABLED', className: 'disabled' },
  ];

  return (
    <div className="security-banner">
      {items.map((item) => (
        <div key={item.label} className="security-banner-item">
          <span className="label">{item.label}:</span>
          <span className={`value ${item.className}`}>{item.value}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Skeleton ────────────────────────────────────────────────────────

export function SkeletonLoader({ height = 200 }: { height?: number }) {
  return <div className="skeleton" style={{ width: '100%', height }} />;
}
