/**
 * CyberFlux — Utility Formatters
 */

import type { Severity, ThreatStatus } from '../types';

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toFixed(0);
}

export function formatRate(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M/s`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K/s`;
  return `${n.toFixed(1)}/s`;
}

export function formatLatency(ms: number): string {
  if (ms < 1) return `${(ms * 1000).toFixed(0)}μs`;
  if (ms < 1000) return `${ms.toFixed(1)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

export function formatTimestamp(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatDuration(seconds: number): string {
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms`;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const min = Math.floor(seconds / 60);
  const sec = Math.floor(seconds % 60);
  return `${min}m ${sec}s`;
}

export function formatConfidence(confidence: number): string {
  return `${(confidence * 100).toFixed(1)}%`;
}

export function severityColor(severity: Severity): string {
  const colors: Record<Severity, string> = {
    CRITICAL: 'var(--danger)',
    HIGH: '#dc2626',
    MEDIUM: 'var(--warning)',
    LOW: 'var(--info)',
    INFO: 'var(--text-muted)',
  };
  return colors[severity] || 'var(--text-muted)';
}

export function threatStatusColor(status: ThreatStatus): string {
  const colors: Record<ThreatStatus, string> = {
    BENIGN: 'var(--success)',
    SUSPICIOUS: 'var(--warning)',
    MALICIOUS: 'var(--danger)',
  };
  return colors[status] || 'var(--text-muted)';
}

export function truncateIP(ip: string, maxLen: number = 15): string {
  return ip.length > maxLen ? ip.substring(0, maxLen) + '…' : ip;
}
