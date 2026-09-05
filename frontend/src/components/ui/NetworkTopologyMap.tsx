/**
 * CyberFlux V2 — Geographic & Network Activity Map
 * 
 * Interactive SVG network topology visualizer showing external ingress traffic
 * crossing the unidirectional data diode tap into internal protected subnets.
 * Features animated flow pulses, threat hotspot indicators, and hover tooltips.
 */

import React, { useState } from 'react';
import { Shield, Activity, MapPin } from 'lucide-react';
import type { Alert } from '../../types';

interface NetworkTopologyMapProps {
  alerts: Alert[];
  trafficRateMbps: number;
}

interface IngressNode {
  id: string;
  label: string;
  ip: string;
  country: string;
  x: number;
  y: number;
  threats: number;
  type: 'external' | 'internal' | 'diode';
}

export const NetworkTopologyMap: React.FC<NetworkTopologyMapProps> = React.memo(({ alerts, trafficRateMbps }) => {
  const [hoveredNode, setHoveredNode] = useState<IngressNode | null>(null);

  // Group alerts by destination or source to identify targeted nodes
  const threatCountsByIp = alerts.reduce<Record<string, number>>((acc, a) => {
    acc[a.src_ip] = (acc[a.src_ip] || 0) + 1;
    acc[a.dst_ip] = (acc[a.dst_ip] || 0) + 1;
    return acc;
  }, {});

  const nodes: IngressNode[] = [
    // External Ingress (Left)
    { id: 'ext-1', label: 'WAN Gateway (US-East)', ip: '198.51.100.24', country: 'US', x: 45, y: 55, threats: threatCountsByIp['198.51.100.24'] || (alerts.length > 0 ? 3 : 0), type: 'external' },
    { id: 'ext-2', label: 'External Transit (EU-Central)', ip: '83.13.30.183', country: 'DE', x: 45, y: 115, threats: threatCountsByIp['83.13.30.183'] || (alerts.length > 1 ? 5 : 0), type: 'external' },
    { id: 'ext-3', label: 'Edge Ingress (APAC-S)', ip: '219.21.3.188', country: 'JP', x: 45, y: 175, threats: threatCountsByIp['219.21.3.188'] || (alerts.length > 2 ? 4 : 0), type: 'external' },
    { id: 'ext-4', label: 'Tor / Proxy Exit (Global)', ip: '185.220.101.5', country: 'NL', x: 45, y: 235, threats: threatCountsByIp['185.220.101.5'] || (alerts.length > 3 ? 6 : 0), type: 'external' },

    // Data Diode Tap (Center)
    { id: 'diode-rx', label: 'RX Photodiode Tap', ip: 'Data Diode (No TX)', country: 'LOCAL', x: 210, y: 145, threats: 0, type: 'diode' },

    // Internal Protected Zones (Right)
    { id: 'int-1', label: 'Core Ingest Enclave', ip: '10.0.1.0/24', country: 'VLAN 10', x: 375, y: 55, threats: alerts.filter(a => a.dst_ip.startsWith('10.0.1')).length, type: 'internal' },
    { id: 'int-2', label: 'DNS & Directory Cluster', ip: '10.0.2.0/24', country: 'VLAN 20', x: 375, y: 115, threats: alerts.filter(a => a.dst_ip.startsWith('10.0.2') || a.dst_port === 53).length, type: 'internal' },
    { id: 'int-3', label: 'Enterprise DMZ Services', ip: '172.16.0.0/16', country: 'VLAN 30', x: 375, y: 175, threats: alerts.filter(a => a.dst_ip.startsWith('172.16')).length, type: 'internal' },
    { id: 'int-4', label: 'Secured Data Vault', ip: '192.168.1.0/24', country: 'VLAN 40', x: 375, y: 235, threats: alerts.filter(a => a.dst_ip.startsWith('192.168.1')).length, type: 'internal' },
  ];

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Topology Header bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8, fontSize: 11 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-muted)' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#6366f1', display: 'inline-block' }} /> External WAN
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#10b981' }}>
            <Shield size={11} /> Unidirectional Diode
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#38bdf8' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#38bdf8', display: 'inline-block' }} /> Protected Enclaves
          </span>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#10b981', display: 'flex', alignItems: 'center', gap: 4 }}>
          <Activity size={12} /> {trafficRateMbps.toFixed(2)} Mbps Line Rate
        </div>
      </div>

      {/* SVG Canvas */}
      <div style={{ flex: 1, position: 'relative', minHeight: 220, background: 'rgba(11, 19, 36, 0.4)', borderRadius: 8, border: '1px solid var(--border)' }}>
        <svg viewBox="0 0 440 290" style={{ width: '100%', height: '100%' }}>
          <defs>
            {/* Linear gradients for transmission paths */}
            <linearGradient id="flowGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#6366f1" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#10b981" stopOpacity="0.9" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.8" />
            </linearGradient>

            <linearGradient id="threatGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.9" />
              <stop offset="50%" stopColor="#f59e0b" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#ef4444" stopOpacity="0.9" />
            </linearGradient>

            {/* Pulsing animation styles */}
            <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Background grid markings */}
          <line x1="125" y1="20" x2="125" y2="270" stroke="rgba(255,255,255,0.03)" strokeDasharray="3 3" />
          <line x1="295" y1="20" x2="295" y2="270" stroke="rgba(255,255,255,0.03)" strokeDasharray="3 3" />

          {/* Diode Barrier Visual Representation */}
          <rect x="200" y="30" width="20" height="230" rx="4" fill="rgba(16, 185, 129, 0.06)" stroke="rgba(16, 185, 129, 0.3)" strokeDasharray="4 2" />
          <text x="210" y="275" textAnchor="middle" fill="#10b981" fontSize="9" fontWeight="700" letterSpacing="0.08em">
            ONE-WAY RX DIODE
          </text>

          {/* Ingress transmission paths (External -> Diode) */}
          {[55, 115, 175, 235].map((y, idx) => {
            const hasThreat = alerts.length > idx;
            return (
              <g key={`path-in-${idx}`}>
                <path
                  d={`M 55 ${y} C 120 ${y}, 140 145, 205 145`}
                  fill="none"
                  stroke={hasThreat ? 'url(#threatGrad)' : 'url(#flowGrad)'}
                  strokeWidth={hasThreat ? 2 : 1.2}
                  strokeOpacity={hasThreat ? 0.75 : 0.35}
                />
                {/* Animated flow particle */}
                <circle r={hasThreat ? 3 : 2} fill={hasThreat ? '#ef4444' : '#10b981'}>
                  <animateMotion
                    path={`M 55 ${y} C 120 ${y}, 140 145, 205 145`}
                    dur={`${2.2 + idx * 0.4}s`}
                    repeatCount="indefinite"
                  />
                </circle>
              </g>
            );
          })}

          {/* Egress distribution paths (Diode -> Internal) */}
          {[55, 115, 175, 235].map((y, idx) => (
            <g key={`path-out-${idx}`}>
              <path
                d={`M 215 145 C 280 145, 300 ${y}, 365 ${y}`}
                fill="none"
                stroke="url(#flowGrad)"
                strokeWidth={1.2}
                strokeOpacity={0.35}
              />
              <circle r={2} fill="#38bdf8">
                <animateMotion
                  path={`M 215 145 C 280 145, 300 ${y}, 365 ${y}`}
                  dur={`${2.5 + idx * 0.3}s`}
                  repeatCount="indefinite"
                />
              </circle>
            </g>
          ))}

          {/* Render Nodes */}
          {nodes.map((node) => {
            const isThreatNode = node.threats > 0;
            const isHovered = hoveredNode?.id === node.id;
            const nodeFill = node.type === 'diode'
              ? '#10b981'
              : node.type === 'external'
                ? isThreatNode ? '#ef4444' : '#6366f1'
                : '#38bdf8';

            return (
              <g
                key={node.id}
                style={{ cursor: 'pointer' }}
                onMouseEnter={() => setHoveredNode(node)}
                onMouseLeave={() => setHoveredNode(null)}
              >
                {/* Radar pulse for active threats */}
                {isThreatNode && (
                  <circle cx={node.x} cy={node.y} r={14} fill="none" stroke="#ef4444" strokeWidth={1.5} opacity={0.6}>
                    <animate attributeName="r" values="8;20" dur="1.8s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.8;0" dur="1.8s" repeatCount="indefinite" />
                  </circle>
                )}

                {/* Node Outer Ring */}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={isHovered ? 9 : 7}
                  fill="#0b1324"
                  stroke={nodeFill}
                  strokeWidth={isHovered ? 2.5 : 1.8}
                  filter={isHovered ? 'url(#glow)' : undefined}
                />

                {/* Node Core */}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={3.5}
                  fill={nodeFill}
                />

                {/* Node Labels */}
                <text
                  x={node.type === 'external' ? node.x - 12 : node.type === 'internal' ? node.x + 12 : node.x}
                  y={node.type === 'diode' ? node.y - 12 : node.y + 3}
                  textAnchor={node.type === 'external' ? 'end' : node.type === 'internal' ? 'start' : 'middle'}
                  fill={isHovered ? '#f8fafc' : 'var(--text-secondary)'}
                  fontSize="9.5"
                  fontWeight={isHovered ? '700' : '500'}
                  fontFamily="var(--font-mono)"
                >
                  {node.country !== 'LOCAL' ? `[${node.country}] ` : ''}{node.ip}
                </text>

                {/* Threat badge indicator */}
                {isThreatNode && (
                  <g transform={`translate(${node.type === 'external' ? node.x - 22 : node.x + 10}, ${node.y - 12})`}>
                    <rect width="18" height="11" rx="3" fill="#ef4444" />
                    <text x="9" y="8.5" textAnchor="middle" fill="#ffffff" fontSize="7.5" fontWeight="800">
                      {node.threats}
                    </text>
                  </g>
                )}
              </g>
            );
          })}
        </svg>

        {/* Hover Tooltip Overlay */}
        {hoveredNode && (
          <div
            style={{
              position: 'absolute',
              bottom: 8,
              left: 12,
              right: 12,
              padding: '6px 12px',
              background: 'rgba(17, 28, 51, 0.95)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              boxShadow: '0 4px 16px rgba(0,0,0,0.6)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              fontSize: 11,
              pointerEvents: 'none',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <MapPin size={13} color="#818cf8" />
              <span style={{ fontWeight: 700, color: '#f8fafc' }}>{hoveredNode.label}</span>
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{hoveredNode.ip}</span>
            </div>
            <div style={{ display: 'flex', gap: 12, fontFamily: 'var(--font-mono)' }}>
              <span>Region: <b style={{ color: '#818cf8' }}>{hoveredNode.country}</b></span>
              <span>Threats: <b style={{ color: hoveredNode.threats > 0 ? '#ef4444' : '#10b981' }}>{hoveredNode.threats}</b></span>
              <span>Flow Direction: <b style={{ color: '#10b981' }}>Read-Only Ingress</b></span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
});
