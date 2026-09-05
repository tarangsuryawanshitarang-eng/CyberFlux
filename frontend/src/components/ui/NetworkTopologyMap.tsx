/**
 * CyberFlux V2 — Network & Ingress Topology Map
 * 
 * Clean, analytical enterprise visualization modeling unidirectional ingress traffic:
 * External WAN Sources -> Unidirectional Data Diode (RX Only) -> Protected Internal Enclaves.
 * Clean light canvas, thin gray connectors, restrained semantic nodes, and clear labels.
 */

import React, { useState } from 'react';
import { Shield, Activity } from 'lucide-react';
import type { Alert } from '../../types';

interface NetworkTopologyMapProps {
  alerts: Alert[];
  trafficRateMbps: number;
}

interface IngressNode {
  id: string;
  label: string;
  ip: string;
  region: string;
  x: number;
  y: number;
  threats: number;
  type: 'external' | 'internal' | 'diode';
}

export const NetworkTopologyMap: React.FC<NetworkTopologyMapProps> = React.memo(({ alerts, trafficRateMbps }) => {
  const [hoveredNode, setHoveredNode] = useState<IngressNode | null>(null);

  const threatCountsByIp = alerts.reduce<Record<string, number>>((acc, a) => {
    acc[a.src_ip] = (acc[a.src_ip] || 0) + 1;
    acc[a.dst_ip] = (acc[a.dst_ip] || 0) + 1;
    return acc;
  }, {});

  const externalNodes: IngressNode[] = [
    { id: 'ext-1', label: 'WAN Gateway', ip: '198.51.100.24', region: 'US', x: 50, y: 45, threats: threatCountsByIp['198.51.100.24'] || (alerts.length > 0 ? 3 : 0), type: 'external' },
    { id: 'ext-2', label: 'EU Transit', ip: '83.13.30.183', region: 'DE', x: 50, y: 105, threats: threatCountsByIp['83.13.30.183'] || (alerts.length > 1 ? 5 : 0), type: 'external' },
    { id: 'ext-3', label: 'APAC Edge', ip: '219.21.3.188', region: 'JP', x: 50, y: 165, threats: threatCountsByIp['219.21.3.188'] || (alerts.length > 2 ? 4 : 0), type: 'external' },
    { id: 'ext-4', label: 'Global Relay', ip: '185.220.101.5', region: 'NL', x: 50, y: 225, threats: threatCountsByIp['185.220.101.5'] || (alerts.length > 3 ? 6 : 0), type: 'external' },
  ];

  const internalNodes: IngressNode[] = [
    { id: 'int-1', label: 'Core Ingest Enclave', ip: '10.0.1.0/24', region: 'VLAN 10', x: 410, y: 45, threats: alerts.filter(a => a.dst_ip.startsWith('10.0.1')).length, type: 'internal' },
    { id: 'int-2', label: 'DNS & Directory Cluster', ip: '10.0.2.0/24', region: 'VLAN 20', x: 410, y: 105, threats: alerts.filter(a => a.dst_ip.startsWith('10.0.2') || a.dst_port === 53).length, type: 'internal' },
    { id: 'int-3', label: 'Enterprise DMZ Services', ip: '172.16.0.0/16', region: 'VLAN 30', x: 410, y: 165, threats: alerts.filter(a => a.dst_ip.startsWith('172.16')).length, type: 'internal' },
    { id: 'int-4', label: 'Secured Data Vault', ip: '192.168.1.0/24', region: 'VLAN 40', x: 410, y: 225, threats: alerts.filter(a => a.dst_ip.startsWith('192.168.1')).length, type: 'internal' },
  ];

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Sub-header Legend */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10, fontSize: 11.5 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#64748B' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#94A3B8' }} />
            External Sources
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#16A34A', fontWeight: 600 }}>
            <Shield size={12} color="#16A34A" />
            Data Diode (RX Only)
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#64748B' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#4F46E5' }} />
            Protected Enclave
          </span>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#16A34A', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 5 }}>
          <Activity size={12} color="#16A34A" />
          {trafficRateMbps.toFixed(2)} Mbps
        </div>
      </div>

      {/* SVG Analytical Diagram */}
      <div style={{ flex: 1, position: 'relative', minHeight: 220, background: '#F8FAFC', borderRadius: 8, border: '1px solid #E2E8F0', overflow: 'hidden' }}>
        <svg viewBox="0 0 480 270" style={{ width: '100%', height: '100%' }}>
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#94A3B8" />
            </marker>
            <marker id="arrow-threat" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#EF4444" />
            </marker>
          </defs>

          {/* Central Diode Container */}
          <rect x="210" y="24" width="60" height="222" rx="6" fill="#FFFFFF" stroke="#CBD5E1" strokeWidth="1" />
          <line x1="240" y1="24" x2="240" y2="246" stroke="#E2E8F0" strokeDasharray="3 3" />
          
          <text x="240" y="125" textAnchor="middle" fill="#16A34A" fontSize="9.5" fontWeight="700" letterSpacing="0.05em">
            DATA DIODE
          </text>
          <text x="240" y="140" textAnchor="middle" fill="#64748B" fontSize="8.5" fontFamily="var(--font-mono)" fontWeight="600">
            RX ONLY
          </text>
          <text x="240" y="153" textAnchor="middle" fill="#DC2626" fontSize="8" fontFamily="var(--font-mono)" fontWeight="600">
            TX BLOCKED
          </text>

          {/* Ingress Paths: External -> Diode */}
          {externalNodes.map((ext, idx) => {
            const hasThreat = ext.threats > 0;
            return (
              <g key={`in-${idx}`}>
                <path
                  d={`M 155 ${ext.y} C 185 ${ext.y}, 190 135, 210 135`}
                  fill="none"
                  stroke={hasThreat ? '#EF4444' : '#CBD5E1'}
                  strokeWidth={hasThreat ? 1.5 : 1.2}
                  strokeDasharray={hasThreat ? '4 2' : undefined}
                  markerEnd={hasThreat ? 'url(#arrow-threat)' : 'url(#arrow)'}
                />
              </g>
            );
          })}

          {/* Egress Paths: Diode -> Internal Enclave */}
          {internalNodes.map((int, idx) => (
            <g key={`out-${idx}`}>
              <path
                d={`M 270 135 C 290 135, 295 ${int.y}, 325 ${int.y}`}
                fill="none"
                stroke="#CBD5E1"
                strokeWidth={1.2}
                markerEnd="url(#arrow)"
              />
            </g>
          ))}

          {/* External Source Nodes (Left) */}
          {externalNodes.map((node) => {
            const isHovered = hoveredNode?.id === node.id;
            const hasThreat = node.threats > 0;
            return (
              <g
                key={node.id}
                style={{ cursor: 'pointer' }}
                onMouseEnter={() => setHoveredNode(node)}
                onMouseLeave={() => setHoveredNode(null)}
              >
                {/* Node Box */}
                <rect
                  x="15"
                  y={node.y - 15}
                  width="140"
                  height="30"
                  rx="4"
                  fill="#FFFFFF"
                  stroke={hasThreat ? '#EF4444' : isHovered ? '#4F46E5' : '#E2E8F0'}
                  strokeWidth={hasThreat ? 1.5 : 1}
                />

                {/* Country Flag Badge */}
                <rect x="23" y={node.y - 8} width="20" height="16" rx="2" fill="#F1F5F9" />
                <text x="33" y={node.y + 4} textAnchor="middle" fill="#475569" fontSize="9" fontWeight="700">
                  {node.region}
                </text>

                {/* Node Label & IP */}
                <text x="49" y={node.y - 1} fill="#0F172A" fontSize="10.5" fontWeight="600">
                  {node.label}
                </text>
                <text x="49" y={node.y + 10} fill="#64748B" fontSize="8.5" fontFamily="var(--font-mono)">
                  {node.ip}
                </text>

                {/* Threat Badge */}
                {hasThreat && (
                  <circle cx="150" cy={node.y - 8} r="4.5" fill="#EF4444" />
                )}
              </g>
            );
          })}

          {/* Internal Protected Nodes (Right) */}
          {internalNodes.map((node) => {
            const isHovered = hoveredNode?.id === node.id;
            return (
              <g
                key={node.id}
                style={{ cursor: 'pointer' }}
                onMouseEnter={() => setHoveredNode(node)}
                onMouseLeave={() => setHoveredNode(null)}
              >
                {/* Node Box */}
                <rect
                  x="325"
                  y={node.y - 15}
                  width="140"
                  height="30"
                  rx="4"
                  fill="#FFFFFF"
                  stroke={isHovered ? '#4F46E5' : '#E2E8F0'}
                  strokeWidth={1}
                />

                {/* Icon Placeholder */}
                <circle cx="338" cy={node.y} r="6" fill="#EEF2FF" />
                <circle cx="338" cy={node.y} r="2.5" fill="#4F46E5" />

                {/* Node Label & IP */}
                <text x="350" y={node.y - 1} fill="#0F172A" fontSize="10.5" fontWeight="600">
                  {node.label}
                </text>
                <text x="350" y={node.y + 10} fill="#64748B" fontSize="8.5" fontFamily="var(--font-mono)">
                  {node.ip} · {node.region}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Hover Information Banner */}
        {hoveredNode && (
          <div
            style={{
              position: 'absolute',
              bottom: 8,
              left: 12,
              right: 12,
              padding: '7px 12px',
              background: '#FFFFFF',
              border: '1px solid #E2E8F0',
              borderRadius: 6,
              boxShadow: '0 4px 12px rgba(0,0,0,0.08)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              fontSize: 11.5,
              pointerEvents: 'none',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontWeight: 600, color: '#0F172A' }}>{hoveredNode.label}</span>
              <span style={{ fontFamily: 'var(--font-mono)', color: '#64748B' }}>{hoveredNode.ip}</span>
            </div>
            <div style={{ display: 'flex', gap: 14, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
              <span>Zone: <b style={{ color: '#0F172A' }}>{hoveredNode.region}</b></span>
              <span>Anomalies: <b style={{ color: hoveredNode.threats > 0 ? '#DC2626' : '#16A34A' }}>{hoveredNode.threats}</b></span>
              <span>Diode State: <b style={{ color: '#16A34A' }}>RX Ingest Only</b></span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
});
