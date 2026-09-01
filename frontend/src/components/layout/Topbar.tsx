/**
 * CyberFlux — Top Bar
 */

import { useWebSocket } from '../../hooks/useWebSocket';
import { useSimulationStore } from '../../stores/simulationStore';

interface TopbarProps {
  title: string;
  description?: string;
}

export function Topbar({ title, description }: TopbarProps) {
  const { connected } = useWebSocket();
  const phase = useSimulationStore((s) => s.currentPhase);

  return (
    <header className="topbar">
      <div>
        <h1 className="page-title">{title}</h1>
        {description && <p className="page-description">{description}</p>}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        {/* Demo Phase Indicator */}
        {phase && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '6px 12px',
            background: 'var(--primary-soft)',
            borderRadius: 8,
            fontSize: 11,
            fontWeight: 650,
            color: 'var(--primary)',
          }}>
            <span>DEMO</span>
            <span style={{ color: 'var(--text-secondary)' }}>
              Phase {(phase.phase_index || 0) + 1}/{phase.total_phases}: {phase.phase_name}
            </span>
          </div>
        )}

        {/* Connection Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          fontSize: 11,
          fontWeight: 600,
          color: connected ? 'var(--success)' : 'var(--danger)',
        }}>
          <div className={`connection-dot ${connected ? 'connected' : 'disconnected'}`} />
          {connected ? 'LIVE' : 'OFFLINE'}
        </div>

        {/* Prototype Label */}
        <div style={{
          padding: '4px 10px',
          background: 'var(--bg-surface-soft)',
          border: '1px solid var(--border)',
          borderRadius: 6,
          fontSize: 9,
          fontWeight: 700,
          color: 'var(--text-muted)',
          letterSpacing: '0.08em',
        }}>
          SIH 2026 PROTOTYPE
        </div>
      </div>
    </header>
  );
}
