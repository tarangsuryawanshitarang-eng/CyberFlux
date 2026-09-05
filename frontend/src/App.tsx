/**
 * CyberFlux V2 — Main Application
 * 
 * Route-level code splitting with React.lazy().
 */

import React, { Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Sidebar } from './components/layout/Sidebar';
import { SkeletonLoader } from './components/ui';
import { useWebSocket } from './hooks/useWebSocket';

// ─── Lazy-loaded pages (code splitting) ──────────────────────────
const Dashboard = React.lazy(() => import('./pages/Dashboard'));
const TrafficExplorer = React.lazy(() => import('./pages/TrafficExplorer'));
const ThreatDetection = React.lazy(() => import('./pages/ThreatDetection'));
const AlertsCenter = React.lazy(() => import('./pages/AlertsCenter'));
const TelemetryAnalytics = React.lazy(() => import('./pages/TelemetryAnalytics'));
const FlowDetail = React.lazy(() => import('./pages/FlowDetail'));
const Architecture = React.lazy(() => import('./pages/Architecture'));

function AppContent() {
  // Initialize real-time WebSocket telemetry connection
  useWebSocket();

  return (
    <div className="app-shell">
      <Sidebar />
      <div className="main">
        <Suspense fallback={
          <div style={{ padding: 24 }}>
            <SkeletonLoader height={50} />
            <div style={{ marginTop: 16 }}>
              <SkeletonLoader height={320} />
            </div>
          </div>
        }>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/traffic" element={<TrafficExplorer />} />
            <Route path="/flows" element={<TrafficExplorer />} />
            <Route path="/alerts" element={<AlertsCenter />} />
            <Route path="/threats" element={<ThreatDetection />} />
            <Route path="/analytics" element={<TelemetryAnalytics />} />
            <Route path="/flow/:flowId" element={<FlowDetail />} />
            <Route path="/architecture" element={<Architecture />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}
