/**
 * CyberFlux — Frontend Configuration
 * 
 * All configurable values in one place.
 */

export const CONFIG = {
  API_URL: import.meta.env.VITE_API_URL || 'http://localhost:8000/api',
  WS_URL: import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/events',

  // Client-side bounds
  MAX_CLIENT_FLOWS: 200,
  MAX_ALERT_HISTORY: 150,
  MAX_METRIC_POINTS: 120,
  MAX_CHART_POINTS: 60,

  // Update throttle (ms)
  CHART_THROTTLE: 1000,
  TABLE_THROTTLE: 500,
  METRICS_THROTTLE: 1000,

  // WebSocket
  WS_RECONNECT_DELAY: 2000,
  WS_MAX_RECONNECT_ATTEMPTS: 10,
} as const;
