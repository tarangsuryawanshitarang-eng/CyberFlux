/**
 * CyberFlux — WebSocket Client
 * 
 * Connection lifecycle, reconnection, heartbeat, event routing to stores.
 */

import { CONFIG } from '../utils/config';
import { useFlowStore } from '../stores/flowStore';
import { useAlertStore } from '../stores/alertStore';
import { useMetricsStore } from '../stores/metricsStore';
import { useSimulationStore } from '../stores/simulationStore';
import type { WSEvent, FlowEvent, Alert, SystemMetrics, DemoPhaseInfo } from '../types';

class WebSocketClient {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private _isConnected = false;
  private _listeners: Array<(connected: boolean) => void> = [];

  get isConnected(): boolean {
    return this._isConnected;
  }

  onConnectionChange(cb: (connected: boolean) => void): () => void {
    this._listeners.push(cb);
    return () => {
      this._listeners = this._listeners.filter((l) => l !== cb);
    };
  }

  private notifyConnectionChange(connected: boolean): void {
    this._isConnected = connected;
    this._listeners.forEach((cb) => cb(connected));
  }

  connect(): void {
    if (this.ws?.readyState === WebSocket.OPEN) return;

    try {
      this.ws = new WebSocket(CONFIG.WS_URL);

      this.ws.onopen = () => {
        this.reconnectAttempts = 0;
        this.notifyConnectionChange(true);
        console.log('[WS] Connected');
      };

      this.ws.onmessage = (event) => {
        try {
          const msg: WSEvent = JSON.parse(event.data);
          this.handleEvent(msg);
        } catch {
          // Ignore malformed messages
        }
      };

      this.ws.onclose = () => {
        this.notifyConnectionChange(false);
        console.log('[WS] Disconnected');
        this.scheduleReconnect();
      };

      this.ws.onerror = () => {
        // onclose will fire after onerror
      };
    } catch {
      this.scheduleReconnect();
    }
  }

  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.notifyConnectionChange(false);
  }

  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= CONFIG.WS_MAX_RECONNECT_ATTEMPTS) {
      console.log('[WS] Max reconnect attempts reached');
      return;
    }
    this.reconnectAttempts++;
    const delay = CONFIG.WS_RECONNECT_DELAY * Math.min(this.reconnectAttempts, 5);
    console.log(`[WS] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
    this.reconnectTimer = setTimeout(() => this.connect(), delay);
  }

  private handleEvent(msg: WSEvent): void {
    switch (msg.type) {
      case 'traffic_update':
        useFlowStore.getState().addFlow(msg.data as FlowEvent);
        break;

      case 'alert':
        useAlertStore.getState().addAlert(msg.data as Alert);
        break;

      case 'metrics_update':
        useMetricsStore.getState().updateMetrics(msg.data as SystemMetrics);
        break;

      case 'demo_phase':
        useSimulationStore.getState().setPhase(msg.data as DemoPhaseInfo);
        break;

      case 'heartbeat':
      case 'pong':
        // Connection alive
        break;
    }
  }

  sendPing(): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: 'ping' }));
    }
  }
}

// Singleton
export const wsClient = new WebSocketClient();
