/**
 * CyberFlux — useWebSocket Hook
 */

import { useEffect, useState } from 'react';
import { wsClient } from '../services/websocket';

export function useWebSocket() {
  const [connected, setConnected] = useState(wsClient.isConnected);

  useEffect(() => {
    wsClient.connect();
    const unsub = wsClient.onConnectionChange(setConnected);
    return () => {
      unsub();
    };
  }, []);

  return { connected };
}
