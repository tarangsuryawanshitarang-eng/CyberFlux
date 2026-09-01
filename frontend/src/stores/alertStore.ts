/**
 * CyberFlux — Alert Store (Zustand)
 */

import { create } from 'zustand';
import type { Alert, Severity } from '../types';
import { CONFIG } from '../utils/config';

interface AlertState {
  alerts: Alert[];
  severityCounts: Record<Severity, number>;
  threatCounts: Record<string, number>;
  addAlert: (alert: Alert) => void;
}

export const useAlertStore = create<AlertState>((set) => ({
  alerts: [],
  severityCounts: { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
  threatCounts: {},

  addAlert: (alert: Alert) => {
    set((state) => {
      const newAlerts = [alert, ...state.alerts];
      if (newAlerts.length > CONFIG.MAX_ALERT_HISTORY) {
        newAlerts.length = CONFIG.MAX_ALERT_HISTORY;
      }

      const newSeverityCounts = { ...state.severityCounts };
      newSeverityCounts[alert.severity] = (newSeverityCounts[alert.severity] || 0) + 1;

      const newThreatCounts = { ...state.threatCounts };
      newThreatCounts[alert.threat_class] = (newThreatCounts[alert.threat_class] || 0) + 1;

      return {
        alerts: newAlerts,
        severityCounts: newSeverityCounts,
        threatCounts: newThreatCounts,
      };
    });
  },
}));
