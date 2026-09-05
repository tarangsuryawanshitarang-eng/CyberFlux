/**
 * CyberFlux — Alert Store (Zustand)
 * 
 * Bounded alert deque with real-time active severity and threat distributions.
 * Counts reflect actual active alerts to maintain strict data credibility.
 */

import { create } from 'zustand';
import type { Alert, Severity } from '../types';
import { CONFIG } from '../utils/config';

interface AlertState {
  alerts: Alert[];
  totalGenerated: number;
  severityCounts: Record<Severity, number>;
  threatCounts: Record<string, number>;
  addAlert: (alert: Alert) => void;
  resetCounts: () => void;
}

export const useAlertStore = create<AlertState>((set) => ({
  alerts: [],
  totalGenerated: 0,
  severityCounts: { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
  threatCounts: {},

  addAlert: (alert: Alert) => {
    set((state) => {
      const newAlerts = [alert, ...state.alerts];
      if (newAlerts.length > CONFIG.MAX_ALERT_HISTORY) {
        newAlerts.length = CONFIG.MAX_ALERT_HISTORY;
      }

      // Compute counts directly from the active bounded alert window
      const sevCounts: Record<Severity, number> = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
      const thrCounts: Record<string, number> = {};

      for (const a of newAlerts) {
        sevCounts[a.severity] = (sevCounts[a.severity] || 0) + 1;
        thrCounts[a.threat_class] = (thrCounts[a.threat_class] || 0) + 1;
      }

      return {
        alerts: newAlerts,
        totalGenerated: state.totalGenerated + 1,
        severityCounts: sevCounts,
        threatCounts: thrCounts,
      };
    });
  },

  resetCounts: () => set({
    alerts: [],
    totalGenerated: 0,
    severityCounts: { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    threatCounts: {},
  }),
}));
