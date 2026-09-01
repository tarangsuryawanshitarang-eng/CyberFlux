/**
 * CyberFlux — Metrics Store (Zustand)
 */

import { create } from 'zustand';
import type { SystemMetrics } from '../types';
import { CONFIG } from '../utils/config';

interface MetricsState {
  current: SystemMetrics | null;
  history: SystemMetrics[];
  updateMetrics: (metrics: SystemMetrics) => void;
}

export const useMetricsStore = create<MetricsState>((set) => ({
  current: null,
  history: [],

  updateMetrics: (metrics: SystemMetrics) => {
    set((state) => {
      const newHistory = [...state.history, metrics];
      if (newHistory.length > CONFIG.MAX_METRIC_POINTS) {
        newHistory.splice(0, newHistory.length - CONFIG.MAX_METRIC_POINTS);
      }
      return { current: metrics, history: newHistory };
    });
  },
}));
