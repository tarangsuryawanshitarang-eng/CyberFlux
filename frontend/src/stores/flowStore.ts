/**
 * CyberFlux — Flow Store (Zustand)
 * 
 * Bounded flow array with filtering. Uses controlled eviction.
 */

import { create } from 'zustand';
import type { FlowEvent, ThreatStatus, Protocol } from '../types';
import { CONFIG } from '../utils/config';

interface FlowFilters {
  protocol: Protocol | '';
  threatStatus: ThreatStatus | '';
  srcIp: string;
  dstIp: string;
}

interface FlowState {
  flows: FlowEvent[];
  selectedFlowId: string | null;
  filters: FlowFilters;
  addFlow: (flow: FlowEvent) => void;
  setSelectedFlow: (id: string | null) => void;
  setFilter: <K extends keyof FlowFilters>(key: K, value: FlowFilters[K]) => void;
  clearFilters: () => void;
  getFilteredFlows: () => FlowEvent[];
}

const defaultFilters: FlowFilters = {
  protocol: '',
  threatStatus: '',
  srcIp: '',
  dstIp: '',
};

export const useFlowStore = create<FlowState>((set, get) => ({
  flows: [],
  selectedFlowId: null,
  filters: { ...defaultFilters },

  addFlow: (flow: FlowEvent) => {
    set((state) => {
      const newFlows = [flow, ...state.flows];
      // Bounded eviction
      if (newFlows.length > CONFIG.MAX_CLIENT_FLOWS) {
        newFlows.length = CONFIG.MAX_CLIENT_FLOWS;
      }
      return { flows: newFlows };
    });
  },

  setSelectedFlow: (id) => set({ selectedFlowId: id }),

  setFilter: (key, value) =>
    set((state) => ({
      filters: { ...state.filters, [key]: value },
    })),

  clearFilters: () => set({ filters: { ...defaultFilters } }),

  getFilteredFlows: () => {
    const { flows, filters } = get();
    let result = flows;

    if (filters.protocol) {
      result = result.filter((f) => f.protocol === filters.protocol);
    }
    if (filters.threatStatus) {
      result = result.filter((f) => f.threat_status === filters.threatStatus);
    }
    if (filters.srcIp) {
      result = result.filter((f) => f.src_ip.includes(filters.srcIp));
    }
    if (filters.dstIp) {
      result = result.filter((f) => f.dst_ip.includes(filters.dstIp));
    }

    return result;
  },
}));
