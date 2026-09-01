/**
 * CyberFlux — Simulation Store (Zustand)
 */

import { create } from 'zustand';
import type { DemoPhaseInfo, SimulationState } from '../types';

interface SimulationStoreState {
  state: SimulationState;
  currentScenario: string;
  currentPhase: DemoPhaseInfo | null;
  eventsGenerated: number;
  elapsedSeconds: number;
  eventRate: number;
  setState: (state: SimulationState) => void;
  setPhase: (phase: DemoPhaseInfo | null) => void;
  update: (data: Partial<SimulationStoreState>) => void;
}

export const useSimulationStore = create<SimulationStoreState>((set) => ({
  state: 'IDLE',
  currentScenario: 'BENIGN',
  currentPhase: null,
  eventsGenerated: 0,
  elapsedSeconds: 0,
  eventRate: 0,

  setState: (state) => set({ state }),
  setPhase: (phase) => set({ currentPhase: phase }),
  update: (data) => set(data),
}));
