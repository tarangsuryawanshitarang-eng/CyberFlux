"""
CyberFlux — Simulation Control Models
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, Field


class DemoPhase(str, enum.Enum):
    NORMAL_1 = "NORMAL"
    RECONNAISSANCE = "RECONNAISSANCE"
    SYN_FLOOD = "SYN_FLOOD"
    DNS_TUNNELING = "DNS_TUNNELING"
    BOTNET_C2 = "BOTNET_C2"
    MALWARE_TLS = "MALWARE_TLS"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    NORMAL_2 = "NORMAL_RETURN"


class SimulationState(str, enum.Enum):
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    DEMO_RUNNING = "DEMO_RUNNING"
    DEMO_PAUSED = "DEMO_PAUSED"


class SimulationConfig(BaseModel):
    """Configuration for starting a simulation."""
    scenario: str = "BENIGN"
    intensity: float = 1.0
    event_rate: float = 50.0
    seed: int | None = None


class SimulationStatus(BaseModel):
    """Current simulation state."""
    state: SimulationState = SimulationState.IDLE
    current_scenario: str = "IDLE"
    current_phase: str | None = None
    phase_index: int = 0
    total_phases: int = 8
    events_generated: int = 0
    elapsed_seconds: float = 0.0
    event_rate: float = 0.0


class DemoPhaseInfo(BaseModel):
    """Broadcast when demo transitions between phases."""
    phase_name: str
    phase_index: int
    total_phases: int
    description: str
    expected_threats: list[str] = Field(default_factory=list)
