"""
CyberFlux — Async Traffic Simulation Engine

Generates synthetic telemetry at a configurable rate. Supports:
- scenario selection, intensity, event_rate
- start / stop / pause / resume
- deterministic seeds
- mixed scenarios (benign + threat)
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import AsyncGenerator

from app import config
from app.models.flow import FlowEvent
from app.models.simulation import SimulationState, SimulationStatus
from app.simulation.scenarios import SCENARIOS

logger = logging.getLogger("cyberflux.simulation")


class SimulationEngine:
    """Async traffic generator producing FlowEvent objects."""

    def __init__(self) -> None:
        self._state: SimulationState = SimulationState.IDLE
        self._scenario: str = "BENIGN"
        self._intensity: float = 1.0
        self._event_rate: float = config.SIMULATION_RATE
        self._seed: int | None = config.SIMULATION_SEED
        self._rng: random.Random = random.Random(self._seed)
        self._events_generated: int = 0
        self._start_time: float = 0.0
        self._pause_event: asyncio.Event = asyncio.Event()
        self._pause_event.set()  # Not paused initially
        self._stop_event: asyncio.Event = asyncio.Event()

    @property
    def state(self) -> SimulationState:
        return self._state

    @property
    def status(self) -> SimulationStatus:
        elapsed = 0.0
        if self._start_time > 0:
            elapsed = time.time() - self._start_time
        return SimulationStatus(
            state=self._state,
            current_scenario=self._scenario,
            events_generated=self._events_generated,
            elapsed_seconds=round(elapsed, 1),
            event_rate=self._event_rate,
        )

    def configure(
        self,
        scenario: str = "BENIGN",
        intensity: float = 1.0,
        event_rate: float | None = None,
        seed: int | None = None,
    ) -> None:
        self._scenario = scenario
        self._intensity = max(0.1, min(intensity, 10.0))
        if event_rate is not None:
            self._event_rate = max(1.0, min(event_rate, 1000.0))
        if seed is not None:
            self._seed = seed
            self._rng = random.Random(seed)

    def start(self) -> None:
        if self._state in (SimulationState.RUNNING, SimulationState.DEMO_RUNNING):
            return
        self._state = SimulationState.RUNNING
        self._events_generated = 0
        self._start_time = time.time()
        self._stop_event.clear()
        self._pause_event.set()
        logger.info("Simulation started: scenario=%s rate=%.1f/s", self._scenario, self._event_rate)

    def stop(self) -> None:
        self._state = SimulationState.IDLE
        self._stop_event.set()
        self._pause_event.set()
        logger.info("Simulation stopped after %d events", self._events_generated)

    def pause(self) -> None:
        if self._state == SimulationState.RUNNING:
            self._state = SimulationState.PAUSED
            self._pause_event.clear()
            logger.info("Simulation paused")
        elif self._state == SimulationState.DEMO_RUNNING:
            self._state = SimulationState.DEMO_PAUSED
            self._pause_event.clear()
            logger.info("Demo paused")

    def resume(self) -> None:
        if self._state == SimulationState.PAUSED:
            self._state = SimulationState.RUNNING
            self._pause_event.set()
            logger.info("Simulation resumed")
        elif self._state == SimulationState.DEMO_PAUSED:
            self._state = SimulationState.DEMO_RUNNING
            self._pause_event.set()
            logger.info("Demo resumed")

    def set_scenario(self, scenario: str) -> None:
        """Change the active scenario (used by demo orchestrator)."""
        self._scenario = scenario

    def set_demo_state(self, running: bool) -> None:
        """Toggle demo mode state."""
        if running:
            self._state = SimulationState.DEMO_RUNNING
            self._stop_event.clear()
            self._pause_event.set()
            self._events_generated = 0
            self._start_time = time.time()
        else:
            self._state = SimulationState.IDLE
            self._stop_event.set()
            self._pause_event.set()

    def _generate_event(self) -> FlowEvent:
        """Generate a single flow event from the current scenario.
        
        During non-demo modes, mix in ~20% benign traffic for realism.
        """
        scenario_key = self._scenario
        if scenario_key != "BENIGN" and self._rng.random() < 0.2:
            scenario_key = "BENIGN"

        profile = SCENARIOS.get(scenario_key, SCENARIOS["BENIGN"])
        flow = profile.generator(self._rng, self._intensity)
        self._events_generated += 1
        return flow

    async def stream(self) -> AsyncGenerator[FlowEvent, None]:
        """Yield FlowEvent objects at the configured rate."""
        interval = 1.0 / max(self._event_rate, 1.0)

        while not self._stop_event.is_set():
            # Respect pause
            await self._pause_event.wait()

            if self._stop_event.is_set():
                break

            yield self._generate_event()

            # Adaptive sleep for rate control
            await asyncio.sleep(interval)
