"""
CyberFlux — One-Click Demo Orchestrator

Runs an 8-phase demo sequence, each phase producing the corresponding
threat telemetry. Transitions are automatic and visible in real time.

Phase sequence:
  1. Normal        →  Baseline traffic
  2. Reconnaissance →  Port scanning
  3. SYN Flood     →  DDoS
  4. DNS Tunneling →  Data exfil via DNS
  5. C2 Beaconing  →  Botnet command & control
  6. TLS Malware   →  Suspicious encrypted traffic
  7. Data Exfil    →  Large outbound transfers
  8. Normal Return →  Back to baseline
"""

from __future__ import annotations

import asyncio
import logging
import time

from app import config
from app.models.simulation import DemoPhase, DemoPhaseInfo
from app.simulation.engine import SimulationEngine

logger = logging.getLogger("cyberflux.demo")

DEMO_SEQUENCE: list[tuple[DemoPhase, str, str, list[str]]] = [
    (
        DemoPhase.NORMAL_1,
        "BENIGN",
        "Baseline normal traffic — establishing behavioral baseline",
        [],
    ),
    (
        DemoPhase.RECONNAISSANCE,
        "RECON_SCAN",
        "Reconnaissance / port scanning detected — high destination fanout",
        ["RECON_SCAN"],
    ),
    (
        DemoPhase.SYN_FLOOD,
        "SYN_FLOOD",
        "SYN flood DDoS attack — extreme packet rate, high source entropy",
        ["SYN_FLOOD"],
    ),
    (
        DemoPhase.DNS_TUNNELING,
        "DNS_TUNNELING",
        "DNS tunneling detected — high-entropy long DNS queries",
        ["DNS_TUNNELING"],
    ),
    (
        DemoPhase.BOTNET_C2,
        "BOTNET_C2",
        "Botnet C2 beaconing — periodic connections to fixed destinations",
        ["BOTNET_C2"],
    ),
    (
        DemoPhase.MALWARE_TLS,
        "MALWARE_TLS",
        "Suspicious TLS/QUIC traffic — anomalous fingerprints (metadata only)",
        ["MALWARE_TLS"],
    ),
    (
        DemoPhase.DATA_EXFILTRATION,
        "DATA_EXFILTRATION",
        "Data exfiltration — large outbound transfers detected",
        ["DATA_EXFILTRATION"],
    ),
    (
        DemoPhase.NORMAL_2,
        "BENIGN",
        "Return to normal — threats subsided, monitoring continues",
        [],
    ),
]


class DemoOrchestrator:
    """Manages the one-click demo phase sequence."""

    def __init__(self, engine: SimulationEngine) -> None:
        self._engine = engine
        self._running = False
        self._phase_index = 0
        self._phase_callback: list = []
        self._task: asyncio.Task | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def current_phase_index(self) -> int:
        return self._phase_index

    @property
    def total_phases(self) -> int:
        return len(DEMO_SEQUENCE)

    def on_phase_change(self, callback) -> None:
        """Register a callback for phase transitions: callback(DemoPhaseInfo)."""
        self._phase_callback.append(callback)

    async def _notify_phase(self, info: DemoPhaseInfo) -> None:
        for cb in self._phase_callback:
            try:
                result = cb(info)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error("Phase callback error: %s", e)

    async def start(self) -> None:
        """Start the full demo sequence."""
        if self._running:
            return
        self._running = True
        self._phase_index = 0
        self._engine.set_demo_state(True)
        logger.info("Demo started — %d phases, %.0fs each", len(DEMO_SEQUENCE), config.DEMO_PHASE_DURATION)

        self._task = asyncio.create_task(self._run_phases())

    async def _run_phases(self) -> None:
        """Execute all phases sequentially."""
        try:
            for i, (phase, scenario, description, threats) in enumerate(DEMO_SEQUENCE):
                if not self._running:
                    break

                self._phase_index = i
                self._engine.set_scenario(scenario)

                info = DemoPhaseInfo(
                    phase_name=phase.value,
                    phase_index=i,
                    total_phases=len(DEMO_SEQUENCE),
                    description=description,
                    expected_threats=threats,
                )
                await self._notify_phase(info)
                logger.info("Demo phase %d/%d: %s", i + 1, len(DEMO_SEQUENCE), phase.value)

                # Wait for phase duration, checking for stop
                phase_start = time.time()
                while time.time() - phase_start < config.DEMO_PHASE_DURATION:
                    if not self._running:
                        return
                    # Respect pause
                    await self._engine._pause_event.wait()
                    await asyncio.sleep(0.5)

            logger.info("Demo completed all phases")
        except asyncio.CancelledError:
            logger.info("Demo cancelled")
        finally:
            self._running = False
            self._engine.set_demo_state(False)

    async def stop(self) -> None:
        """Stop the demo."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._engine.set_demo_state(False)
        logger.info("Demo stopped")

    def pause(self) -> None:
        """Pause the demo."""
        self._engine.pause()

    def resume(self) -> None:
        """Resume the demo."""
        self._engine.resume()
