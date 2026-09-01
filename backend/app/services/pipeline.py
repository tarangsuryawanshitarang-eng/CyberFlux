"""
CyberFlux — End-to-End Pipeline Orchestrator

Connects: Simulator → Aggregator → Feature Extractor → Detector → Risk Scorer → Alert Generator → WebSocket

Detection latency is measured per event.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable, Awaitable

from app.models.flow import FlowEvent
from app.processing.flow_aggregator import FlowAggregator
from app.processing.feature_extractor import extract_features
from app.detection.base import Detector
from app.detection.rule_based import RuleBasedDetector
from app.detection.risk_scorer import score_severity, score_threat_status
from app.services.alert_service import AlertService
from app.services.metrics_service import MetricsService
from app.simulation.engine import SimulationEngine
from app.simulation.demo import DemoOrchestrator

logger = logging.getLogger("cyberflux.pipeline")


class Pipeline:
    """Orchestrates the full detection pipeline."""

    def __init__(self) -> None:
        # Core components
        self.simulator = SimulationEngine()
        self.aggregator = FlowAggregator()
        self.detector: Detector = RuleBasedDetector()
        self.alert_service = AlertService()
        self.metrics_service = MetricsService()
        self.demo = DemoOrchestrator(self.simulator)

        # Callbacks for broadcasting events
        self._on_flow: list[Callable[[FlowEvent], Awaitable[None]]] = []
        self._on_alert: list[Callable] = []
        self._on_metrics: list[Callable] = []

        # Pipeline task
        self._task: asyncio.Task | None = None
        self._metrics_task: asyncio.Task | None = None

    def on_flow(self, callback) -> None:
        self._on_flow.append(callback)

    def on_alert(self, callback) -> None:
        self._on_alert.append(callback)

    def on_metrics(self, callback) -> None:
        self._on_metrics.append(callback)

    async def _notify_flow(self, flow: FlowEvent) -> None:
        for cb in self._on_flow:
            try:
                result = cb(flow)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error("Flow callback error: %s", e)

    async def _notify_alert(self, alert) -> None:
        for cb in self._on_alert:
            try:
                result = cb(alert)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error("Alert callback error: %s", e)

    async def _notify_metrics(self, metrics) -> None:
        for cb in self._on_metrics:
            try:
                result = cb(metrics)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error("Metrics callback error: %s", e)

    def process_flow(self, flow: FlowEvent) -> FlowEvent:
        """Run a single flow through the detection pipeline.
        
        Returns the flow with detection results populated.
        Measures actual detection latency.
        """
        start = time.perf_counter()

        # 1. Aggregate
        flow = self.aggregator.process(flow)

        # 2. Extract features
        features = extract_features(flow)

        # 3. Detect
        result = self.detector.detect(features)

        # 4. Score
        severity = score_severity(result)
        threat_status = score_threat_status(result)

        # 5. Populate flow with results
        flow.threat_class = result.threat_class
        flow.threat_status = threat_status
        flow.confidence = result.confidence
        flow.severity = severity
        flow.anomaly_score = result.anomaly_score
        flow.evidence = result.evidence
        flow.top_contributing_features = result.top_contributing_features

        # 6. Measure latency
        latency_ms = (time.perf_counter() - start) * 1000
        flow.detection_latency_ms = round(latency_ms, 3)

        # 7. Record metrics
        self.metrics_service.record_event(flow.packets, flow.bytes_total)
        self.metrics_service.record_flow()
        self.metrics_service.record_detection_latency(latency_ms)

        return flow

    async def run(self) -> None:
        """Start the pipeline — processes events from the simulator."""
        logger.info("Pipeline started")
        self._metrics_task = asyncio.create_task(self._metrics_loop())

        try:
            async for raw_flow in self.simulator.stream():
                # Process through detection pipeline
                flow = self.process_flow(raw_flow)

                # Broadcast flow update
                await self._notify_flow(flow)

                # Generate alert if needed
                alert = self.alert_service.maybe_create_alert(flow)
                if alert:
                    await self._notify_alert(alert)

        except asyncio.CancelledError:
            logger.info("Pipeline cancelled")
        except Exception as e:
            logger.error("Pipeline error: %s", e, exc_info=True)
        finally:
            if self._metrics_task:
                self._metrics_task.cancel()
            logger.info("Pipeline stopped")

    async def _metrics_loop(self) -> None:
        """Periodic metrics snapshots."""
        from app import config
        try:
            while True:
                await asyncio.sleep(config.METRICS_INTERVAL)
                snapshot = self.metrics_service.take_snapshot(
                    active_flows=self.aggregator.active_count
                )
                await self._notify_metrics(snapshot)
        except asyncio.CancelledError:
            pass

    def start_pipeline(self) -> None:
        """Start the pipeline as an asyncio task."""
        self.simulator.start()
        self._task = asyncio.create_task(self.run())

    def stop_pipeline(self) -> None:
        """Stop the pipeline."""
        self.simulator.stop()
        if self._task and not self._task.done():
            self._task.cancel()

    async def start_demo(self) -> None:
        """Start the one-click demo."""
        if self._task and not self._task.done():
            self.stop_pipeline()
            await asyncio.sleep(0.2)

        self.simulator.configure(event_rate=40)
        self.simulator.set_demo_state(True)

        # Start pipeline
        self._task = asyncio.create_task(self.run())
        # Start demo orchestrator
        await self.demo.start()

    async def stop_demo(self) -> None:
        """Stop the demo."""
        await self.demo.stop()
        self.stop_pipeline()
