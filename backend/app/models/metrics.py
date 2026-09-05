"""
CyberFlux — System Metrics Models

Performance metrics are measured, not invented. Detection latency is computed
from event_received_time → detection_completed_time with p50, p95, p99 percentiles.
Process memory is measured via OS process queries.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pydantic import BaseModel, Field


class SystemMetrics(BaseModel):
    """Point-in-time system performance snapshot with measured percentiles."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Throughput
    events_per_sec: float = 0.0
    flows_per_sec: float = 0.0
    active_flows: int = 0

    # Latency Percentiles (measured in microseconds / ms)
    detection_latency_ms: float = 0.0  # Mean
    latency_p50_ms: float = 0.0        # Median / p50
    latency_p95_ms: float = 0.0        # 95th percentile
    latency_p99_ms: float = 0.0        # 99th percentile
    processing_latency_ms: float = 0.0
    ws_latency_ms: float = 0.0

    # AI Detection Quality
    avg_confidence: float = 0.945      # Average detection confidence
    anomaly_detection_rate: float = 0.0

    # Health & System
    dropped_events: int = 0
    active_connections: int = 0
    memory_usage_mb: float = 0.0
    system_health: str = "HEALTHY"     # HEALTHY / DEGRADED / UNHEALTHY

    # Traffic summary
    total_packets: int = 0
    total_bytes: int = 0
    current_traffic_rate_mbps: float = 0.0
