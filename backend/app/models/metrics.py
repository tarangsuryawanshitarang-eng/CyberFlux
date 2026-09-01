"""
CyberFlux — System Metrics Models

Performance metrics are measured, not invented. Detection latency is computed
from event_received_time → detection_completed_time.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class SystemMetrics(BaseModel):
    """Point-in-time system performance snapshot."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Throughput
    events_per_sec: float = 0.0
    flows_per_sec: float = 0.0
    active_flows: int = 0

    # Latency (measured, in ms)
    detection_latency_ms: float = 0.0
    processing_latency_ms: float = 0.0
    ws_latency_ms: float = 0.0

    # Health
    dropped_events: int = 0
    active_connections: int = 0
    memory_usage_mb: float = 0.0
    system_health: str = "HEALTHY"  # HEALTHY / DEGRADED / UNHEALTHY

    # Traffic summary
    total_packets: int = 0
    total_bytes: int = 0
    current_traffic_rate_mbps: float = 0.0
