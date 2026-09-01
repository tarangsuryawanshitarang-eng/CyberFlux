"""
CyberFlux — Alert Models
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field


class Alert(BaseModel):
    """A detection alert generated when a flow is classified as suspicious/malicious."""

    alert_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:10])
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Source flow
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    # Detection
    threat_class: str
    confidence: float
    severity: str
    anomaly_score: float

    # Explainability
    evidence: list[str] = Field(default_factory=list)
    top_contributing_features: dict[str, float] = Field(default_factory=dict)

    # Pipeline metadata
    detection_latency_ms: float = 0.0


class AlertSummary(BaseModel):
    """Aggregated alert statistics."""
    total_alerts: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    alerts_last_5min: int = 0
    threat_class_counts: dict[str, int] = Field(default_factory=dict)
