"""
CyberFlux — Alert Service

Bounded alert storage, filtering, and severity aggregation.
"""

from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timedelta, timezone

from app import config
from app.models.alert import Alert, AlertSummary
from app.models.flow import FlowEvent, ThreatStatus

logger = logging.getLogger("cyberflux.alerts")


class AlertService:
    """Manages alert generation and bounded storage."""

    def __init__(self, max_alerts: int = config.MAX_ALERT_HISTORY) -> None:
        self._alerts: deque[Alert] = deque(maxlen=max_alerts)
        self._total_generated: int = 0

    def maybe_create_alert(self, flow: FlowEvent) -> Alert | None:
        """Create an alert if the flow is suspicious or malicious."""
        if flow.threat_status == ThreatStatus.BENIGN:
            return None

        alert = Alert(
            flow_id=flow.flow_id,
            timestamp=flow.timestamp,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            threat_class=flow.threat_class,
            confidence=flow.confidence,
            severity=flow.severity,
            anomaly_score=flow.anomaly_score,
            evidence=flow.evidence,
            top_contributing_features=flow.top_contributing_features,
            detection_latency_ms=flow.detection_latency_ms,
        )
        self._alerts.append(alert)
        self._total_generated += 1
        return alert

    def get_alerts(self, limit: int = 50, severity: str | None = None) -> list[Alert]:
        alerts = list(reversed(self._alerts))
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return alerts[:limit]

    def get_summary(self) -> AlertSummary:
        now = datetime.now(timezone.utc)
        five_min_ago = now - timedelta(minutes=5)

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        threat_counts: dict[str, int] = {}
        recent = 0

        for alert in self._alerts:
            severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
            threat_counts[alert.threat_class] = threat_counts.get(alert.threat_class, 0) + 1
            if alert.timestamp >= five_min_ago:
                recent += 1

        return AlertSummary(
            total_alerts=self._total_generated,
            critical_count=severity_counts.get("CRITICAL", 0),
            high_count=severity_counts.get("HIGH", 0),
            medium_count=severity_counts.get("MEDIUM", 0),
            low_count=severity_counts.get("LOW", 0),
            info_count=severity_counts.get("INFO", 0),
            alerts_last_5min=recent,
            threat_class_counts=threat_counts,
        )

    def clear(self) -> None:
        self._alerts.clear()
        self._total_generated = 0
