"""
CyberFlux — Evidence Builder

Builds human-readable evidence strings and top contributing features.
All evidence reflects actual detector inputs — nothing is fabricated.
"""

from __future__ import annotations

from app.detection.base import DetectionResult


def format_evidence_summary(result: DetectionResult) -> str:
    """Format a one-line summary of the detection evidence."""
    if not result.evidence:
        return "No anomalous features detected"
    return " | ".join(result.evidence[:3])


def get_top_features_sorted(result: DetectionResult, top_n: int = 5) -> list[tuple[str, float]]:
    """Return top contributing features sorted by importance."""
    items = sorted(
        result.top_contributing_features.items(),
        key=lambda x: x[1],
        reverse=True,
    )
    return items[:top_n]
