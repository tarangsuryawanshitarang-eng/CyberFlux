"""
CyberFlux — Feature Extractor

Extracts behavioral features from flow events for each threat category.
Features are computed from the flow metadata — never from payload content.
"""

from __future__ import annotations

import math

from app.models.flow import FlowEvent


def extract_features(flow: FlowEvent) -> dict[str, float]:
    """Extract a feature vector from a flow event.
    
    Returns a dict of feature_name → value. These are the inputs
    to the detection engine and are displayed in the explainability view.
    """
    features: dict[str, float] = {}

    # ─── Volumetric features ──────────────────────────────────
    features["packets_per_second"] = flow.packets_per_second
    features["bytes_per_second"] = flow.bytes_per_second
    features["packet_count"] = float(flow.packets)
    features["byte_count"] = float(flow.bytes_total)
    features["duration"] = flow.duration

    # ─── Directional features ─────────────────────────────────
    features["outbound_inbound_ratio"] = flow.outbound_inbound_ratio
    features["outbound_bytes"] = float(flow.outbound_bytes)
    features["inbound_bytes"] = float(flow.inbound_bytes)

    # ─── Network behavioral ──────────────────────────────────
    features["source_entropy"] = flow.source_entropy
    features["destination_fanout"] = float(flow.destination_fanout)
    features["port_fanout"] = float(flow.port_fanout)

    # ─── Timing behavioral ───────────────────────────────────
    features["mean_interarrival"] = flow.mean_interarrival
    features["interarrival_std"] = flow.interarrival_std
    features["periodicity_score"] = flow.periodicity_score

    # Coefficient of variation for timing
    if flow.mean_interarrival > 0:
        features["interarrival_cv"] = flow.interarrival_std / flow.mean_interarrival
    else:
        features["interarrival_cv"] = 0.0

    # ─── DNS features ─────────────────────────────────────────
    features["dns_entropy"] = flow.dns_entropy
    features["dns_query_length"] = float(flow.dns_query_length)
    features["dns_query_frequency"] = flow.dns_query_frequency

    # ─── TLS/QUIC metadata ────────────────────────────────────
    # Encode TLS version as numeric for detection
    tls_version_map = {"TLS 1.0": 1.0, "TLS 1.1": 1.1, "TLS 1.2": 1.2, "TLS 1.3": 1.3}
    features["tls_version_num"] = tls_version_map.get(flow.tls_version, 0.0)
    features["has_ja3"] = 1.0 if flow.ja3 else 0.0
    features["has_suspicious_fingerprint"] = (
        1.0 if "suspicious" in flow.tls_fingerprint.lower() else 0.0
    )

    # ─── Packet statistics ────────────────────────────────────
    features["packet_size_mean"] = flow.packet_size_mean
    features["packet_size_std"] = flow.packet_size_std

    # Packet size coefficient of variation
    if flow.packet_size_mean > 0:
        features["packet_size_cv"] = flow.packet_size_std / flow.packet_size_mean
    else:
        features["packet_size_cv"] = 0.0

    # ─── Derived indicators ──────────────────────────────────
    # SYN-like indicator: small packets at very high rate
    features["syn_indicator"] = (
        1.0 if flow.packet_size_mean < 80 and flow.packets_per_second > 1000 else 0.0
    )

    # Scan indicator: high fanout, short connections
    features["scan_indicator"] = (
        1.0 if flow.port_fanout > 20 or flow.destination_fanout > 20 else 0.0
    )

    # Exfil indicator: very high outbound ratio + large volume
    features["exfil_indicator"] = (
        1.0 if flow.outbound_inbound_ratio > 5.0 and flow.outbound_bytes > 100000 else 0.0
    )

    # Beacon indicator: high periodicity + small payload
    features["beacon_indicator"] = (
        1.0 if flow.periodicity_score > 0.6 and flow.packet_size_mean < 400 else 0.0
    )

    return features
