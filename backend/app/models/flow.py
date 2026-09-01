"""
CyberFlux — Flow / Event Models

Canonical flow schema from spec section 9. Every field is typed and documented.
Payload content is never stored or exposed.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, ConfigDict


# ─── Enums ────────────────────────────────────────────────────────────

class Protocol(str, enum.Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    DNS = "DNS"
    TLS = "TLS"
    QUIC = "QUIC"
    HTTP = "HTTP"
    OTHER = "OTHER"


class ThreatClass(str, enum.Enum):
    BENIGN = "BENIGN"
    SYN_FLOOD = "SYN_FLOOD"
    UDP_REFLECTION = "UDP_REFLECTION"
    BOTNET_C2 = "BOTNET_C2"
    DGA_DOMAIN = "DGA_DOMAIN"
    DNS_TUNNELING = "DNS_TUNNELING"
    MALWARE_TLS = "MALWARE_TLS"
    RECON_SCAN = "RECON_SCAN"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"


class ThreatStatus(str, enum.Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class Severity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ─── Flow Event ───────────────────────────────────────────────────────

class FlowEvent(BaseModel):
    """Canonical flow record. Metadata and behavioral features only — no payload."""

    # Identity
    flow_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    src_port: int = 0
    dst_port: int = 0
    protocol: Protocol = Protocol.TCP

    # Volume
    duration: float = 0.0
    packets: int = 0
    bytes_total: int = 0  # renamed from 'bytes' to avoid builtin shadow

    # Rates
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0

    # Directional
    inbound_bytes: int = 0
    outbound_bytes: int = 0
    outbound_inbound_ratio: float = 0.0

    # Behavioral — Network
    source_entropy: float = 0.0
    destination_fanout: int = 0
    port_fanout: int = 0

    # Behavioral — Timing
    mean_interarrival: float = 0.0
    interarrival_std: float = 0.0
    periodicity_score: float = 0.0

    # Behavioral — DNS
    dns_entropy: float = 0.0
    dns_query_length: int = 0
    dns_query_frequency: float = 0.0

    # Behavioral — TLS / QUIC metadata
    tls_version: str = ""
    tls_fingerprint: str = ""
    ja3: str = ""
    ja3s: str = ""
    ja4: str = ""

    # Behavioral — Packet statistics
    packet_size_mean: float = 0.0
    packet_size_std: float = 0.0

    # Detection results (populated after detection)
    threat_class: ThreatClass = ThreatClass.BENIGN
    threat_status: ThreatStatus = ThreatStatus.BENIGN
    confidence: float = 0.0
    severity: Severity = Severity.INFO
    anomaly_score: float = 0.0

    # Explainability
    evidence: list[str] = Field(default_factory=list)
    top_contributing_features: dict[str, float] = Field(default_factory=dict)

    # Pipeline metadata
    detection_latency_ms: float = 0.0

    model_config = ConfigDict(use_enum_values=True)


class FlowSummary(BaseModel):
    """Lightweight projection for table views."""
    flow_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: int
    bytes_total: int
    duration: float
    threat_class: str
    threat_status: str
    confidence: float
    severity: str
