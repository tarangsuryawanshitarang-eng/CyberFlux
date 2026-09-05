"""
CyberFlux — Threat Scenario Profiles

Each scenario defines realistic statistical distributions for its threat category.
These are *synthetic telemetry profiles*, NOT attack tooling.
All domains use safe `.example` TLD per spec.
"""

from __future__ import annotations

import random
import math
import string
from dataclasses import dataclass, field
from typing import Callable

from app.models.flow import FlowEvent, Protocol, ThreatClass


# ─── Helpers ──────────────────────────────────────────────────────────

_INTERNAL_SUBNETS = ["10.0.1.", "10.0.2.", "10.0.3.", "192.168.1.", "172.16.0."]
_EXTERNAL_IPS = [
    "203.0.113.", "198.51.100.", "192.0.2.", "100.64.0.",
    "45.33.32.", "185.125.190.", "91.189.88.", "151.101.1.",
]


def _rand_internal_ip(rng: random.Random) -> str:
    return rng.choice(_INTERNAL_SUBNETS) + str(rng.randint(1, 254))


def _rand_external_ip(rng: random.Random) -> str:
    return rng.choice(_EXTERNAL_IPS) + str(rng.randint(1, 254))


def _rand_port(rng: random.Random, well_known: bool = False) -> int:
    if well_known:
        return rng.choice([80, 443, 8080, 8443, 53, 22, 25, 110, 143, 993])
    return rng.randint(1024, 65535)


def _generate_dga_domain(rng: random.Random) -> str:
    """Safe synthetic DGA domain using .example TLD."""
    length = rng.randint(8, 18)
    chars = string.ascii_lowercase + string.digits
    name = "".join(rng.choice(chars) for _ in range(length))
    return f"{name}.example"


def _generate_dns_tunnel_query(rng: random.Random) -> str:
    """Safe synthetic DNS tunnel query — long, high-entropy subdomain."""
    length = rng.randint(48, 96)
    chars = string.ascii_lowercase + string.digits
    encoded = "".join(rng.choice(chars) for _ in range(length))
    # Chunk into dot-separated labels
    labels = [encoded[i:i+16] for i in range(0, len(encoded), 16)]
    return ".".join(labels) + ".tunnel.example"


def _char_entropy(s: str) -> float:
    """Shannon entropy of character distribution."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# ─── Scenario Generator Functions ────────────────────────────────────

def generate_benign(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """Normal traffic — varied protocols, moderate volumes, low entropy."""
    protocol = rng.choice([Protocol.TCP, Protocol.UDP, Protocol.HTTP, Protocol.TLS])
    duration = rng.uniform(0.1, 30.0)
    packets = rng.randint(5, 500)
    bytes_total = packets * rng.randint(64, 1500)

    return FlowEvent(
        src_ip=_rand_internal_ip(rng),
        dst_ip=_rand_external_ip(rng),
        src_port=_rand_port(rng),
        dst_port=_rand_port(rng, well_known=True),
        protocol=protocol,
        duration=round(duration, 3),
        packets=packets,
        bytes_total=bytes_total,
        packets_per_second=round(packets / max(duration, 0.01), 1),
        bytes_per_second=round(bytes_total / max(duration, 0.01), 1),
        inbound_bytes=int(bytes_total * rng.uniform(0.3, 0.7)),
        outbound_bytes=int(bytes_total * rng.uniform(0.3, 0.7)),
        outbound_inbound_ratio=round(rng.uniform(0.5, 2.0), 2),
        source_entropy=round(rng.uniform(1.0, 3.5), 2),
        destination_fanout=rng.randint(1, 5),
        port_fanout=rng.randint(1, 3),
        mean_interarrival=round(rng.uniform(0.5, 5.0), 3),
        interarrival_std=round(rng.uniform(0.1, 2.0), 3),
        periodicity_score=round(rng.uniform(0.0, 0.25), 3),
        packet_size_mean=round(rng.uniform(200, 1200), 1),
        packet_size_std=round(rng.uniform(50, 400), 1),
        tls_version="TLS 1.3" if protocol == Protocol.TLS else "",
        ja3=f"{rng.randint(700,799)},{rng.randint(0,99)}" if protocol == Protocol.TLS else "",
    )


def generate_syn_flood(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """SYN flood — high packet rate, low duration, high source entropy."""
    variant = rng.choice(["rate_spike", "entropy_surge", "ack_depletion"])
    packets = int(rng.randint(12000, 65000) * intensity)
    duration = rng.uniform(0.05, 1.2)
    bytes_total = packets * 60  # SYN packets are small (40-60 bytes)

    entropy = rng.uniform(6.2, 7.8) if variant == "entropy_surge" else rng.uniform(5.5, 6.8)

    return FlowEvent(
        src_ip=f"{rng.randint(1,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        dst_ip=_rand_internal_ip(rng),
        src_port=_rand_port(rng),
        dst_port=rng.choice([80, 443, 8080, 53, 3389]),
        protocol=Protocol.TCP,
        duration=round(duration, 3),
        packets=packets,
        bytes_total=bytes_total,
        packets_per_second=round(packets / max(duration, 0.01), 1),
        bytes_per_second=round(bytes_total / max(duration, 0.01), 1),
        inbound_bytes=bytes_total,
        outbound_bytes=int(bytes_total * rng.uniform(0.01, 0.03)),
        outbound_inbound_ratio=round(rng.uniform(0.01, 0.03), 3),
        source_entropy=round(entropy, 2),
        destination_fanout=1,
        port_fanout=1,
        mean_interarrival=round(rng.uniform(0.00005, 0.0005), 6),
        interarrival_std=round(rng.uniform(0.00001, 0.0001), 6),
        periodicity_score=round(rng.uniform(0.0, 0.1), 3),
        packet_size_mean=60.0,
        packet_size_std=round(rng.uniform(0, 3), 1),
    )


def generate_udp_reflection(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """UDP reflection/amplification — huge inbound bytes, small outbound."""
    amplification_factor = rng.choice([25.0, 45.0, 70.0, 100.0])
    packets = int(rng.randint(4000, 35000) * intensity)
    duration = rng.uniform(0.3, 3.5)
    inbound = packets * rng.randint(1400, 4200)
    outbound = int(inbound / amplification_factor)

    return FlowEvent(
        src_ip=_rand_external_ip(rng),
        dst_ip=_rand_internal_ip(rng),
        src_port=rng.choice([53, 123, 161, 1900, 11211, 389]),
        dst_port=_rand_port(rng),
        protocol=Protocol.UDP,
        duration=round(duration, 3),
        packets=packets,
        bytes_total=inbound + outbound,
        packets_per_second=round(packets / max(duration, 0.01), 1),
        bytes_per_second=round((inbound + outbound) / max(duration, 0.01), 1),
        inbound_bytes=inbound,
        outbound_bytes=outbound,
        outbound_inbound_ratio=round(outbound / max(inbound, 1), 4),
        source_entropy=round(rng.uniform(4.2, 6.8), 2),
        destination_fanout=1,
        port_fanout=1,
        packet_size_mean=round(rng.uniform(1400, 4000), 1),
        packet_size_std=round(rng.uniform(50, 300), 1),
    )


def generate_botnet_c2(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """C2 beaconing — periodic, small payloads, few destinations."""
    c2_ip = rng.choice(["198.51.100.10", "198.51.100.11", "203.0.113.50", "100.64.0.22"])
    interval = rng.gauss(60.0, 0.8)  # Extremely regular with tiny jitter
    packets = rng.randint(4, 12)
    bytes_total = packets * rng.randint(120, 320)

    return FlowEvent(
        src_ip=_rand_internal_ip(rng),
        dst_ip=c2_ip,
        src_port=_rand_port(rng),
        dst_port=rng.choice([443, 8443, 4444, 8080]),
        protocol=Protocol.TLS,
        duration=round(rng.uniform(0.2, 1.5), 3),
        packets=packets,
        bytes_total=bytes_total,
        packets_per_second=round(packets / max(rng.uniform(0.2, 1.5), 0.01), 1),
        bytes_per_second=round(bytes_total / max(rng.uniform(0.2, 1.5), 0.01), 1),
        inbound_bytes=int(bytes_total * 0.35),
        outbound_bytes=int(bytes_total * 0.65),
        outbound_inbound_ratio=round(0.65 / 0.35, 2),
        source_entropy=round(rng.uniform(1.0, 2.0), 2),
        destination_fanout=1,
        port_fanout=1,
        mean_interarrival=round(interval, 3),
        interarrival_std=round(rng.uniform(0.2, 1.2), 3),
        periodicity_score=round(rng.uniform(0.88, 0.99), 3),
        packet_size_mean=round(rng.uniform(120, 280), 1),
        packet_size_std=round(rng.uniform(5, 25), 1),
        tls_version="TLS 1.2",
        ja3="771,49195-49199,23-24,0",
        tls_fingerprint="c2_beacon_synthetic",
    )


def generate_dga_domain(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """DGA domain activity — high-entropy domain names, frequent DNS queries."""
    domain = _generate_dga_domain(rng)
    entropy = _char_entropy(domain.split(".")[0])

    return FlowEvent(
        src_ip=_rand_internal_ip(rng),
        dst_ip=_rand_external_ip(rng),
        src_port=_rand_port(rng),
        dst_port=53,
        protocol=Protocol.DNS,
        duration=round(rng.uniform(0.01, 0.2), 3),
        packets=rng.randint(2, 6),
        bytes_total=rng.randint(90, 320),
        dns_entropy=round(entropy, 3),
        dns_query_length=len(domain),
        dns_query_frequency=round(rng.uniform(12.0, 35.0) * intensity, 1),
        source_entropy=round(rng.uniform(1.0, 2.0), 2),
        destination_fanout=rng.randint(1, 3),
        packet_size_mean=round(rng.uniform(90, 210), 1),
        packet_size_std=round(rng.uniform(5, 25), 1),
    )


def generate_dns_tunneling(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """DNS tunneling — very long queries, high entropy, frequent lookups."""
    query = _generate_dns_tunnel_query(rng)
    payload = query.replace(".tunnel.example", "").replace(".", "")
    entropy = _char_entropy(payload)

    return FlowEvent(
        src_ip=_rand_internal_ip(rng),
        dst_ip=_rand_external_ip(rng),
        src_port=_rand_port(rng),
        dst_port=53,
        protocol=Protocol.DNS,
        duration=round(rng.uniform(0.02, 0.25), 3),
        packets=rng.randint(4, 12),
        bytes_total=rng.randint(350, 1200),
        dns_entropy=round(entropy, 3),
        dns_query_length=len(query),
        dns_query_frequency=round(rng.uniform(25.0, 95.0) * intensity, 1),
        source_entropy=round(rng.uniform(1.0, 2.0), 2),
        destination_fanout=1,
        packet_size_mean=round(rng.uniform(250, 650), 1),
        packet_size_std=round(rng.uniform(20, 80), 1),
        outbound_bytes=rng.randint(450, 1000),
        inbound_bytes=rng.randint(60, 160),
        outbound_inbound_ratio=round(rng.uniform(4.0, 9.0), 2),
    )


def generate_malware_tls(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """Malware over TLS/QUIC — suspicious fingerprints, abnormal timing, diverse indicators."""
    variant = rng.choice(["ja3_anomaly", "deprecated_ssl", "timing_jitter", "sni_mismatch"])
    protocol = rng.choice([Protocol.TLS, Protocol.QUIC])

    tls_ver = "TLS 1.0" if variant == "deprecated_ssl" else rng.choice(["TLS 1.1", "TLS 1.2"])
    ja3_val = (
        "769,49162-49172,10-11,0" if variant == "ja3_anomaly"
        else "771,49195-49199,23-24,0"
    )

    return FlowEvent(
        src_ip=_rand_internal_ip(rng),
        dst_ip=_rand_external_ip(rng),
        src_port=_rand_port(rng),
        dst_port=443,
        protocol=protocol,
        duration=round(rng.uniform(5, 180), 3),
        packets=rng.randint(40, 400),
        bytes_total=rng.randint(6000, 95000),
        packets_per_second=round(rng.uniform(2, 25), 1),
        bytes_per_second=round(rng.uniform(200, 6000), 1),
        inbound_bytes=rng.randint(1200, 15000),
        outbound_bytes=rng.randint(4000, 75000),
        outbound_inbound_ratio=round(rng.uniform(2.5, 9.0), 2),
        mean_interarrival=round(rng.uniform(0.5, 8.0), 3),
        interarrival_std=round(rng.uniform(0.3, 4.0), 3),
        periodicity_score=round(rng.uniform(0.35, 0.75), 3),
        packet_size_mean=round(rng.uniform(350, 1200), 1),
        packet_size_std=round(rng.uniform(150, 500), 1),
        tls_version=tls_ver,
        ja3=ja3_val,
        ja3s="769,49162,65281",
        ja4="t10d0711h2_" + "".join(rng.choices("0123456789abcdef", k=12)),
        tls_fingerprint=f"suspicious_{variant}",
    )


def generate_recon_scan(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """Reconnaissance / port scan — high fanout, short connections, many failures."""
    variant = rng.choice(["vertical_sweep", "horizontal_scan", "syn_stealth"])
    target_ip = _rand_internal_ip(rng)
    dst_port = rng.randint(1, 65535)

    dest_fo = rng.randint(40, 300) if variant == "horizontal_scan" else rng.randint(5, 25)
    port_fo = rng.randint(80, 1500) if variant == "vertical_sweep" else rng.randint(15, 60)

    return FlowEvent(
        src_ip=_rand_external_ip(rng),
        dst_ip=target_ip,
        src_port=_rand_port(rng),
        dst_port=dst_port,
        protocol=Protocol.TCP,
        duration=round(rng.uniform(0.001, 0.3), 4),
        packets=rng.randint(1, 3),
        bytes_total=rng.randint(40, 180),
        packets_per_second=round(rng.uniform(80, 750) * intensity, 1),
        bytes_per_second=round(rng.uniform(3000, 30000), 1),
        destination_fanout=dest_fo,
        port_fanout=port_fo,
        source_entropy=round(rng.uniform(1.2, 2.8), 2),
        mean_interarrival=round(rng.uniform(0.0008, 0.02), 4),
        interarrival_std=round(rng.uniform(0.0002, 0.005), 4),
        packet_size_mean=60.0,
        packet_size_std=round(rng.uniform(0, 8), 1),
    )


def generate_data_exfiltration(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """Data exfiltration — large outbound transfers, high bandwidth."""
    outbound = int(rng.randint(2_000_000, 25_000_000) * intensity)
    inbound = rng.randint(2000, 15000)
    total = outbound + inbound
    duration = rng.uniform(20, 300)
    packets = int(total / rng.randint(1100, 1460))

    return FlowEvent(
        src_ip=_rand_internal_ip(rng),
        dst_ip=_rand_external_ip(rng),
        src_port=_rand_port(rng),
        dst_port=rng.choice([443, 8443, 22, 9001, 8080]),
        protocol=rng.choice([Protocol.TLS, Protocol.TCP]),
        duration=round(duration, 3),
        packets=packets,
        bytes_total=total,
        packets_per_second=round(packets / max(duration, 0.01), 1),
        bytes_per_second=round(total / max(duration, 0.01), 1),
        inbound_bytes=inbound,
        outbound_bytes=outbound,
        outbound_inbound_ratio=round(outbound / max(inbound, 1), 2),
        source_entropy=round(rng.uniform(1.0, 1.8), 2),
        destination_fanout=1,
        port_fanout=1,
        mean_interarrival=round(rng.uniform(0.002, 0.1), 3),
        interarrival_std=round(rng.uniform(0.001, 0.02), 3),
        packet_size_mean=round(rng.uniform(1300, 1460), 1),
        packet_size_std=round(rng.uniform(10, 60), 1),
    )


# ─── Scenario Registry ───────────────────────────────────────────────

@dataclass
class ScenarioProfile:
    name: str
    threat_class: ThreatClass
    generator: Callable[[random.Random, float], FlowEvent]
    description: str
    target_event_rate: float
    expected_threats: list[str] = field(default_factory=list)


SCENARIOS: dict[str, ScenarioProfile] = {
    "BENIGN": ScenarioProfile(
        name="Normal Traffic",
        threat_class=ThreatClass.BENIGN,
        generator=generate_benign,
        description="Baseline legitimate network traffic",
        target_event_rate=35.0,
    ),
    "RECON_SCAN": ScenarioProfile(
        name="Reconnaissance / Port Scan",
        threat_class=ThreatClass.RECON_SCAN,
        generator=generate_recon_scan,
        description="Network reconnaissance / port scanning simulation",
        target_event_rate=120.0,
        expected_threats=["RECON_SCAN"],
    ),
    "SYN_FLOOD": ScenarioProfile(
        name="SYN Flood",
        threat_class=ThreatClass.SYN_FLOOD,
        generator=generate_syn_flood,
        description="TCP SYN flood DDoS simulation",
        target_event_rate=320.0,
        expected_threats=["SYN_FLOOD"],
    ),
    "DNS_TUNNELING": ScenarioProfile(
        name="DNS Tunneling",
        threat_class=ThreatClass.DNS_TUNNELING,
        generator=generate_dns_tunneling,
        description="DNS tunneling exfiltration simulation",
        target_event_rate=65.0,
        expected_threats=["DNS_TUNNELING"],
    ),
    "BOTNET_C2": ScenarioProfile(
        name="Botnet C2 Beaconing",
        threat_class=ThreatClass.BOTNET_C2,
        generator=generate_botnet_c2,
        description="Command & control beaconing simulation",
        target_event_rate=45.0,
        expected_threats=["BOTNET_C2"],
    ),
    "DGA_DOMAIN": ScenarioProfile(
        name="DGA Domain Activity",
        threat_class=ThreatClass.DGA_DOMAIN,
        generator=generate_dga_domain,
        description="Domain Generation Algorithm activity simulation",
        target_event_rate=55.0,
        expected_threats=["DGA_DOMAIN"],
    ),
    "MALWARE_TLS": ScenarioProfile(
        name="Malware over TLS/QUIC",
        threat_class=ThreatClass.MALWARE_TLS,
        generator=generate_malware_tls,
        description="Suspicious encrypted traffic simulation (metadata only)",
        target_event_rate=50.0,
        expected_threats=["MALWARE_TLS"],
    ),
    "DATA_EXFILTRATION": ScenarioProfile(
        name="Data Exfiltration",
        threat_class=ThreatClass.DATA_EXFILTRATION,
        generator=generate_data_exfiltration,
        description="Large outbound data transfer simulation",
        target_event_rate=80.0,
        expected_threats=["DATA_EXFILTRATION"],
    ),
    "UDP_REFLECTION": ScenarioProfile(
        name="UDP Reflection",
        threat_class=ThreatClass.UDP_REFLECTION,
        generator=generate_udp_reflection,
        description="UDP amplification/reflection attack simulation",
        target_event_rate=180.0,
        expected_threats=["UDP_REFLECTION"],
    ),
}
