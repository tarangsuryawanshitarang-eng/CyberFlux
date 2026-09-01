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
    length = rng.randint(8, 16)
    chars = string.ascii_lowercase + string.digits
    name = "".join(rng.choice(chars) for _ in range(length))
    return f"{name}.example"


def _generate_dns_tunnel_query(rng: random.Random) -> str:
    """Safe synthetic DNS tunnel query — long, high-entropy subdomain."""
    length = rng.randint(40, 80)
    chars = string.ascii_lowercase + string.digits
    encoded = "".join(rng.choice(chars) for _ in range(length))
    # Chunk into dot-separated labels
    labels = [encoded[i:i+12] for i in range(0, len(encoded), 12)]
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
        periodicity_score=round(rng.uniform(0.0, 0.3), 3),
        packet_size_mean=round(rng.uniform(200, 1200), 1),
        packet_size_std=round(rng.uniform(50, 400), 1),
        tls_version="TLS 1.3" if protocol == Protocol.TLS else "",
        ja3=f"{rng.randint(700,799)},{rng.randint(0,99)}" if protocol == Protocol.TLS else "",
    )


def generate_syn_flood(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """SYN flood — high packet rate, low duration, high source entropy."""
    packets = int(rng.randint(5000, 50000) * intensity)
    duration = rng.uniform(0.1, 2.0)
    bytes_total = packets * 60  # SYN packets are small

    return FlowEvent(
        src_ip=f"{rng.randint(1,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        dst_ip=_rand_internal_ip(rng),
        src_port=_rand_port(rng),
        dst_port=rng.choice([80, 443, 8080]),
        protocol=Protocol.TCP,
        duration=round(duration, 3),
        packets=packets,
        bytes_total=bytes_total,
        packets_per_second=round(packets / max(duration, 0.01), 1),
        bytes_per_second=round(bytes_total / max(duration, 0.01), 1),
        inbound_bytes=bytes_total,
        outbound_bytes=int(bytes_total * 0.03),
        outbound_inbound_ratio=round(0.03, 2),
        source_entropy=round(rng.uniform(5.5, 7.5), 2),
        destination_fanout=1,
        port_fanout=1,
        mean_interarrival=round(rng.uniform(0.0001, 0.001), 6),
        interarrival_std=round(rng.uniform(0.00001, 0.0005), 6),
        periodicity_score=round(rng.uniform(0.0, 0.15), 3),
        packet_size_mean=60.0,
        packet_size_std=round(rng.uniform(0, 5), 1),
    )


def generate_udp_reflection(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """UDP reflection/amplification — huge inbound bytes, small outbound."""
    packets = int(rng.randint(2000, 30000) * intensity)
    duration = rng.uniform(0.5, 5.0)
    inbound = packets * rng.randint(1000, 4000)
    outbound = packets * rng.randint(40, 80)

    return FlowEvent(
        src_ip=_rand_external_ip(rng),
        dst_ip=_rand_internal_ip(rng),
        src_port=rng.choice([53, 123, 161, 1900, 11211]),
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
        source_entropy=round(rng.uniform(4.0, 6.5), 2),
        destination_fanout=1,
        port_fanout=1,
        packet_size_mean=round(rng.uniform(1200, 4000), 1),
        packet_size_std=round(rng.uniform(100, 500), 1),
    )


def generate_botnet_c2(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """C2 beaconing — periodic, small payloads, few destinations."""
    # C2 servers are a small set
    c2_ip = rng.choice(["198.51.100.10", "198.51.100.11", "203.0.113.50"])
    interval = rng.gauss(60.0, 2.0)  # Very regular
    packets = rng.randint(3, 15)
    bytes_total = packets * rng.randint(100, 400)

    return FlowEvent(
        src_ip=_rand_internal_ip(rng),
        dst_ip=c2_ip,
        src_port=_rand_port(rng),
        dst_port=rng.choice([443, 8443, 4444, 8080]),
        protocol=Protocol.TLS,
        duration=round(rng.uniform(0.5, 3.0), 3),
        packets=packets,
        bytes_total=bytes_total,
        packets_per_second=round(packets / max(rng.uniform(0.5, 3.0), 0.01), 1),
        bytes_per_second=round(bytes_total / max(rng.uniform(0.5, 3.0), 0.01), 1),
        inbound_bytes=int(bytes_total * 0.4),
        outbound_bytes=int(bytes_total * 0.6),
        outbound_inbound_ratio=round(0.6 / 0.4, 2),
        source_entropy=round(rng.uniform(1.0, 2.5), 2),
        destination_fanout=1,
        port_fanout=1,
        mean_interarrival=round(interval, 3),
        interarrival_std=round(rng.uniform(0.5, 3.0), 3),
        periodicity_score=round(rng.uniform(0.75, 0.98), 3),
        packet_size_mean=round(rng.uniform(150, 350), 1),
        packet_size_std=round(rng.uniform(10, 50), 1),
        tls_version="TLS 1.2",
        ja3="771,49195-49199,23-24,0",
        tls_fingerprint="c2_beacon_synthetic",
    )


def generate_dga_domain(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """DGA domain activity — high-entropy domain names, frequent DNS queries."""
    domain = _generate_dga_domain(rng)
    entropy = _char_entropy(domain.split(".")[0])
    digit_ratio = sum(c.isdigit() for c in domain) / max(len(domain), 1)

    return FlowEvent(
        src_ip=_rand_internal_ip(rng),
        dst_ip=_rand_external_ip(rng),
        src_port=_rand_port(rng),
        dst_port=53,
        protocol=Protocol.DNS,
        duration=round(rng.uniform(0.01, 0.5), 3),
        packets=rng.randint(2, 6),
        bytes_total=rng.randint(80, 300),
        dns_entropy=round(entropy, 3),
        dns_query_length=len(domain),
        dns_query_frequency=round(rng.uniform(5.0, 30.0) * intensity, 1),
        source_entropy=round(rng.uniform(1.0, 2.0), 2),
        destination_fanout=rng.randint(1, 3),
        packet_size_mean=round(rng.uniform(80, 200), 1),
        packet_size_std=round(rng.uniform(5, 30), 1),
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
        duration=round(rng.uniform(0.01, 0.3), 3),
        packets=rng.randint(2, 8),
        bytes_total=rng.randint(200, 800),
        dns_entropy=round(entropy, 3),
        dns_query_length=len(query),
        dns_query_frequency=round(rng.uniform(20.0, 100.0) * intensity, 1),
        source_entropy=round(rng.uniform(1.0, 2.0), 2),
        destination_fanout=1,
        packet_size_mean=round(rng.uniform(200, 600), 1),
        packet_size_std=round(rng.uniform(30, 100), 1),
        outbound_bytes=rng.randint(300, 700),
        inbound_bytes=rng.randint(50, 150),
        outbound_inbound_ratio=round(rng.uniform(3.0, 8.0), 2),
    )


def generate_malware_tls(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """Malware over TLS/QUIC — suspicious fingerprints, abnormal timing."""
    protocol = rng.choice([Protocol.TLS, Protocol.QUIC])

    return FlowEvent(
        src_ip=_rand_internal_ip(rng),
        dst_ip=_rand_external_ip(rng),
        src_port=_rand_port(rng),
        dst_port=443,
        protocol=protocol,
        duration=round(rng.uniform(10, 300), 3),
        packets=rng.randint(50, 500),
        bytes_total=rng.randint(5000, 100000),
        packets_per_second=round(rng.uniform(1, 20), 1),
        bytes_per_second=round(rng.uniform(100, 5000), 1),
        inbound_bytes=rng.randint(1000, 20000),
        outbound_bytes=rng.randint(3000, 80000),
        outbound_inbound_ratio=round(rng.uniform(2.0, 10.0), 2),
        mean_interarrival=round(rng.uniform(1.0, 10.0), 3),
        interarrival_std=round(rng.uniform(0.5, 5.0), 3),
        periodicity_score=round(rng.uniform(0.3, 0.7), 3),
        packet_size_mean=round(rng.uniform(300, 1400), 1),
        packet_size_std=round(rng.uniform(200, 600), 1),
        tls_version="TLS 1.0" if rng.random() < 0.3 else "TLS 1.2",
        ja3="769,49162-49172,10-11,0",  # Suspicious — old cipher suites
        ja3s="769,49162,65281",
        ja4="t10d0711h2_" + "".join(rng.choices("0123456789abcdef", k=12)),
        tls_fingerprint="suspicious_synthetic",
    )


def generate_recon_scan(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """Reconnaissance / port scan — high fanout, short connections, many failures."""
    target_ip = _rand_internal_ip(rng)
    dst_port = rng.randint(1, 65535)

    return FlowEvent(
        src_ip=_rand_external_ip(rng),
        dst_ip=target_ip,
        src_port=_rand_port(rng),
        dst_port=dst_port,
        protocol=Protocol.TCP,
        duration=round(rng.uniform(0.001, 0.5), 4),
        packets=rng.randint(1, 4),
        bytes_total=rng.randint(40, 200),
        packets_per_second=round(rng.uniform(50, 500) * intensity, 1),
        bytes_per_second=round(rng.uniform(2000, 20000), 1),
        destination_fanout=rng.randint(20, 200),
        port_fanout=rng.randint(50, 1000),
        source_entropy=round(rng.uniform(1.0, 2.5), 2),
        mean_interarrival=round(rng.uniform(0.001, 0.05), 4),
        interarrival_std=round(rng.uniform(0.0005, 0.01), 4),
        packet_size_mean=60.0,
        packet_size_std=round(rng.uniform(0, 10), 1),
    )


def generate_data_exfiltration(rng: random.Random, intensity: float = 1.0) -> FlowEvent:
    """Data exfiltration — large outbound transfers, long duration."""
    outbound = int(rng.randint(500_000, 10_000_000) * intensity)
    inbound = rng.randint(1000, 10000)
    total = outbound + inbound
    duration = rng.uniform(30, 600)
    packets = int(total / rng.randint(800, 1400))

    return FlowEvent(
        src_ip=_rand_internal_ip(rng),
        dst_ip=_rand_external_ip(rng),
        src_port=_rand_port(rng),
        dst_port=rng.choice([443, 8443, 22, 8080]),
        protocol=rng.choice([Protocol.TLS, Protocol.TCP]),
        duration=round(duration, 3),
        packets=packets,
        bytes_total=total,
        packets_per_second=round(packets / max(duration, 0.01), 1),
        bytes_per_second=round(total / max(duration, 0.01), 1),
        inbound_bytes=inbound,
        outbound_bytes=outbound,
        outbound_inbound_ratio=round(outbound / max(inbound, 1), 2),
        source_entropy=round(rng.uniform(1.0, 2.0), 2),
        destination_fanout=1,
        port_fanout=1,
        mean_interarrival=round(rng.uniform(0.01, 0.5), 3),
        interarrival_std=round(rng.uniform(0.005, 0.1), 3),
        packet_size_mean=round(rng.uniform(1200, 1460), 1),
        packet_size_std=round(rng.uniform(20, 100), 1),
    )


# ─── Scenario Registry ───────────────────────────────────────────────

@dataclass
class ScenarioProfile:
    name: str
    threat_class: ThreatClass
    generator: Callable[[random.Random, float], FlowEvent]
    description: str
    expected_threats: list[str] = field(default_factory=list)


SCENARIOS: dict[str, ScenarioProfile] = {
    "BENIGN": ScenarioProfile(
        name="Normal Traffic",
        threat_class=ThreatClass.BENIGN,
        generator=generate_benign,
        description="Baseline legitimate network traffic",
    ),
    "SYN_FLOOD": ScenarioProfile(
        name="SYN Flood",
        threat_class=ThreatClass.SYN_FLOOD,
        generator=generate_syn_flood,
        description="TCP SYN flood DDoS simulation",
        expected_threats=["SYN_FLOOD"],
    ),
    "UDP_REFLECTION": ScenarioProfile(
        name="UDP Reflection",
        threat_class=ThreatClass.UDP_REFLECTION,
        generator=generate_udp_reflection,
        description="UDP amplification/reflection attack simulation",
        expected_threats=["UDP_REFLECTION"],
    ),
    "BOTNET_C2": ScenarioProfile(
        name="Botnet C2 Beaconing",
        threat_class=ThreatClass.BOTNET_C2,
        generator=generate_botnet_c2,
        description="Command & control beaconing simulation",
        expected_threats=["BOTNET_C2"],
    ),
    "DGA_DOMAIN": ScenarioProfile(
        name="DGA Domain Activity",
        threat_class=ThreatClass.DGA_DOMAIN,
        generator=generate_dga_domain,
        description="Domain Generation Algorithm activity simulation",
        expected_threats=["DGA_DOMAIN"],
    ),
    "DNS_TUNNELING": ScenarioProfile(
        name="DNS Tunneling",
        threat_class=ThreatClass.DNS_TUNNELING,
        generator=generate_dns_tunneling,
        description="DNS tunneling exfiltration simulation",
        expected_threats=["DNS_TUNNELING"],
    ),
    "MALWARE_TLS": ScenarioProfile(
        name="Malware over TLS/QUIC",
        threat_class=ThreatClass.MALWARE_TLS,
        generator=generate_malware_tls,
        description="Suspicious encrypted traffic simulation (metadata only)",
        expected_threats=["MALWARE_TLS"],
    ),
    "RECON_SCAN": ScenarioProfile(
        name="Reconnaissance / Port Scan",
        threat_class=ThreatClass.RECON_SCAN,
        generator=generate_recon_scan,
        description="Network reconnaissance / port scanning simulation",
        expected_threats=["RECON_SCAN"],
    ),
    "DATA_EXFILTRATION": ScenarioProfile(
        name="Data Exfiltration",
        threat_class=ThreatClass.DATA_EXFILTRATION,
        generator=generate_data_exfiltration,
        description="Large outbound data transfer simulation",
        expected_threats=["DATA_EXFILTRATION"],
    ),
}
