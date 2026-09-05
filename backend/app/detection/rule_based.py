"""
CyberFlux — Rule-Based Detector

Deterministic / statistical-threshold detector for the initial prototype.
Confidence values are computed from feature magnitudes, not fabricated.
"""

from __future__ import annotations

from app.detection.base import Detector, DetectionResult
from app.models.flow import ThreatClass


class RuleBasedDetector(Detector):
    """Threshold-based detector covering all 8 threat categories."""

    @property
    def name(self) -> str:
        return "CyberFlux Rule-Based Detector v1 (Prototype)"

    @property
    def detector_type(self) -> str:
        return "RULE_BASED"

    def detect(self, features: dict[str, float]) -> DetectionResult:
        """Apply rules in priority order. First match wins."""

        # ── SYN Flood ─────────────────────────────────────────
        if self._check_syn_flood(features):
            return self._build_result(features, ThreatClass.SYN_FLOOD, self._syn_flood_rules)

        # ── UDP Reflection ────────────────────────────────────
        if self._check_udp_reflection(features):
            return self._build_result(features, ThreatClass.UDP_REFLECTION, self._udp_reflection_rules)

        # ── Reconnaissance / Port Scan ────────────────────────
        if self._check_recon(features):
            return self._build_result(features, ThreatClass.RECON_SCAN, self._recon_rules)

        # ── Botnet C2 Beaconing ──────────────────────────────
        if self._check_c2_beacon(features):
            return self._build_result(features, ThreatClass.BOTNET_C2, self._c2_rules)

        # ── DNS Tunneling ─────────────────────────────────────
        if self._check_dns_tunnel(features):
            return self._build_result(features, ThreatClass.DNS_TUNNELING, self._dns_tunnel_rules)

        # ── DGA Domain ────────────────────────────────────────
        if self._check_dga(features):
            return self._build_result(features, ThreatClass.DGA_DOMAIN, self._dga_rules)

        # ── Malware TLS/QUIC ──────────────────────────────────
        if self._check_malware_tls(features):
            return self._build_result(features, ThreatClass.MALWARE_TLS, self._malware_tls_rules)

        # ── Data Exfiltration ─────────────────────────────────
        if self._check_exfiltration(features):
            return self._build_result(features, ThreatClass.DATA_EXFILTRATION, self._exfil_rules)

        # ── Benign ────────────────────────────────────────────
        return DetectionResult(
            threat_class=ThreatClass.BENIGN,
            confidence=max(0.85, 1.0 - features.get("source_entropy", 0) * 0.05),
            anomaly_score=0.0,
        )

    # ─── Detection checks ────────────────────────────────────────────

    def _check_syn_flood(self, f: dict[str, float]) -> bool:
        return (
            f.get("syn_indicator", 0) > 0.5
            or (f.get("packets_per_second", 0) > 5000 and f.get("packet_size_mean", 1500) < 80)
        ) and f.get("source_entropy", 0) > 4.0

    def _check_udp_reflection(self, f: dict[str, float]) -> bool:
        return (
            f.get("packet_size_mean", 0) > 1000
            and f.get("inbound_bytes", 0) > f.get("outbound_bytes", 0) * 10
            and f.get("packets_per_second", 0) > 500
        )

    def _check_recon(self, f: dict[str, float]) -> bool:
        return (
            f.get("scan_indicator", 0) > 0.5
            or f.get("port_fanout", 0) > 30
            or f.get("destination_fanout", 0) > 15
        )

    def _check_c2_beacon(self, f: dict[str, float]) -> bool:
        return (
            f.get("beacon_indicator", 0) > 0.5
            or (f.get("periodicity_score", 0) > 0.6 and f.get("interarrival_cv", 1.0) < 0.15)
        )

    def _check_dns_tunnel(self, f: dict[str, float]) -> bool:
        return (
            f.get("dns_query_length", 0) > 35
            and f.get("dns_entropy", 0) > 3.0
            and f.get("dns_query_frequency", 0) > 8
        )

    def _check_dga(self, f: dict[str, float]) -> bool:
        return (
            f.get("dns_entropy", 0) > 3.0
            and f.get("dns_query_length", 0) > 8
            and f.get("dns_query_frequency", 0) > 3
            and not self._check_dns_tunnel(f)  # DNS tunnel takes priority
        )

    def _check_malware_tls(self, f: dict[str, float]) -> bool:
        return (
            f.get("has_suspicious_fingerprint", 0) > 0.5
            or (
                f.get("tls_version_num", 1.3) < 1.2
                and f.get("has_ja3", 0) > 0.5
                and f.get("outbound_inbound_ratio", 0) > 2.0
            )
        )

    def _check_exfiltration(self, f: dict[str, float]) -> bool:
        return (
            f.get("exfil_indicator", 0) > 0.5
            or (
                f.get("outbound_inbound_ratio", 0) > 5.0
                and f.get("outbound_bytes", 0) > 50000
                and f.get("duration", 0) > 10
            )
        )

    # ─── Confidence & evidence builders ──────────────────────────────

    @staticmethod
    def _syn_flood_rules(f: dict[str, float]) -> tuple[float, float, list[str], dict[str, float]]:
        pps = f.get("packets_per_second", 0)
        entropy = f.get("source_entropy", 0)
        confidence = min(0.99, 0.7 + (pps / 100000) * 0.2 + (entropy / 8) * 0.1)
        anomaly = min(1.0, pps / 50000)
        evidence = [
            f"SYN rate: {pps:,.0f}/sec",
            f"Source entropy: {entropy:.1f} (high dispersion)",
            f"Packet size: {f.get('packet_size_mean', 0):.0f} bytes (SYN-sized)",
            "Destination concentration: HIGH",
        ]
        top_features = {
            "SYN rate": min(1.0, pps / 50000),
            "Source entropy": min(1.0, entropy / 8),
            "Packet size uniformity": 1.0 - min(1.0, f.get("packet_size_std", 0) / 100),
            "Destination concentration": 1.0 - min(1.0, f.get("destination_fanout", 1) / 10),
        }
        return confidence, anomaly, evidence, top_features

    @staticmethod
    def _udp_reflection_rules(f: dict[str, float]) -> tuple[float, float, list[str], dict[str, float]]:
        ratio = f.get("inbound_bytes", 0) / max(f.get("outbound_bytes", 1), 1)
        pps = f.get("packets_per_second", 0)
        confidence = min(0.98, 0.6 + min(ratio / 100, 0.25) + min(pps / 20000, 0.15))
        anomaly = min(1.0, ratio / 50)
        evidence = [
            f"Amplification ratio: {ratio:.1f}x",
            f"Inbound volume: {f.get('inbound_bytes', 0):,.0f} bytes",
            f"Packet rate: {pps:,.0f}/sec",
            f"Avg packet size: {f.get('packet_size_mean', 0):,.0f} bytes",
        ]
        top_features = {
            "Amplification ratio": min(1.0, ratio / 50),
            "Inbound volume": min(1.0, f.get("inbound_bytes", 0) / 10_000_000),
            "Packet rate": min(1.0, pps / 20000),
            "Packet size": min(1.0, f.get("packet_size_mean", 0) / 4000),
        }
        return confidence, anomaly, evidence, top_features

    @staticmethod
    def _recon_rules(f: dict[str, float]) -> tuple[float, float, list[str], dict[str, float]]:
        port_fo = f.get("port_fanout", 0)
        dest_fo = f.get("destination_fanout", 0)
        confidence = min(0.95, 0.5 + min(port_fo / 500, 0.3) + min(dest_fo / 100, 0.2))
        anomaly = min(1.0, max(port_fo, dest_fo) / 200)
        evidence = [
            f"Port fanout: {port_fo:.0f} unique ports",
            f"Host fanout: {dest_fo:.0f} unique destinations",
            f"Connection rate: {f.get('packets_per_second', 0):,.0f}/sec",
            f"Avg duration: {f.get('duration', 0):.3f}s (very short)",
        ]
        top_features = {
            "Port fanout": min(1.0, port_fo / 500),
            "Destination fanout": min(1.0, dest_fo / 100),
            "Connection rate": min(1.0, f.get("packets_per_second", 0) / 1000),
            "Short duration": max(0, 1.0 - f.get("duration", 0) / 5),
        }
        return confidence, anomaly, evidence, top_features

    @staticmethod
    def _c2_rules(f: dict[str, float]) -> tuple[float, float, list[str], dict[str, float]]:
        periodicity = f.get("periodicity_score", 0)
        cv = f.get("interarrival_cv", 1.0)
        confidence = min(0.96, 0.5 + periodicity * 0.35 + max(0, 0.15 - cv * 0.5))
        anomaly = periodicity
        evidence = [
            f"Periodicity score: {periodicity:.2f} (highly regular)",
            f"Inter-arrival CV: {cv:.3f} (low variance)",
            f"Mean interval: {f.get('mean_interarrival', 0):.1f}s",
            f"Payload size: {f.get('packet_size_mean', 0):.0f} bytes (small)",
        ]
        top_features = {
            "Periodicity": periodicity,
            "Timing regularity": max(0, 1.0 - cv),
            "Small payload": max(0, 1.0 - f.get("packet_size_mean", 0) / 1000),
            "Low destination count": max(0, 1.0 - f.get("destination_fanout", 0) / 10),
        }
        return confidence, anomaly, evidence, top_features

    @staticmethod
    def _dns_tunnel_rules(f: dict[str, float]) -> tuple[float, float, list[str], dict[str, float]]:
        ql = f.get("dns_query_length", 0)
        entropy = f.get("dns_entropy", 0)
        freq = f.get("dns_query_frequency", 0)
        confidence = min(0.97, 0.4 + min(ql / 100, 0.25) + min(entropy / 5, 0.2) + min(freq / 50, 0.15))
        anomaly = min(1.0, ql / 80)
        evidence = [
            f"Query length: {ql:.0f} chars (extremely long)",
            f"Character entropy: {entropy:.2f} (high randomness)",
            f"Query frequency: {freq:.1f}/sec",
            f"Outbound/inbound ratio: {f.get('outbound_inbound_ratio', 0):.1f}",
        ]
        top_features = {
            "Query length": min(1.0, ql / 80),
            "Character entropy": min(1.0, entropy / 5),
            "Query frequency": min(1.0, freq / 50),
            "Data directionality": min(1.0, f.get("outbound_inbound_ratio", 0) / 10),
        }
        return confidence, anomaly, evidence, top_features

    @staticmethod
    def _dga_rules(f: dict[str, float]) -> tuple[float, float, list[str], dict[str, float]]:
        entropy = f.get("dns_entropy", 0)
        ql = f.get("dns_query_length", 0)
        freq = f.get("dns_query_frequency", 0)
        confidence = min(0.92, 0.4 + min(entropy / 5, 0.3) + min(ql / 20, 0.15) + min(freq / 30, 0.1))
        anomaly = min(1.0, entropy / 4.5)
        evidence = [
            f"Domain entropy: {entropy:.2f} (algorithmically generated)",
            f"Domain length: {ql:.0f} chars",
            f"Query frequency: {freq:.1f}/sec",
            "Domain pattern: random alphanumeric (DGA signature)",
        ]
        top_features = {
            "Character entropy": min(1.0, entropy / 5),
            "Domain length": min(1.0, ql / 20),
            "Query frequency": min(1.0, freq / 30),
            "Pattern anomaly": min(1.0, entropy / 4),
        }
        return confidence, anomaly, evidence, top_features

    @staticmethod
    def _malware_tls_rules(f: dict[str, float]) -> tuple[float, float, list[str], dict[str, float]]:
        suspicious_fp = f.get("has_suspicious_fingerprint", 0)
        tls_ver = f.get("tls_version_num", 1.3)
        ratio = f.get("outbound_inbound_ratio", 0)
        periodicity = f.get("periodicity_score", 0)
        confidence = min(0.96, 0.45 + suspicious_fp * 0.25 + max(0, (1.3 - tls_ver) * 0.2) + min(ratio / 20, 0.15))
        anomaly = suspicious_fp * 0.6 + max(0, (1.2 - tls_ver)) * 0.3 + min(ratio / 10, 0.1)
        tls_label = {0: "None", 1.0: "TLS 1.0 (Deprecated)", 1.1: "TLS 1.1 (Weak)", 1.2: "TLS 1.2", 1.3: "TLS 1.3"}.get(tls_ver, f"TLS {tls_ver}")
        
        evidence = []
        if tls_ver <= 1.0:
            evidence.append(f"Protocol risk: {tls_label} with legacy cipher suite negotiation")
        if suspicious_fp > 0.5:
            evidence.append(f"JA3 fingerprint anomaly: Known C2/malware toolkit signature match")
        if ratio > 2.5:
            evidence.append(f"Asymmetric outbound data flow: {ratio:.1f}x outbound/inbound ratio")
        if periodicity > 0.35:
            evidence.append(f"Handshake timing regularity: Periodicity score {periodicity:.2f}")
        if not evidence:
            evidence = [
                f"TLS version: {tls_label} (metadata only — PAYLOAD DECRYPTION: DISABLED)",
                f"Suspicious fingerprint: {'YES' if suspicious_fp else 'NO'}",
                f"Traffic ratio: {ratio:.1f}x outbound",
            ]

        top_features = {
            "Fingerprint anomaly": suspicious_fp if suspicious_fp > 0 else 0.4,
            "TLS version risk": max(0.1, (1.3 - tls_ver) / 0.3) if tls_ver > 0 else 0.1,
            "Traffic asymmetry": min(1.0, ratio / 10),
            "Timing pattern": periodicity,
        }
        return confidence, anomaly, evidence, top_features

    @staticmethod
    def _exfil_rules(f: dict[str, float]) -> tuple[float, float, list[str], dict[str, float]]:
        outbound = f.get("outbound_bytes", 0)
        ratio = f.get("outbound_inbound_ratio", 0)
        duration = f.get("duration", 0)
        confidence = min(0.94, 0.4 + min(outbound / 5_000_000, 0.25) + min(ratio / 20, 0.2) + min(duration / 300, 0.1))
        anomaly = min(1.0, outbound / 5_000_000)
        evidence = [
            f"Outbound volume: {outbound:,.0f} bytes",
            f"Outbound/inbound ratio: {ratio:.1f}x",
            f"Duration: {duration:.1f}s (sustained transfer)",
            f"Transfer rate: {f.get('bytes_per_second', 0):,.0f} bytes/sec",
        ]
        top_features = {
            "Outbound volume": min(1.0, outbound / 5_000_000),
            "Data asymmetry": min(1.0, ratio / 20),
            "Duration": min(1.0, duration / 300),
            "Transfer rate": min(1.0, f.get("bytes_per_second", 0) / 50000),
        }
        return confidence, anomaly, evidence, top_features

    def _build_result(
        self,
        features: dict[str, float],
        threat_class: ThreatClass,
        rule_fn,
    ) -> DetectionResult:
        confidence, anomaly, evidence, top_features = rule_fn(features)
        return DetectionResult(
            threat_class=threat_class,
            confidence=round(confidence, 4),
            anomaly_score=round(anomaly, 4),
            evidence=evidence,
            top_contributing_features=top_features,
        )
