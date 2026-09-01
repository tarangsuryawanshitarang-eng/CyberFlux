"""
CyberFlux — Detection Tests
"""

import random
import pytest

from app.detection.rule_based import RuleBasedDetector
from app.detection.risk_scorer import score_severity, score_threat_status
from app.models.flow import ThreatClass, Severity, ThreatStatus
from app.simulation.scenarios import (
    generate_benign, generate_syn_flood, generate_botnet_c2,
    generate_dga_domain, generate_dns_tunneling, generate_malware_tls,
    generate_recon_scan, generate_data_exfiltration,
)
from app.processing.feature_extractor import extract_features


rng = random.Random(42)
detector = RuleBasedDetector()


def _detect(gen):
    flow = gen(rng, 1.0)
    features = extract_features(flow)
    return detector.detect(features)


# ─── Threat Detection ────────────────────────────────────────────────

def test_benign_detection():
    result = _detect(generate_benign)
    assert result.threat_class == ThreatClass.BENIGN
    assert result.confidence > 0.5


def test_syn_flood_detection():
    result = _detect(generate_syn_flood)
    assert result.threat_class == ThreatClass.SYN_FLOOD
    assert result.confidence > 0.5
    assert len(result.evidence) > 0
    assert len(result.top_contributing_features) > 0


def test_c2_beacon_detection():
    result = _detect(generate_botnet_c2)
    assert result.threat_class == ThreatClass.BOTNET_C2
    assert result.confidence > 0.5


def test_dga_detection():
    result = _detect(generate_dga_domain)
    assert result.threat_class == ThreatClass.DGA_DOMAIN
    assert result.confidence > 0.3


def test_dns_tunnel_detection():
    result = _detect(generate_dns_tunneling)
    assert result.threat_class == ThreatClass.DNS_TUNNELING
    assert result.confidence > 0.5


def test_malware_tls_detection():
    result = _detect(generate_malware_tls)
    assert result.threat_class == ThreatClass.MALWARE_TLS
    assert result.confidence > 0.3


def test_recon_detection():
    result = _detect(generate_recon_scan)
    assert result.threat_class == ThreatClass.RECON_SCAN
    assert result.confidence > 0.4


def test_exfil_detection():
    result = _detect(generate_data_exfiltration)
    assert result.threat_class == ThreatClass.DATA_EXFILTRATION
    assert result.confidence > 0.4


# ─── Risk Scoring ────────────────────────────────────────────────────

def test_severity_benign():
    from app.detection.base import DetectionResult
    result = DetectionResult(threat_class=ThreatClass.BENIGN, confidence=0.9)
    assert score_severity(result) == Severity.INFO


def test_severity_critical():
    from app.detection.base import DetectionResult
    result = DetectionResult(threat_class=ThreatClass.SYN_FLOOD, confidence=0.95)
    assert score_severity(result) == Severity.CRITICAL


def test_threat_status_malicious():
    from app.detection.base import DetectionResult
    result = DetectionResult(threat_class=ThreatClass.SYN_FLOOD, confidence=0.85)
    assert score_threat_status(result) == ThreatStatus.MALICIOUS


def test_threat_status_benign():
    from app.detection.base import DetectionResult
    result = DetectionResult(threat_class=ThreatClass.BENIGN, confidence=0.95)
    assert score_threat_status(result) == ThreatStatus.BENIGN


# ─── Evidence ────────────────────────────────────────────────────────

def test_evidence_not_empty():
    result = _detect(generate_syn_flood)
    assert len(result.evidence) > 0
    assert all(isinstance(e, str) for e in result.evidence)


def test_top_features_not_empty():
    result = _detect(generate_syn_flood)
    assert len(result.top_contributing_features) > 0
    assert all(0 <= v <= 1.0 for v in result.top_contributing_features.values())
