"""
CyberFlux — Risk Scorer

Maps detection results to severity levels based on threat class + confidence.
Severity derivation is consistent and documented.
"""

from __future__ import annotations

from app.detection.base import DetectionResult
from app.models.flow import Severity, ThreatClass, ThreatStatus


# Threat classes with inherently higher base severity
_HIGH_SEVERITY_THREATS = {
    ThreatClass.SYN_FLOOD,
    ThreatClass.UDP_REFLECTION,
    ThreatClass.DATA_EXFILTRATION,
}

_MEDIUM_SEVERITY_THREATS = {
    ThreatClass.BOTNET_C2,
    ThreatClass.DNS_TUNNELING,
    ThreatClass.MALWARE_TLS,
}

_LOW_SEVERITY_THREATS = {
    ThreatClass.DGA_DOMAIN,
    ThreatClass.RECON_SCAN,
}


def score_severity(result: DetectionResult) -> Severity:
    """Derive severity from threat class and confidence.
    
    Higher-impact threats start at a higher base severity.
    Confidence shifts the final severity up or down.
    """
    if result.threat_class == ThreatClass.BENIGN:
        return Severity.INFO

    confidence = result.confidence

    if result.threat_class in _HIGH_SEVERITY_THREATS:
        if confidence >= 0.85:
            return Severity.CRITICAL
        elif confidence >= 0.65:
            return Severity.HIGH
        elif confidence >= 0.45:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    elif result.threat_class in _MEDIUM_SEVERITY_THREATS:
        if confidence >= 0.90:
            return Severity.CRITICAL
        elif confidence >= 0.75:
            return Severity.HIGH
        elif confidence >= 0.50:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    else:  # LOW_SEVERITY_THREATS
        if confidence >= 0.90:
            return Severity.HIGH
        elif confidence >= 0.70:
            return Severity.MEDIUM
        elif confidence >= 0.40:
            return Severity.LOW
        else:
            return Severity.INFO


def score_threat_status(result: DetectionResult) -> ThreatStatus:
    """Determine threat status from detection result."""
    if result.threat_class == ThreatClass.BENIGN:
        return ThreatStatus.BENIGN

    if result.confidence >= 0.70:
        return ThreatStatus.MALICIOUS
    elif result.confidence >= 0.40:
        return ThreatStatus.SUSPICIOUS
    else:
        return ThreatStatus.BENIGN
