"""
CyberFlux — Abstract Detector Interface

Clean abstraction allowing future replacement with ML models
(Random Forest, XGBoost, Isolation Forest, etc.) without changing
the pipeline or frontend contracts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from app.models.flow import ThreatClass, Severity


@dataclass
class DetectionResult:
    """Output of a detector — consumed by risk scorer and alert generator."""
    threat_class: ThreatClass = ThreatClass.BENIGN
    confidence: float = 0.0  # 0.0 – 1.0
    anomaly_score: float = 0.0  # 0.0 – 1.0
    evidence: list[str] = field(default_factory=list)
    top_contributing_features: dict[str, float] = field(default_factory=dict)


class Detector(ABC):
    """Abstract detector interface.
    
    Implementations:
      - RuleBasedDetector: deterministic / statistical baseline
      - MLDetector (future): trained model inference
      - HybridDetector (future): ensemble of rule + ML
    """

    @abstractmethod
    def detect(self, features: dict[str, float]) -> DetectionResult:
        """Analyze a feature vector and return a detection result."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable detector name."""
        ...

    @property
    def detector_type(self) -> str:
        """Detector type label for the UI."""
        return "RULE_BASED"
