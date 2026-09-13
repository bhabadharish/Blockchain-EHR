"""
Intrusion Detection System (IDS) Package.
Combines offline-trained PyTorch deep models, risk scoring, severity rules, SOC responses, and breach simulation.
"""

from ids.preprocessing import IDSPreprocessor
from ids.inference import IDSInferenceEngine
from ids.risk import RiskScoringEngine
from ids.severity import SeverityEngine
from ids.response import ResponseRecommendationEngine
from ids.simulation import BreachSimulationEngine, SecurityIncident

__all__ = [
    "IDSPreprocessor",
    "IDSInferenceEngine",
    "RiskScoringEngine",
    "SeverityEngine",
    "ResponseRecommendationEngine",
    "BreachSimulationEngine",
    "SecurityIncident"
]
