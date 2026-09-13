"""
Quantitative Risk Assessment Engine.
Computes a composite security risk score (0-100) combining multi-layer signals:
- Intrusion Detection confidence and attack severity
- Cryptographic integrity status (hash mismatch / tamper evidence)
- Identity & Access privilege status
- Protected EHR payload sensitivity
"""

from typing import Dict, Any, Optional


class RiskScoringEngine:
    """
    Composite Healthcare Cybersecurity Risk Engine.
    Produces an explainable numerical risk score from 0.0 to 100.0.
    """

    # Inherent attack severity weights (0 - 40 base points)
    ATTACK_WEIGHTS = {
        "Ransomware": 40.0,
        "Backdoor": 38.0,
        "MITM": 36.0,
        "SQL_injection": 34.0,
        "DDoS_HTTP": 30.0,
        "DDoS_TCP": 30.0,
        "DDoS_UDP": 28.0,
        "DDoS_ICMP": 26.0,
        "Uploading": 28.0,
        "Password": 25.0,
        "XSS": 24.0,
        "Vulnerability_scanner": 18.0,
        "Port_Scanning": 14.0,
        "Fingerprinting": 10.0,
        "Normal": 0.0
    }

    @classmethod
    def calculate_risk(
        cls,
        attack_type: str,
        confidence_pct: float,
        integrity_failed: bool = False,
        unauthorized_access: bool = False,
        repeated_attempts: int = 1,
        sensitive_field_count: int = 0,
        accessor_role: str = "DOCTOR",
        availability_impact: bool = False
    ) -> Dict[str, Any]:
        """
        Calculates composite risk score with granular component breakdown.
        """
        # 1. Attack Telemetry Component (0 - 40 points)
        base_attack_wt = cls.ATTACK_WEIGHTS.get(attack_type, 20.0)
        attack_score = (base_attack_wt * (confidence_pct / 100.0)) if attack_type != "Normal" else 0.0

        # 2. Cryptographic Integrity Failure (0 - 25 points)
        # An on-chain hash mismatch or authentication tag failure is a direct payload compromise
        integrity_score = 25.0 if integrity_failed else 0.0

        # 3. Access Control / Authorization Anomaly (0 - 15 points)
        access_score = 0.0
        if unauthorized_access:
            access_score += 10.0
            if repeated_attempts > 1:
                access_score += min(5.0, repeated_attempts * 1.5)

        # 4. EHR Data Sensitivity Component (0 - 10 points)
        # Sensitive HIPAA identifiers or abnormal laboratory markers increase impact
        sensitivity_score = min(10.0, sensitive_field_count * 1.5)

        # 5. Availability & Privilege Multiplier (0 - 10 points)
        impact_score = 0.0
        if availability_impact or "DDoS" in attack_type:
            impact_score += 5.0
        if accessor_role in ["ADMIN", "DOCTOR"] and unauthorized_access:
            impact_score += 5.0

        raw_score = attack_score + integrity_score + access_score + sensitivity_score + impact_score
        total_risk = min(100.0, max(0.0, round(raw_score, 1)))

        return {
            "risk_score": total_risk,
            "components": {
                "attack_telemetry": round(attack_score, 1),
                "integrity_compromise": round(integrity_score, 1),
                "access_anomaly": round(access_score, 1),
                "data_sensitivity": round(sensitivity_score, 1),
                "availability_privilege": round(impact_score, 1)
            },
            "formula": "Risk = Attack(40%) + Integrity(25%) + Access(15%) + Sensitivity(10%) + Impact(10%)"
        }
