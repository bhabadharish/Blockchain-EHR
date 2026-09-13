"""
Transparent Severity Scoring Engine.
Maps multi-signal telemetry (attack type, confidence, integrity failure, unauthorized access)
into explainable discrete security levels: LOW, MEDIUM, HIGH, CRITICAL.
"""

from typing import Dict, Any, List, Tuple


class SeverityEngine:
    """
    Explainable Rule-Based Healthcare Security Severity Classifier.
    """

    LEVELS = ["SECURE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    @classmethod
    def evaluate(
        cls,
        attack_type: str,
        confidence_pct: float,
        risk_score: float,
        integrity_failed: bool = False,
        unauthorized_access: bool = False,
        repeated_attempts: int = 1,
        sensitive_fields: int = 0
    ) -> Dict[str, Any]:
        """
        Evaluates severity level with an explainable rule rationale.
        """
        matched_rules: List[str] = []

        # Rule 1: Direct Ciphertext / Blockchain Tampering
        if integrity_failed and unauthorized_access:
            level = "CRITICAL"
            matched_rules.append("RULE_CRIT_01: Blockchain hash mismatch accompanied by unauthorized access attempt.")
        elif integrity_failed:
            level = "CRITICAL"
            matched_rules.append("RULE_CRIT_02: Payload integrity failure detected against on-chain anchor.")
        # Rule 2: High Impact Attacks (Ransomware, Backdoor)
        elif attack_type in ["Ransomware", "Backdoor"] and confidence_pct >= 85.0:
            level = "CRITICAL"
            matched_rules.append(f"RULE_CRIT_03: High-confidence active {attack_type} intrusion targeting storage/host.")
        # Rule 3: Session Interception (MITM) or Privileged Breach
        elif attack_type == "MITM" and confidence_pct >= 80.0:
            level = "HIGH"
            matched_rules.append("RULE_HIGH_01: Man-In-The-Middle packet interception detected in EHR transmission channel.")
        elif attack_type in ["SQL_injection", "Uploading"] and confidence_pct >= 80.0:
            level = "HIGH"
            matched_rules.append(f"RULE_HIGH_02: Web/API layer compromise attempt ({attack_type}) detected.")
        elif "DDoS" in attack_type and confidence_pct >= 85.0:
            level = "HIGH"
            matched_rules.append(f"RULE_HIGH_03: High-volume denial of service ({attack_type}) impacting EHR gateway availability.")
        elif unauthorized_access and repeated_attempts >= 3:
            level = "HIGH"
            matched_rules.append("RULE_HIGH_04: Persistent brute-force or repeated unauthorized access attempts.")
        # Rule 4: Medium Impact & Scanners
        elif attack_type in ["Password", "Port_Scanning", "Vulnerability_scanner", "XSS"]:
            level = "MEDIUM"
            matched_rules.append(f"RULE_MED_01: Reconnaissance or authentication probing ({attack_type}) detected.")
        elif unauthorized_access:
            level = "MEDIUM"
            matched_rules.append("RULE_MED_02: Single unauthorized access rejection at RBAC smart-contract gateway.")
        # Rule 5: Low Impact
        elif attack_type in ["Fingerprinting"]:
            level = "LOW"
            matched_rules.append("RULE_LOW_01: Passive fingerprinting or benign network reconnaissance detected.")
        elif attack_type != "Normal" and confidence_pct < 60.0:
            level = "LOW"
            matched_rules.append("RULE_LOW_02: Sub-threshold anomaly detected; classified as low-confidence alert.")
        elif attack_type == "Normal" and not integrity_failed and not unauthorized_access:
            level = "SECURE"
            matched_rules.append("RULE_SEC_01: Transmission verified; normal network telemetry and intact cryptographic hash.")
        else:
            # Fallback based on numerical risk score
            if risk_score >= 80.0:
                level = "CRITICAL"
                matched_rules.append(f"RULE_FALLBACK: Risk score {risk_score} exceeds critical threshold (80.0).")
            elif risk_score >= 60.0:
                level = "HIGH"
                matched_rules.append(f"RULE_FALLBACK: Risk score {risk_score} exceeds high threshold (60.0).")
            elif risk_score >= 30.0:
                level = "MEDIUM"
                matched_rules.append(f"RULE_FALLBACK: Risk score {risk_score} exceeds medium threshold (30.0).")
            else:
                level = "LOW"
                matched_rules.append(f"RULE_FALLBACK: Baseline risk score {risk_score}.")

        # Visual color badge
        color_map = {
            "SECURE": "#10B981",    # Green
            "LOW": "#3B82F6",       # Blue
            "MEDIUM": "#F59E0B",    # Amber/Yellow
            "HIGH": "#F97316",      # Orange
            "CRITICAL": "#EF4444"   # Red
        }

        return {
            "severity": level,
            "color": color_map.get(level, "#6B7280"),
            "primary_rationale": matched_rules[0] if matched_rules else "Standard heuristic evaluation.",
            "all_rules": matched_rules,
            "requires_immediate_isolation": level in ["CRITICAL", "HIGH"]
        }
