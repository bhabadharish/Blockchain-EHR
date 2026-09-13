"""
Breach Simulation Engine for Post-Encryption Cybersecurity Scenarios.
Uses recorded Edge-IIoT telemetry and cryptographic tamper models to demonstrate
realistic attack detection, severity scoring, alert generation, and blockchain incident logging.
"""

import os
import time
import uuid
import hashlib
import pandas as pd
import numpy as np
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple

from ids.preprocessing import IDSPreprocessor
from ids.inference import IDSInferenceEngine
from ids.risk import RiskScoringEngine
from ids.severity import SeverityEngine
from ids.response import ResponseRecommendationEngine


@dataclass
class SecurityIncident:
    """
    Immutable Security Incident Container representing a detected or simulated breach event.
    """
    incident_id: str
    timestamp: float
    iso_time: str
    payload_id: str
    scenario_name: str
    simulated_attack_type: str
    predicted_attack_type: str
    prediction_correct: bool
    confidence_pct: float
    probability: float
    risk_score: float
    severity: str
    severity_color: str
    integrity_status: str  # "VALID" or "BREACHED"
    original_hash: str
    current_hash: str
    hash_match: bool
    unauthorized_access: bool
    source_ip: str
    destination_ip: str
    protocol: str
    blockchain_tx_hash: Optional[str] = None
    blockchain_status: str = "NOT RECORDED"
    recommended_actions: List[str] = field(default_factory=list)
    lifecycle_status: str = "DETECTED"
    explainable_rationale: str = ""
    telemetry_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BreachSimulationEngine:
    """
    Controlled simulator for Post-Encryption EHR Breach Scenarios.
    Replays authentic Edge-IIoT telemetry safely without external network calls.
    """

    SCENARIOS = {
        "NORMAL_TRANSMISSION": {
            "title": "Clean Authorized Transmission",
            "attack_type": "Normal",
            "tamper_ciphertext": False,
            "unauthorized_access": False,
            "description": "Legitimate doctor accessing encrypted EHR payload over standard secure channel."
        },
        "MITM": {
            "title": "Man-In-The-Middle Session Interception",
            "attack_type": "MITM",
            "tamper_ciphertext": False,
            "unauthorized_access": True,
            "description": "Adversary intercepts wire transmission session attempting ARP poisoning / replay; EHR payload protected by AES-GCM."
        },
        "TAMPERED_CIPHERTEXT": {
            "title": "Ciphertext Bit-Flip / Integrity Tampering",
            "attack_type": "MITM",
            "tamper_ciphertext": True,
            "unauthorized_access": False,
            "description": "Attacker intercepts encrypted ciphertext in transit or storage and modifies payload bytes."
        },
        "UNAUTHORIZED_CREDENTIAL": {
            "title": "Unauthorized Role / Invalid Credential Access",
            "attack_type": "Password",
            "tamper_ciphertext": False,
            "unauthorized_access": True,
            "description": "Unregistered or revoked entity attempts to decrypt EHR using compromised session token."
        },
        "DDOS_FLOOD": {
            "title": "Distributed Denial of Service (DDoS) Flood",
            "attack_type": "DDoS_HTTP",
            "tamper_ciphertext": False,
            "unauthorized_access": False,
            "description": "High-volume botnet flood attempting to exhaust EHR clinical API gateway bandwidth."
        },
        "SQL_INJECTION_QUERY": {
            "title": "Clinical API SQL Injection Attack",
            "attack_type": "SQL_injection",
            "tamper_ciphertext": False,
            "unauthorized_access": True,
            "description": "Exploit payload embedded in EHR query API attempting unauthorized database exfiltration."
        },
        "RANSOMWARE_EXFILTRATION": {
            "title": "Host Ransomware & Lateral Exfiltration",
            "attack_type": "Ransomware",
            "tamper_ciphertext": False,
            "unauthorized_access": True,
            "description": "Malicious process executing on storage node attempting volume encryption; EHR saved by authenticated encryption."
        },
        "PORT_SCAN_RECONNAISSANCE": {
            "title": "Perimeter Port Scanning & Reconnaissance",
            "attack_type": "Port_Scanning",
            "tamper_ciphertext": False,
            "unauthorized_access": False,
            "description": "Attacker scanning RPC port 8545 and clinical services for open vulnerable endpoints."
        },
        "BACKDOOR": {
            "title": "Persistent Command & Control Backdoor",
            "attack_type": "Backdoor",
            "tamper_ciphertext": False,
            "unauthorized_access": True,
            "description": "Covert reverse-shell beaconing on hospital transmission subnet."
        },
        "PASSWORD": {
            "title": "Credential Stuffing & Auth Brute-Force",
            "attack_type": "Password",
            "tamper_ciphertext": False,
            "unauthorized_access": True,
            "description": "Automated brute-force authentication targeting EHRAccessControl smart contract."
        },
        "XSS": {
            "title": "Cross-Site Scripting API Injection",
            "attack_type": "XSS",
            "tamper_ciphertext": False,
            "unauthorized_access": True,
            "description": "Malicious script payload injected into clinician portal telemetry."
        },
        "UPLOADING": {
            "title": "Arbitrary Shell Upload Exploit",
            "attack_type": "Uploading",
            "tamper_ciphertext": False,
            "unauthorized_access": True,
            "description": "Attacker attempting to upload arbitrary shell script to EHR gateway."
        },
        "VULNERABILITY_SCANNER": {
            "title": "Automated Vulnerability Scanner Probe",
            "attack_type": "Vulnerability_scanner",
            "tamper_ciphertext": False,
            "unauthorized_access": False,
            "description": "Automated scanning tool probing Ganache RPC port 8545 and EHR endpoints."
        },
        "FINGERPRINTING": {
            "title": "OS & Service Fingerprinting",
            "attack_type": "Fingerprinting",
            "tamper_ciphertext": False,
            "unauthorized_access": False,
            "description": "TCP stack fingerprinting probe mapping clinical server architecture."
        }
    }

    def __init__(
        self,
        samples_path: str = "artifacts/demo/live_samples.csv",
        preprocessor: Optional[IDSPreprocessor] = None,
        inference_engine: Optional[IDSInferenceEngine] = None
    ):
        self.samples_path = samples_path
        self.preprocessor = preprocessor or IDSPreprocessor()
        self.inference_engine = inference_engine or IDSInferenceEngine()
        self.df_samples: Optional[pd.DataFrame] = None
        self._load_telemetry_samples()

    def _load_telemetry_samples(self):
        if os.path.exists(self.samples_path):
            try:
                self.df_samples = pd.read_csv(self.samples_path)
            except Exception as e:
                print(f"Error loading telemetry samples: {e}")
                self.df_samples = None

    def get_telemetry_row(self, attack_type: str) -> Dict[str, Any]:
        """
        Retrieves a genuine Edge-IIoT telemetry record corresponding to the specified attack class.
        """
        if self.df_samples is not None and not self.df_samples.empty:
            subset = self.df_samples[self.df_samples["Attack_type"] == attack_type]
            if not subset.empty:
                return subset.sample(n=1).iloc[0].to_dict()
            # If exact match not found, try substring
            subset = self.df_samples[self.df_samples["Attack_type"].str.contains(attack_type, case=False, na=False)]
            if not subset.empty:
                return subset.sample(n=1).iloc[0].to_dict()
            return self.df_samples.sample(n=1).iloc[0].to_dict()

        # Synthetic fallback record if samples file is not accessible
        return {
            "frame.time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ip.src_host": "192.168.0.170" if attack_type != "Normal" else "10.0.1.50",
            "ip.dst_host": "192.168.0.128",
            "tcp.srcport": 44320,
            "tcp.dstport": 80 if "HTTP" in attack_type else (8545 if "Scan" in attack_type else 443),
            "tcp.len": 1440.0 if "DDoS" in attack_type else 128.0,
            "Attack_type": attack_type,
            "Attack_label": 0 if attack_type == "Normal" else 1
        }

    def simulate_breach(
        self,
        scenario_key: str,
        payload_id: str,
        original_hash: str,
        ciphertext_bytes: bytes,
        sensitive_field_count: int = 5,
        accessor_role: str = "DOCTOR",
        repeated_attempts: int = 1
    ) -> SecurityIncident:
        """
        Executes a complete controlled breach simulation step:
        1. Select scenario parameters
        2. Simulate ciphertext tampering (if scenario dictates)
        3. Retrieve genuine Edge-IIoT telemetry for the attack
        4. Run preprocessor and deep IDS inference engine
        5. Compute risk score and explainable severity
        6. Generate SOC response recommendations
        7. Produce immutable SecurityIncident object
        """
        now = time.time()
        iso_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now))
        inc_id = f"INC-{time.strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}"

        if scenario_key in self.SCENARIOS:
            scen = self.SCENARIOS[scenario_key]
        else:
            match = next((v for k, v in self.SCENARIOS.items() if k.lower() == str(scenario_key).lower() or str(scenario_key).lower() in k.lower() or k.lower() in str(scenario_key).lower()), None)
            if not match:
                match = next((v for k, v in self.SCENARIOS.items() if v["attack_type"].lower() == str(scenario_key).lower()), None)
            scen = match or self.SCENARIOS["NORMAL_TRANSMISSION"]

        target_attack = scen["attack_type"]
        is_tampered = scen["tamper_ciphertext"]
        unauthorized = scen["unauthorized_access"]

        # 1. Simulate Cryptographic Tampering
        if is_tampered:
            # Modify first byte of ciphertext to simulate bit-flip / payload alteration
            tampered_bytes = bytearray(ciphertext_bytes) if ciphertext_bytes else bytearray(b"ORIGINAL_PAYLOAD")
            if len(tampered_bytes) > 0:
                tampered_bytes[0] ^= 0xFF
            current_hash = hashlib.sha256(tampered_bytes).hexdigest()
            hash_match = False
            integrity_status = "BREACHED"
        else:
            current_hash = original_hash
            hash_match = True
            integrity_status = "VALID"

        # 2. Retrieve genuine recorded network telemetry
        telemetry = self.get_telemetry_row(target_attack)
        src_ip = str(telemetry.get("ip.src_host", "192.168.0.170"))
        dst_ip = str(telemetry.get("ip.dst_host", "192.168.0.128"))
        protocol = "TCP" if float(telemetry.get("tcp.dstport", 0)) > 0 else "UDP/IP"

        # 3. Process telemetry through IDS
        feature_vector = self.preprocessor.transform_record(telemetry)
        ml_result = self.inference_engine.predict(
            feature_vector,
            known_attack_type=target_attack
        )

        pred_attack = ml_result["predicted_attack_type"]
        prob = ml_result["probability"]
        conf = ml_result["confidence_pct"]
        pred_correct = (pred_attack == target_attack)

        # 4. Compute Multi-Signal Risk Score
        risk_data = RiskScoringEngine.calculate_risk(
            attack_type=pred_attack if ml_result["is_attack"] else "Normal",
            confidence_pct=conf,
            integrity_failed=not hash_match,
            unauthorized_access=unauthorized,
            repeated_attempts=repeated_attempts,
            sensitive_field_count=sensitive_field_count,
            accessor_role=accessor_role,
            availability_impact=("DDoS" in target_attack)
        )
        risk_score = risk_data["risk_score"]

        # 5. Determine Explainable Severity
        sev_data = SeverityEngine.evaluate(
            attack_type=pred_attack if ml_result["is_attack"] else "Normal",
            confidence_pct=conf,
            risk_score=risk_score,
            integrity_failed=not hash_match,
            unauthorized_access=unauthorized,
            repeated_attempts=repeated_attempts,
            sensitive_fields=sensitive_field_count
        )
        severity = sev_data["severity"]
        sev_color = sev_data["color"]
        rationale = sev_data["primary_rationale"]

        # 6. Generate SOC Response Recommendations
        recommendations = ResponseRecommendationEngine.get_recommendations(
            attack_type=pred_attack if ml_result["is_attack"] else "Normal",
            integrity_failed=not hash_match,
            unauthorized_access=unauthorized
        )

        return SecurityIncident(
            incident_id=inc_id,
            timestamp=now,
            iso_time=iso_str,
            payload_id=payload_id,
            scenario_name=scen["title"],
            simulated_attack_type=target_attack,
            predicted_attack_type=pred_attack,
            prediction_correct=pred_correct,
            confidence_pct=conf,
            probability=prob,
            risk_score=risk_score,
            severity=severity,
            severity_color=sev_color,
            integrity_status=integrity_status,
            original_hash=original_hash,
            current_hash=current_hash,
            hash_match=hash_match,
            unauthorized_access=unauthorized,
            source_ip=src_ip,
            destination_ip=dst_ip,
            protocol=protocol,
            blockchain_tx_hash=None,
            blockchain_status="PENDING REGISTRATION",
            recommended_actions=recommendations,
            lifecycle_status="DETECTED",
            explainable_rationale=rationale,
            telemetry_summary={
                "tcp_dstport": telemetry.get("tcp.dstport", 0),
                "tcp_len": telemetry.get("tcp.len", 0),
                "http_method": telemetry.get("http.request.method", "N/A"),
                "device_src": src_ip
            }
        )
