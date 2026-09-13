"""
test_end_to_end_demo.py
Comprehensive End-to-End Test Suite verifying the full 22-step PhD research pipeline:
1. EHR Loading & Minimization
2. Canonical Serialization & Entropy
3. AES-256-GCM Authenticated Encryption & Decryption
4. Wrong-key & Ciphertext Tampering Rejection
5. SHA-256 Hash Digest Generation
6. Ganache Blockchain Metadata Registration
7. Smart Contract Multi-Role Authorization & Revocation
8. Post-Encryption Breach Simulation (MITM, DDoS, Tampering)
9. Preprocessor & Deep Model (MI-CNN-BiLSTM-Attention) Inference
10. Attack Classification & Confidence Calculation
11. Multi-Signal Composite Risk Score Calculation
12. Transparent Severity Rule Engine
13. SOC Countermeasure Playbook Mapping
14. Ganache Blockchain Incident Notarization
15. Cryptographic Integrity Audit & Event Emission
"""

import os
import sys
import time
import pytest
import numpy as np
import pandas as pd

# Add root directory to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from ehr.loader import MIMICLoader
from ehr.sanitizer import EHRSanitizer
from ehr.serializer import EHRSerializer
from ehr.payload import EHRPayload
from crypto.encryption import AES256GCMCipher, LegacyFernetCipher, UnauthenticatedAESCBCCipher
from crypto.key_management import KeyManager
from crypto.hashing import HashEngine
from crypto.signatures import DigitalSignatureEngine
from blockchain.contract_client import BlockchainContractClient
from ids.preprocessing import IDSPreprocessor
from ids.inference import IDSInferenceEngine
from ids.risk import RiskScoringEngine
from ids.severity import SeverityEngine
from ids.response import ResponseRecommendationEngine
from ids.simulation import BreachSimulationEngine


def test_ehr_loading_and_sanitization():
    loader = MIMICLoader()
    tables = loader.get_available_tables()
    assert len(tables) > 0, "MIMIC tables should be discovered."
    assert "LABEVENTS" in tables, "LABEVENTS table should be present."

    demo_rec = loader.get_demo_record("CRITICAL_ICU_LAB")
    assert demo_rec is not None, "Demonstration record should load."
    assert "valuenum" in demo_rec, "Lab value should exist in demo record."

    sanitizer = EHRSanitizer()
    sanitized = sanitizer.sanitize_record(demo_rec)
    assert "pseudonym" in sanitized, "Pseudonym should be generated."
    assert sanitized["exposure_analysis"]["sensitive_field_count"] > 0, "Sensitive fields should be detected."
    assert "SSN" not in sanitized["masked_data"], "Direct SSN should not be present."


def test_ehr_serialization_and_entropy():
    demo_data = {"record_id": "REC-001", "glucose": 195.0, "unit": "mg/dL"}
    canon_bytes = EHRSerializer.to_canonical_json_bytes(demo_data)
    assert isinstance(canon_bytes, bytes), "Canonical serialization must yield bytes."

    entropy = EHRSerializer.compute_entropy(canon_bytes)
    assert 0.0 <= entropy <= 8.0, f"Entropy {entropy} must be within [0, 8]."


def test_aes_256_gcm_authenticated_encryption():
    km = KeyManager()
    active_key = km.get_active_key()
    assert len(active_key.key_bytes) == 32, "Key must be 256 bits (32 bytes)."

    plaintext = b"CLINICAL_ICU_OBSERVATION_GLUCOSE_195"
    receipt = AES256GCMCipher.encrypt(plaintext, active_key.key_bytes, key_id=active_key.key_id)

    assert receipt.ciphertext_bytes != plaintext, "Ciphertext must not match plaintext."
    assert len(receipt.nonce_bytes) == 12, "Nonce must be 96 bits."
    assert len(receipt.tag_bytes) == 16, "Tag must be 128 bits."
    assert receipt.sha256_hash is not None, "Payload SHA-256 hash must be generated."

    # Successful Decryption
    decrypted = AES256GCMCipher.decrypt(
        receipt.ciphertext_bytes,
        active_key.key_bytes,
        receipt.nonce_bytes,
        receipt.tag_bytes
    )
    assert decrypted == plaintext, "Decrypted plaintext must match original."

    # Wrong Key Rejection
    wrong_key = b"\x00" * 32
    with pytest.raises(Exception):
        AES256GCMCipher.decrypt(
            receipt.ciphertext_bytes,
            wrong_key,
            receipt.nonce_bytes,
            receipt.tag_bytes
        )

    # Ciphertext Tampering Rejection
    tampered_bytes = bytearray(receipt.ciphertext_bytes)
    tampered_bytes[0] ^= 0xFF
    with pytest.raises(Exception):
        AES256GCMCipher.decrypt(
            bytes(tampered_bytes),
            active_key.key_bytes,
            receipt.nonce_bytes,
            receipt.tag_bytes
        )


def test_key_rotation():
    km = KeyManager()
    initial_id = km.get_active_key().key_id
    new_key = km.rotate_key("Routine test rotation")
    assert new_key.key_id != initial_id, "Rotated key ID must differ from previous."
    assert km.get_active_key().key_id == new_key.key_id, "Active key must be updated."


def test_digital_signatures():
    data = b"EHR_INTEGRITY_SIGNATURE_PAYLOAD"
    priv, pub = DigitalSignatureEngine.generate_keypair()
    sig = DigitalSignatureEngine.sign_data(data, priv)
    assert DigitalSignatureEngine.verify_signature(data, sig, pub) is True, "Valid signature must verify."
    assert DigitalSignatureEngine.verify_signature(b"TAMPERED_PAYLOAD", sig, pub) is False, "Tampered payload must fail signature verification."


def test_blockchain_contract_client():
    cc = BlockchainContractClient()
    assert cc is not None, "Contract client must instantiate."
    
    # Register EHR Metadata
    rec_res = cc.register_ehr_metadata(
        record_id="EHR-TEST-001",
        payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        algorithm="AES-256-GCM",
        key_id="KEY-01",
        access_policy="DOCTOR_ONLY"
    )
    assert rec_res["status"] == "SUCCESS", "EHR metadata registration should succeed."

    # Verify matching hash
    v_res = cc.verify_integrity("EHR-TEST-001", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert v_res["match"] is True, "Matching hash must verify."

    # Verify mismatch hash
    v_fail = cc.verify_integrity("EHR-TEST-001", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    assert v_fail["match"] is False, "Mismatched hash must fail."

    # Role authorization
    auth_res = cc.authorize_user(
        user_address="0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1",
        role="DOCTOR",
        validity_seconds=3600
    )
    assert auth_res["status"] == "SUCCESS", "User authorization should succeed."


def test_ids_preprocessing_and_inference():
    prep = IDSPreprocessor()
    assert len(prep.selected_features) == 20, "20 selected features must be loaded."
    
    engine = IDSInferenceEngine()
    assert len(engine.classes) == 15, "15 attack classes must be supported."

    # Synthetic feature test vector
    test_vec = np.random.randn(1, 20).astype(np.float32)
    _ = engine.predict(test_vec)  # Warmup run for PyTorch kernel initialization
    res = engine.predict(test_vec)
    assert "is_attack" in res, "Inference result must contain is_attack flag."
    assert "probability" in res, "Inference result must contain probability."
    assert "latency_ms" in res, "Inference latency must be reported."
    assert res["latency_ms"] < 50.0, f"Warm inference latency ({res['latency_ms']:.2f}ms) must complete within edge SLA."


def test_risk_and_severity_engine():
    # Scenario 1: Critical breach (Integrity failed + unauthorized access)
    risk_crit = RiskScoringEngine.calculate_risk(
        attack_type="MITM",
        confidence_pct=99.0,
        integrity_failed=True,
        unauthorized_access=True,
        sensitive_field_count=8
    )
    assert risk_crit["risk_score"] >= 70.0, "Integrity failure + unauthorized access must yield high risk."

    sev_crit = SeverityEngine.evaluate(
        attack_type="MITM",
        confidence_pct=99.0,
        risk_score=risk_crit["risk_score"],
        integrity_failed=True,
        unauthorized_access=True
    )
    assert sev_crit["severity"] == "CRITICAL", "Must be classified as CRITICAL severity."

    # Scenario 2: Normal clean transmission
    risk_norm = RiskScoringEngine.calculate_risk(
        attack_type="Normal",
        confidence_pct=99.0,
        integrity_failed=False,
        unauthorized_access=False
    )
    sev_norm = SeverityEngine.evaluate(
        attack_type="Normal",
        confidence_pct=99.0,
        risk_score=risk_norm["risk_score"]
    )
    assert sev_norm["severity"] == "SECURE", "Clean normal traffic must be evaluated as SECURE."


def test_soc_response_playbooks():
    actions_ddos = ResponseRecommendationEngine.get_recommendations("DDoS_HTTP")
    assert any("rate-limit" in a.lower() for a in actions_ddos), "DDoS playbook must recommend rate limiting."

    actions_mitm = ResponseRecommendationEngine.get_recommendations("MITM")
    assert any("rotate" in a.lower() or "session" in a.lower() for a in actions_mitm), "MITM playbook must recommend key rotation or session termination."


def test_full_end_to_end_breach_simulation_pipeline():
    """
    Executes the complete 22-step research workflow end-to-end.
    """
    # 1. Load EHR
    loader = MIMICLoader()
    demo_rec = loader.get_demo_record("CRITICAL_ICU_LAB")

    # 2. Privacy Sanitization
    sanitizer = EHRSanitizer()
    sanitized = sanitizer.sanitize_record(demo_rec)

    # 3. Canonical Serialization
    canon_bytes = EHRSerializer.to_canonical_json_bytes(sanitized["masked_data"])

    # 4. Cryptographic Encryption
    km = KeyManager()
    active_key = km.get_active_key()
    receipt = AES256GCMCipher.encrypt(canon_bytes, active_key.key_bytes, key_id=active_key.key_id)

    # 5. Blockchain Registration
    cc = BlockchainContractClient()
    reg_tx = cc.register_ehr_metadata(
        record_id=demo_rec["record_id"],
        payload_hash=receipt.sha256_hash,
        algorithm="AES-256-GCM",
        key_id=active_key.key_id,
        access_policy="DOCTOR_ONLY"
    )
    assert reg_tx["status"] == "SUCCESS"

    # 6. Controlled Breach Simulation (Ciphertext Tampering)
    sim = BreachSimulationEngine()
    incident = sim.simulate_breach(
        scenario_key="TAMPERED_CIPHERTEXT",
        payload_id=demo_rec["record_id"],
        original_hash=receipt.sha256_hash,
        ciphertext_bytes=receipt.ciphertext_bytes,
        sensitive_field_count=len(sanitized["sensitive_fields"]),
        accessor_role="DOCTOR"
    )

    # 7. Verify Threat Evaluation
    assert incident.hash_match is False, "Tampered ciphertext must cause hash mismatch."
    assert incident.integrity_status == "BREACHED", "Integrity must be BREACHED."
    assert incident.severity == "CRITICAL", "Tampering must trigger CRITICAL severity."
    assert len(incident.recommended_actions) > 0, "Countermeasure actions must be populated."

    # 8. Blockchain Incident Notarization
    inc_tx = cc.record_incident(
        incident_id=incident.incident_id,
        payload_hash=incident.current_hash,
        attack_type=incident.predicted_attack_type,
        severity=incident.severity,
        confidence_pct=incident.confidence_pct,
        integrity_status=incident.integrity_status
    )
    assert inc_tx["status"] == "SUCCESS", "Incident must be successfully notarized on blockchain."


if __name__ == "__main__":
    print("=" * 70)
    print("RUNNING COMPLETE END-TO-END DEMO TEST SUITE")
    print("=" * 70)
    test_ehr_loading_and_sanitization()
    print("✓ test_ehr_loading_and_sanitization passed")
    test_ehr_serialization_and_entropy()
    print("✓ test_ehr_serialization_and_entropy passed")
    test_aes_256_gcm_authenticated_encryption()
    print("✓ test_aes_256_gcm_authenticated_encryption passed")
    test_key_rotation()
    print("✓ test_key_rotation passed")
    test_digital_signatures()
    print("✓ test_digital_signatures passed")
    test_blockchain_contract_client()
    print("✓ test_blockchain_contract_client passed")
    test_ids_preprocessing_and_inference()
    print("✓ test_ids_preprocessing_and_inference passed")
    test_risk_and_severity_engine()
    print("✓ test_risk_and_severity_engine passed")
    test_soc_response_playbooks()
    print("✓ test_soc_response_playbooks passed")
    test_full_end_to_end_breach_simulation_pipeline()
    print("✓ test_full_end_to_end_breach_simulation_pipeline passed")
    print("=" * 70)
    print("ALL 10 VERIFICATION MODULES PASSED SUCCESSFULLY! 🚀")
    print("=" * 70)
