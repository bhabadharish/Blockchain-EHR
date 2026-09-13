"""
Unit tests for blockchain ledger, block mining, and tamper detection.
"""

import pytest
from src.blockchain import BlockchainEngine
from src.crypto import CryptographicEngine


def test_blockchain_ledger_and_blocks():
    bc = BlockchainEngine()
    initial_blocks = len(bc.chain)
    assert initial_blocks >= 1, "Genesis block missing"

    # Submit transaction
    receipt = bc.submit_security_event_tx(
        event_id="0xtest_event_001",
        device_hash="0xdev_001",
        prediction=1,
        attack_type="Ransomware",
        confidence=98.7,
        payload_hash="0xpayload_hash_001",
        model_hash="0xmodel_hash_001",
        policy_hash="0xpolicy_hash_001"
    )

    assert receipt["status"] == "SUCCESS"
    assert len(bc.chain) == initial_blocks + 1
    assert receipt["gas_used"] > 0

    stats = bc.get_ledger_stats()
    assert stats["total_transactions"] >= 1


def test_tamper_detection_workflow():
    bc = BlockchainEngine()
    event_id = "0xtamper_test_event"
    payload_hash = "0xoriginal_unaltered_hash_12345"

    bc.submit_security_event_tx(
        event_id=event_id,
        device_hash="0xdev_tamper",
        prediction=1,
        attack_type="DDoS_HTTP",
        confidence=95.0,
        payload_hash=payload_hash,
        model_hash="0xmodel",
        policy_hash="0xpolicy"
    )

    # Legitimate hash check
    res_valid = bc.verify_tamper_evidence(event_id, payload_hash)
    assert res_valid["verdict"] == "INTEGRITY_VERIFIED"
    assert res_valid["integrity_verified"] is True

    # Tampered hash check
    res_tamper = bc.verify_tamper_evidence(event_id, "0xmodified_corrupted_hash")
    assert res_tamper["verdict"] == "TAMPER_DETECTED"
    assert res_tamper["integrity_verified"] is False
