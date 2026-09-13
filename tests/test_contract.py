"""
Unit tests for smart contract RBAC, ABAC, and audit logging.
"""

import pytest
from src.smart_contract import SmartContractManager


def test_smart_contract_rbac_and_abac():
    mgr = SmartContractManager()
    admin = mgr.admin_address
    analyst_addr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    unknown_addr = "0x0000000000000000000000000000000000000099"

    # Create event
    event_id = "0xcontract_test_event"
    mgr.create_security_event(
        caller=admin,
        event_id=event_id,
        device_hash="0xdev",
        prediction=1,
        attack_type="Backdoor",
        confidence=99.0,
        payload_hash="0xhash123",
        model_hash="0xmod",
        policy_hash="0xpol"
    )

    # Admin access
    allow_admin, _ = mgr.authorize_access(admin, event_id)
    assert allow_admin is True

    # Security analyst with correct attribute
    allow_analyst, _ = mgr.authorize_access(analyst_addr, event_id, requested_attribute="IIoT_SECURITY")
    assert allow_analyst is True

    # Unknown user
    allow_unknown, _ = mgr.authorize_access(unknown_addr, event_id)
    assert allow_unknown is False

    # Check audit log length
    logs = mgr.get_audit_log(10)
    assert len(logs) >= 3
