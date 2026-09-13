"""
Unit tests for QKD simulation, TC-QC tensor encryption, QDS, and cryptographic baselines.
"""

import pytest
import numpy as np
from src.qkd import BB84Simulation
from src.tcqc import TCQCSimulation
from src.crypto import CryptographicEngine


def test_bb84_simulation():
    qkd = BB84Simulation(seed=42)
    res_normal = qkd.simulate(num_qubits=500, eavesdropper=False)
    assert res_normal["security_decision"] == "SECURE_KEY_ESTABLISHED"
    assert res_normal["qber_percent"] < 11.0
    assert len(res_normal["final_symmetric_key_hex"]) == 64

    res_eve = qkd.simulate(num_qubits=500, eavesdropper=True)
    assert res_eve["security_decision"] == "ABORTED_EAVESDROPPER_DETECTED"
    assert res_eve["eavesdrop_detected"] is True
    assert res_eve["qber_percent"] > 11.0


def test_tcqc_simulation():
    tcqc = TCQCSimulation(state_dim=4, key_dim=4, seed=42)
    dummy_telemetry = np.random.randn(16)
    bench = tcqc.benchmark_telemetry_payload(dummy_telemetry)

    assert bench["is_faithful"] is True
    assert bench["reconstruction_error"] < 1e-5
    assert bench["fidelity"] > 0.999
    assert bench["decryption_latency_ms"] > 0.0


def test_crypto_engine_and_qds():
    crypto = CryptographicEngine()
    qds = crypto.generate_and_verify_qds("Test-Telemetry-Message")
    assert qds["decision"] == "Signature Valid"
    assert qds["quantum_fidelity"] > 0.95

    # Test baseline benchmarks
    baselines = crypto.benchmark_baselines("Telemetry-String")
    assert "AES_256" in baselines
    assert "RSA_2048" in baselines
    assert "ECC_SECP256R1" in baselines
