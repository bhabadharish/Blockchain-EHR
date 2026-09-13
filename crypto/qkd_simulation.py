"""
crypto/qkd_simulation.py
BB84 Quantum Key Distribution (QKD) Software Simulation.
NOTE: This is a software simulation of the BB84 protocol for session key negotiation.
It does NOT claim or utilize physical quantum optical hardware.
"""

import random
import hashlib
from typing import Dict, Any, List, Tuple


class BB84Simulation:
    """Simulates BB84 photon-state polarization, basis reconciliation, and QBER analysis."""

    BASES = ["RECTILINEAR (+)", "DIAGONAL (x)"]

    @classmethod
    def simulate_key_exchange(
        cls,
        num_qubits: int = 1000,
        eavesdrop: bool = False,
        eve_intercept_rate: float = 0.5
    ) -> Dict[str, Any]:
        """
        Executes full BB84 simulation:
        1. Alice selects random bits and bases.
        2. Bob chooses random measurement bases.
        3. Optional Eve intercept-resend attack.
        4. Sifting phase where bases match.
        5. Quantum Bit Error Rate (QBER) calculation.
        """
        # Alice
        alice_bits = [random.randint(0, 1) for _ in range(num_qubits)]
        alice_bases = [random.choice(cls.BASES) for _ in range(num_qubits)]

        # Transmission Channel (with optional Eve)
        channel_bits = list(alice_bits)
        if eavesdrop:
            for i in range(num_qubits):
                if random.random() < eve_intercept_rate:
                    eve_basis = random.choice(cls.BASES)
                    # If Eve guessed wrong basis, she introduces ~50% error probability upon re-emission
                    if eve_basis != alice_bases[i]:
                        channel_bits[i] = random.randint(0, 1)

        # Bob
        bob_bases = [random.choice(cls.BASES) for _ in range(num_qubits)]
        bob_measured = []
        for i in range(num_qubits):
            if bob_bases[i] == alice_bases[i]:
                bob_measured.append(channel_bits[i])
            else:
                bob_measured.append(random.randint(0, 1))

        # Sifting (matching bases)
        sifted_alice = []
        sifted_bob = []
        for i in range(num_qubits):
            if alice_bases[i] == bob_bases[i]:
                sifted_alice.append(alice_bits[i])
                sifted_bob.append(bob_measured[i])

        # QBER estimation on sample (e.g. first 20% of sifted bits)
        sample_size = max(1, len(sifted_alice) // 5)
        errors = sum(1 for a, b in zip(sifted_alice[:sample_size], sifted_bob[:sample_size]) if a != b)
        qber = (errors / sample_size) if sample_size > 0 else 0.0

        # Discard sample bits from final key
        final_bits_alice = sifted_alice[sample_size:]
        final_bits_bob = sifted_bob[sample_size:]

        # Eavesdropping threshold (standard BB84 threshold is ~11% QBER)
        eve_detected = qber > 0.11

        # Derive 256-bit AES session key via SHA-256 privacy amplification
        bit_str = "".join(str(b) for b in final_bits_alice)
        session_key = hashlib.sha256(bit_str.encode()).digest()

        sifted_key = sifted_alice
        eavesdrop_detected = eve_detected
        final_key_hex = session_key.hex()

        return {
            "mechanism": "BB84 Quantum Key Agreement (Software Simulation)",
            "physical_quantum_hardware": False,
            "raw_qubits_sent": num_qubits,
            "raw_bits_sent": num_qubits,
            "sifted_key_length": len(sifted_key),
            "sample_errors": errors,
            "qber_pct": round(qber, 2),
            "eavesdropping_detected": eavesdrop_detected,
            "abort_threshold_pct": 11.0,
            "derived_key_hex": final_key_hex,
            "key_agreement_success": not eavesdrop_detected and len(sifted_key) >= 128
        }


class BB84Simulator:
    """Wrapper class providing object-oriented BB84 simulation API."""
    def __init__(self, num_bits: int = 256, eve_present: bool = True):
        self.num_bits = num_bits
        self.eve_present = eve_present

    def run_simulation(self) -> Dict[str, Any]:
        return BB84Simulation.simulate_key_exchange(
            num_qubits=self.num_bits,
            eavesdrop=self.eve_present
        )
