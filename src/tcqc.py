"""
Tensor-Categorical Quantum Cryptography (TC-QC) Software Simulation Engine.
Part of the PhD Research Platform for Edge-IIoT IDS with Blockchain & Quantum Security.
Faithfully implements the mathematical formulation from the JIDMIS research manuscript (Equation 13):
C_EHR = A · (X_data ⊗ K_QC) · Bᵀ
Utilizes braided non-commutative tensor transformations over monoidal categories.
Clearly labeled as SOFTWARE SIMULATION in adherence to scientific transparency.
"""

import time
import numpy as np
from typing import Dict, Any, Tuple


class TCQCSimulation:
    """
    Mathematical software demonstration of Tensor-Category Quantum Cryptography.
    Uses invertible transformation matrices A and B, Kronecker tensor product (⊗),
    and bilinear morphisms to encrypt and decrypt IIoT telemetry state vectors.
    """

    def __init__(self, state_dim: int = 4, key_dim: int = 4, seed: int = 42):
        self.state_dim = state_dim
        self.key_dim = key_dim
        self.composite_dim = state_dim * key_dim
        self.seed = seed

        # Generate secret invertible transformation matrices A and B
        rng = np.random.default_rng(seed)
        
        # Invertible matrix A
        A_raw = rng.standard_normal((self.composite_dim, self.composite_dim))
        # Ensure conditioning by adding scaled identity
        self.A = A_raw + np.eye(self.composite_dim) * 2.0
        self.A_inv = np.linalg.inv(self.A)

        # Invertible matrix B
        B_raw = rng.standard_normal((self.composite_dim, self.composite_dim))
        self.B = B_raw + np.eye(self.composite_dim) * 2.0
        self.B_inv = np.linalg.inv(self.B)

        # Quantum Key Tensor representation K_QC
        self.K_QC = rng.standard_normal((key_dim, key_dim))
        # Normalize key tensor
        self.K_QC /= np.linalg.norm(self.K_QC)

    def format_payload_to_tensor(self, payload_vector: np.ndarray) -> np.ndarray:
        """
        Pads or reshapes incoming normalized telemetry feature vector to (state_dim, state_dim).
        """
        flat = np.asarray(payload_vector, dtype=np.float64).flatten()
        target_size = self.state_dim * self.state_dim
        
        if len(flat) < target_size:
            padded = np.pad(flat, (0, target_size - len(flat)), mode='constant')
        else:
            padded = flat[:target_size]

        return padded.reshape((self.state_dim, self.state_dim))

    def encrypt(self, X_data: np.ndarray) -> Tuple[np.ndarray, float]:
        """
        Executes Eq. 13: C_EHR = A · (X_data ⊗ K_QC) · Bᵀ
        Returns (Ciphertext_Tensor, latency_ms).
        """
        t0 = time.perf_counter()

        # Step 1: Kronecker Tensor Product: X_data ⊗ K_QC
        tensor_kron = np.kron(X_data, self.K_QC) # Shape: (composite_dim, composite_dim)

        # Step 2: Secret non-commutative bilinear morphism: A · (X_data ⊗ K_QC) · Bᵀ
        C_EHR = self.A @ tensor_kron @ self.B.T

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return C_EHR, elapsed_ms

    def decrypt(self, C_EHR: np.ndarray) -> Tuple[np.ndarray, float]:
        """
        Decodes ciphertext via matrix inversion:
        (X_data ⊗ K_QC) = A⁻¹ · C_EHR · (Bᵀ)⁻¹
        Then recovers X_data using key projection.
        Returns (Reconstructed_X, latency_ms).
        """
        t0 = time.perf_counter()

        # Step 1: Invert secret morphisms
        # Note: (Bᵀ)⁻¹ = (B⁻¹)ᵀ
        tensor_kron_rec = self.A_inv @ C_EHR @ self.B_inv.T

        # Step 2: Unweave Kronecker product using Frobenius inner product with K_QC
        # Since K_QC is normalized (||K_QC||_F ≈ 1), X[i, j] = Tr((tensor_block_ij) · K_QCᵀ) / ||K_QC||_F²
        X_rec = np.zeros((self.state_dim, self.state_dim), dtype=np.float64)
        k_norm_sq = np.sum(self.K_QC ** 2)

        for i in range(self.state_dim):
            for j in range(self.state_dim):
                block = tensor_kron_rec[
                    i * self.key_dim:(i + 1) * self.key_dim,
                    j * self.key_dim:(j + 1) * self.key_dim
                ]
                X_rec[i, j] = np.sum(block * self.K_QC) / k_norm_sq

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return X_rec, elapsed_ms

    def benchmark_telemetry_payload(self, telemetry_features: np.ndarray) -> Dict[str, Any]:
        """
        Complete encryption-decryption cycle with reconstruction fidelity verification.
        """
        X_data = self.format_payload_to_tensor(telemetry_features)
        
        # Encryption
        C_EHR, enc_latency_ms = self.encrypt(X_data)
        
        # Decryption
        X_rec, dec_latency_ms = self.decrypt(C_EHR)
        
        # Reconstruction Error (Frobenius Norm)
        recon_error = float(np.linalg.norm(X_data - X_rec, ord='fro'))
        fidelity = float(1.0 - min(1.0, recon_error / (np.linalg.norm(X_data) + 1e-8)))

        return {
            "type": "SIMULATION",
            "protocol": "Tensor-Categorical Quantum Cryptography (TC-QC)",
            "equation": "C_EHR = A · (X_data ⊗ K_QC) · Bᵀ",
            "state_dimension": f"{self.state_dim}x{self.state_dim}",
            "key_dimension": f"{self.key_dim}x{self.key_dim}",
            "composite_tensor_dimension": f"{self.composite_dim}x{self.composite_dim}",
            "encryption_latency_ms": round(enc_latency_ms, 4),
            "decryption_latency_ms": round(dec_latency_ms, 4),
            "reconstruction_error": round(recon_error, 8),
            "fidelity": round(fidelity, 6),
            "is_faithful": recon_error < 1e-5,
            "sample_input_tensor": X_data.round(3).tolist(),
            "sample_cipher_tensor": C_EHR[:4, :4].round(3).tolist(),
            "sample_reconstructed_tensor": X_rec.round(3).tolist()
        }


class TCQCEngine:
    """Wrapper class providing tensor encryption & decryption interface for Streamlit page 16."""
    def __init__(self, matrix_dim: int = 4, key_dim: int = 4, seed: int = 42):
        self.matrix_dim = matrix_dim
        self.key_dim = key_dim
        self.sim = TCQCSimulation(state_dim=matrix_dim, key_dim=key_dim, seed=seed)

    def encrypt_telemetry_tensor(self, sample_vector: np.ndarray) -> Dict[str, Any]:
        c_ehr, lat = self.sim.encrypt(sample_vector)
        return {
            "ciphertext": c_ehr,
            "key_tensor": self.sim.K_QC,
            "latency_ms": lat
        }

    def decrypt_telemetry_tensor(self, ciphertext: np.ndarray, key_tensor: np.ndarray = None) -> np.ndarray:
        x_rec, _ = self.sim.decrypt(ciphertext)
        return x_rec

