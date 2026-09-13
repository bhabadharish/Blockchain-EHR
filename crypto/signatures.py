"""
crypto/signatures.py
Digital Signatures & Message Authentication Module.
Provides asymmetric digital signatures (ECDSA SECP256R1, RSA-2048)
and symmetric integrity tags (HMAC-SHA256), accurately labeled.
"""

import hmac
import hashlib
import time
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class DigitalSignatureEngine:
    """
    Asymmetric Digital Signature Engine using ECDSA (SECP256R1) and RSA-2048.
    Provides non-repudiation and origin authenticity for healthcare providers.
    """

    def __init__(self):
        # ECDSA Key Pair
        self.ecdsa_private_key = ec.generate_private_key(ec.SECP256R1())
        self.ecdsa_public_key = self.ecdsa_private_key.public_key()

        # RSA Key Pair
        self.rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rsa_public_key = self.rsa_private_key.public_key()

    @staticmethod
    def generate_keypair():
        """Generates (private_key, public_key) ECDSA SECP256R1 pair."""
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        return priv, pub

    @staticmethod
    def sign_data(payload_bytes: bytes, private_key) -> bytes:
        """Signs payload bytes using private key and SHA-256."""
        return private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))

    @staticmethod
    def verify_signature(payload_bytes: bytes, signature_bytes: bytes, public_key) -> bool:
        """Verifies signature against payload using public key."""
        try:
            public_key.verify(signature_bytes, payload_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def sign_payload_ecdsa(self, payload_bytes: bytes) -> Dict[str, Any]:
        """Signs payload using ECDSA (SECP256R1) with SHA-256."""
        t0 = time.perf_counter()
        signature = self.ecdsa_private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
        lat_ms = (time.perf_counter() - t0) * 1000.0

        pub_bytes = self.ecdsa_public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

        return {
            "mechanism": "Asymmetric Digital Signature (ECDSA SECP256R1 + SHA-256)",
            "signature_hex": signature.hex(),
            "signature_bytes": signature,
            "signature_length_bytes": len(signature),
            "public_key_pem": pub_bytes.decode(),
            "latency_ms": round(lat_ms, 4)
        }

    def verify_payload_ecdsa(self, payload_bytes: bytes, signature_bytes: bytes) -> bool:
        """Verifies ECDSA signature using public key."""
        try:
            self.ecdsa_public_key.verify(signature_bytes, payload_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    @staticmethod
    def generate_hmac(key: bytes, payload_bytes: bytes) -> Dict[str, Any]:
        """
        Symmetric Message Authentication Code (HMAC-SHA256).
        Correctly labeled as symmetric integrity/authentication (NOT a digital signature).
        """
        t0 = time.perf_counter()
        tag = hmac.new(key, payload_bytes, hashlib.sha256).digest()
        lat_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "mechanism": "Symmetric Message Authentication (HMAC-SHA256)",
            "mac_hex": tag.hex(),
            "mac_bytes": tag,
            "mac_length_bytes": len(tag),
            "latency_ms": round(lat_ms, 4)
        }

    @staticmethod
    def verify_hmac(key: bytes, payload_bytes: bytes, expected_tag: bytes) -> bool:
        """Constant-time HMAC verification."""
        computed = hmac.new(key, payload_bytes, hashlib.sha256).digest()
        return hmac.compare_digest(computed, expected_tag)
