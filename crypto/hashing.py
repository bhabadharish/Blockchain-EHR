"""
crypto/hashing.py
Cryptographic SHA-256 Hashing & Merkle Integrity Module.
Computes deterministic SHA-256 digests and Merkle trees for EHR payloads.
"""

import hashlib
import json
from typing import List, Dict, Any, Union


class HashEngine:
    """Cryptographic hashing and Merkle tree verification engine."""

    @staticmethod
    def sha256(data: Union[bytes, str, Dict[str, Any]]) -> str:
        """Computes deterministic hexadecimal SHA-256 digest."""
        if isinstance(data, bytes):
            raw = data
        elif isinstance(data, str):
            raw = data.encode("utf-8")
        else:
            raw = json.dumps(data, sort_keys=True, separators=(',', ':'), default=str).encode("utf-8")
        return "0x" + hashlib.sha256(raw).hexdigest()

    @staticmethod
    def compute_merkle_root(hashes: List[str]) -> str:
        """Computes cryptographic Merkle tree root for an arbitrary batch of payload hashes."""
        if not hashes:
            return "0x" + ("0" * 64)
        if len(hashes) == 1:
            return hashes[0]

        current_level = [h.replace("0x", "") for h in hashes]
        while len(current_level) > 1:
            if len(current_level) % 2 != 0:
                current_level.append(current_level[-1])
            next_level = []
            for i in range(0, len(current_level), 2):
                combined = current_level[i] + current_level[i+1]
                parent = hashlib.sha256(bytes.fromhex(combined)).hexdigest()
                next_level.append(parent)
            current_level = next_level

        return "0x" + current_level[0]
