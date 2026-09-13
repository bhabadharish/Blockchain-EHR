"""
crypto/key_management.py
Cryptographic Key Lifecycle & Key Vault Management.
Implements key generation, key identifier derivation, usage tracking, key rotation,
and key revocation/destruction simulation.
"""

import time
import hashlib
from typing import Dict, Any, List, Optional
from crypto.encryption import AES256GCMCipher


class KeyMetadata:
    """Metadata tracking a specific cryptographic key."""

    def __init__(self, key_id: str, key_bytes: bytes, algorithm: str = "AES-256-GCM"):
        self.key_id = key_id
        self._key_bytes = key_bytes
        self.algorithm = algorithm
        self.created_at = time.time()
        self.status = "ACTIVE"  # ACTIVE, ROTATED, REVOKED, DESTROYED
        self.usage_count = 0
        self.rotated_at: Optional[float] = None
        self.revoked_at: Optional[float] = None

    @property
    def key_bytes(self) -> bytes:
        return self.get_key()

    def __getitem__(self, idx):
        if idx == 0:
            return self.key_id
        elif idx == 1:
            return self.key_bytes
        raise IndexError("KeyMetadata tuple index out of range (0 or 1)")

    def __iter__(self):
        yield self.key_id
        yield self.key_bytes

    def get_key(self) -> bytes:
        if self.status in ["REVOKED", "DESTROYED"]:
            raise PermissionError(f"Access Denied: Key {self.key_id} is {self.status}")
        self.usage_count += 1
        return self._key_bytes

    def rotate(self):
        self.status = "ROTATED"
        self.rotated_at = time.time()

    def destroy(self):
        self.status = "DESTROYED"
        self.revoked_at = time.time()
        self._key_bytes = b"\x00" * len(self._key_bytes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "status": self.status,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.created_at)),
            "usage_count": self.usage_count,
            "rotated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.rotated_at)) if self.rotated_at else None,
            "revoked_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.revoked_at)) if self.revoked_at else None
        }


class KeyManager:
    """Enterprise Key Management Service (KMS) simulation for EHR encryption keys."""

    def __init__(self):
        self.vault: Dict[str, KeyMetadata] = {}
        self.active_key_id: Optional[str] = None
        self.rotation_history: List[Dict[str, Any]] = []
        self._initialize_primary_key()

    @property
    def keys(self) -> Dict[str, KeyMetadata]:
        return self.vault

    def _initialize_primary_key(self):
        """Generates initial root active key."""
        raw_key = AES256GCMCipher.generate_key()
        key_id = "KEY-" + hashlib.sha256(raw_key).hexdigest()[:12].upper()
        meta = KeyMetadata(key_id=key_id, key_bytes=raw_key)
        self.vault[key_id] = meta
        self.active_key_id = key_id

    def get_active_key(self) -> KeyMetadata:
        """Returns active KeyMetadata object (supports key.key_id, key.key_bytes, and tuple unpacking)."""
        if not self.active_key_id or self.active_key_id not in self.vault:
            self._initialize_primary_key()
        return self.vault[self.active_key_id]

    def get_key_by_id(self, key_id: str) -> bytes:
        """Retrieves specific key by ID (for historical decryption)."""
        if key_id not in self.vault:
            raise KeyError(f"Key ID {key_id} not found in KMS vault")
        return self.vault[key_id].get_key()

    def rotate_key(self, reason: str = "Routine SOC Key Rotation") -> KeyMetadata:
        """
        Rotates current active key:
        Old key is archived with status ROTATED; fresh active key is instantiated.
        """
        old_id = self.active_key_id
        if old_id and old_id in self.vault:
            self.vault[old_id].rotate()

        raw_key = AES256GCMCipher.generate_key()
        new_id = "KEY-" + hashlib.sha256(raw_key).hexdigest()[:12].upper()
        meta = KeyMetadata(key_id=new_id, key_bytes=raw_key)
        self.vault[new_id] = meta
        self.active_key_id = new_id

        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "event": "KEY_ROTATION",
            "reason": reason,
            "previous_key_id": old_id,
            "new_key_id": new_id,
            "status": "SUCCESS"
        }
        self.rotation_history.append(event)
        return meta

    def revoke_key(self, key_id: str, reason: str = "COMPROMISE_SUSPECTED") -> Dict[str, Any]:
        """Revokes and destroys a compromised key."""
        if key_id in self.vault:
            self.vault[key_id].destroy()
            if self.active_key_id == key_id:
                # Force new key creation
                self._initialize_primary_key()
            event = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "event": "KEY_REVOCATION",
                "key_id": key_id,
                "reason": reason,
                "status": "DESTROYED"
            }
            self.rotation_history.append(event)
            return event
        raise KeyError(f"Key {key_id} not found")

    def list_keys(self) -> List[Dict[str, Any]]:
        """Returns inventory of all managed keys and lifecycle statuses."""
        return [k.to_dict() for k in self.vault.values()]
