"""
blockchain/python_ledger.py
In-Memory Blockchain & EVM Simulation Fallback.
Provides resilient local block generation and smart contract logic when a physical
Ganache node is unavailable. Labeled clearly: "LOCAL FALLBACK / DEMONSTRATION MODE".
"""

import time
import json
import hashlib
from typing import Dict, Any, List, Optional, Tuple


class FallbackBlock:
    def __init__(self, index: int, previous_hash: str, transactions: List[Dict[str, Any]]):
        self.index = index
        self.timestamp = time.time()
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.nonce = 0
        self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        s = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "prev": self.previous_hash,
            "tx_len": len(self.transactions)
        }, sort_keys=True)
        return "0x" + hashlib.sha256(s.encode()).hexdigest()


class PythonLedgerEngine:
    """In-memory fallback ledger and smart contract simulator."""

    MODE_LABEL = "LOCAL FALLBACK / DEMONSTRATION MODE (In-Memory Python EVM)"

    def __init__(self):
        self.chain: List[FallbackBlock] = []
        self.ehr_registry: Dict[str, Dict[str, Any]] = {}
        self.incidents: Dict[str, Dict[str, Any]] = {}
        self.users: Dict[str, Dict[str, Any]] = {
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266": {"role": "ADMIN", "active": True}
        }
        self.audit_log: List[Dict[str, Any]] = []
        self._init_genesis()

    def _init_genesis(self):
        genesis = FallbackBlock(
            index=0,
            previous_hash="0x" + ("0" * 64),
            transactions=[{
                "tx_hash": "0x" + ("0" * 64),
                "type": "GENESIS",
                "message": "Privacy-Preserving EHR Consortium Genesis Block"
            }]
        )
        self.chain.append(genesis)

    def reset(self):
        self.chain.clear()
        self.ehr_registry.clear()
        self.incidents.clear()
        self.audit_log.clear()
        self._init_genesis()

    def register_ehr(self, record_id: str, payload_hash: str, algorithm: str, key_id: str, policy: str) -> Dict[str, Any]:
        tx_hash = "0x" + hashlib.sha256(f"{record_id}{payload_hash}{time.time()}".encode()).hexdigest()
        self.ehr_registry[record_id] = {
            "record_id": record_id,
            "payload_hash": payload_hash,
            "algorithm": algorithm,
            "key_id": key_id,
            "policy": policy,
            "timestamp": time.time(),
            "tx_hash": tx_hash
        }
        new_block = FallbackBlock(
            index=len(self.chain),
            previous_hash=self.chain[-1].hash,
            transactions=[{"tx_hash": tx_hash, "type": "EHR_REGISTRATION", "record_id": record_id}]
        )
        self.chain.append(new_block)
        return {
            "status": "SUCCESS",
            "tx_hash": tx_hash,
            "block_number": new_block.index,
            "gas_used": 65420,
            "record_id": record_id,
            "payload_hash": payload_hash
        }

    def register_ehr_metadata(
        self,
        record_id: str,
        payload_hash: str,
        algorithm: str = "AES-256-GCM",
        key_id: str = "KEY-001",
        access_policy: str = "DEFAULT",
        **kwargs
    ) -> Dict[str, Any]:
        """Registers EHR metadata in simulated fallback ledger with full metadata fields."""
        policy = kwargs.get("policy", access_policy)
        return self.register_ehr(record_id, payload_hash, algorithm, key_id, policy)

    def verify_integrity(self, record_id: str, recomputed_hash: str) -> Tuple[bool, str]:
        if record_id not in self.ehr_registry:
            return False, "RECORD_NOT_FOUND"
        stored = self.ehr_registry[record_id]["payload_hash"]
        is_valid = (stored.lower() == recomputed_hash.lower())
        self.audit_log.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "event": "INTEGRITY_VERIFICATION",
            "record_id": record_id,
            "verdict": "VERIFIED" if is_valid else "TAMPER_DETECTED"
        })
        return is_valid, "INTEGRITY_VERIFIED_AUTHENTIC" if is_valid else "TAMPER_DETECTED_HASH_MISMATCH"

    def record_incident(self, incident_id: str, record_id: str, attack_type: str, severity: str, confidence: float, breached: bool, action: str) -> Dict[str, Any]:
        tx_hash = "0x" + hashlib.sha256(f"{incident_id}{attack_type}{time.time()}".encode()).hexdigest()
        self.incidents[incident_id] = {
            "incident_id": incident_id,
            "record_id": record_id,
            "attack_type": attack_type,
            "severity": severity,
            "confidence": confidence,
            "integrity_breached": breached,
            "recommended_action": action,
            "timestamp": time.time(),
            "tx_hash": tx_hash
        }
        new_block = FallbackBlock(
            index=len(self.chain),
            previous_hash=self.chain[-1].hash,
            transactions=[{"tx_hash": tx_hash, "type": "SECURITY_INCIDENT", "incident_id": incident_id, "attack": attack_type}]
        )
        self.chain.append(new_block)
        return {"status": "SUCCESS", "tx_hash": tx_hash, "block_number": new_block.index, "gas_used": 78200}
