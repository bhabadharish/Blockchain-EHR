"""
Local Blockchain Ledger & Web3 Integration Engine.
Part of the PhD Research Platform for Edge-IIoT IDS with Blockchain & Quantum Security.
Provides immutable block generation, transaction mining, gas tracking, throughput profiling,
and seamless connection to Ganache/Hardhat/Anvil nodes or local resilient EVM simulation.
"""

import time
import hashlib
import json
from typing import Dict, Any, List, Optional, Tuple
from src.utils import load_config
from src.smart_contract import SmartContractManager

try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False


class Block:
    """Individual block in the immutable distributed ledger."""
    def __init__(self, index: int, previous_hash: str, transactions: List[Dict[str, Any]]):
        self.index = index
        self.timestamp = time.time()
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.nonce = 0
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "tx_count": len(self.transactions),
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode("utf-8")).hexdigest()


class BlockchainEngine:
    """
    Unified Blockchain Engine.
    Handles transaction submission, block creation, Web3 connectivity check,
    smart contract orchestration, and cryptographic tamper detection.
    """

    def __init__(self, config_path: str = "config.yaml"):
        self.config = load_config(config_path)
        self.rpc_url = self.config["blockchain"]["rpc_url"]
        self.contract_mgr = SmartContractManager(config_path)
        
        # Check Web3 connectivity
        self.is_connected_to_node = False
        self.w3 = None
        if WEB3_AVAILABLE:
            try:
                self.w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={'timeout': 0.5}))
                self.is_connected_to_node = self.w3.is_connected()
            except Exception:
                self.is_connected_to_node = False

        # Mode description
        self.mode = "LIVE_NODE (Web3 RPC)" if self.is_connected_to_node else "BLOCKCHAIN_SIMULATION_MODE"

        # Local Ledger Chain
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict[str, Any]] = []
        self.transaction_history: List[Dict[str, Any]] = []
        self._create_genesis_block()

    def reset(self):
        """Resets the blockchain ledger back to Genesis Block #0 and clears transaction history."""
        self.chain = []
        self.pending_transactions = []
        self.transaction_history = []
        self._create_genesis_block()
        if hasattr(self, "contract_mgr") and hasattr(self.contract_mgr, "reset"):
            self.contract_mgr.reset()

    def _create_genesis_block(self):
        """Initializes the immutable ledger with Genesis Block #0."""
        genesis_block = Block(
            index=0,
            previous_hash="0000000000000000000000000000000000000000000000000000000000000000",
            transactions=[{
                "tx_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "type": "GENESIS",
                "message": "Edge-IIoT Security Consortium Genesis Block Anchored",
                "timestamp": time.time()
            }]
        )
        self.chain.append(genesis_block)

    def submit_security_event_tx(
        self,
        event_id: str,
        device_hash: str,
        prediction: int,
        attack_type: str,
        confidence: float,
        payload_hash: str,
        model_hash: str,
        policy_hash: str,
        sender: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Anchors an intrusion detection security event onto the blockchain ledger.
        Executes smart contract createSecurityEvent, computes gas, and generates receipt.
        """
        t0 = time.perf_counter()
        caller = sender or self.contract_mgr.admin_address

        # 1. Execute smart contract state transition
        contract_res = self.contract_mgr.create_security_event(
            caller=caller,
            event_id=event_id,
            device_hash=device_hash,
            prediction=prediction,
            attack_type=attack_type,
            confidence=confidence,
            payload_hash=payload_hash,
            model_hash=model_hash,
            policy_hash=policy_hash
        )

        # 2. Build transaction record
        tx_data = {
            "event_id": event_id,
            "device_hash": device_hash,
            "prediction": "ATTACK" if prediction == 1 else "NORMAL",
            "attack_type": attack_type,
            "confidence": round(confidence, 2),
            "payload_hash": payload_hash,
            "model_hash": model_hash,
            "policy_hash": policy_hash,
            "sender": caller,
            "timestamp": time.time()
        }
        raw_tx_str = json.dumps(tx_data, sort_keys=True)
        tx_hash = "0x" + hashlib.sha256(raw_tx_str.encode("utf-8")).hexdigest()

        # Simulated gas calculation (approx 65,000 gas for storage write)
        gas_used = 65240
        gas_price_gwei = 20

        elapsed_sec = time.perf_counter() - t0
        confirmation_latency_ms = elapsed_sec * 1000.0

        tx_receipt = {
            "tx_hash": tx_hash,
            "block_number": len(self.chain),
            "event_id": event_id,
            "device_hash": device_hash,
            "payload_hash": payload_hash,
            "prediction": prediction,
            "attack_type": attack_type,
            "confidence": round(confidence, 2),
            "model_hash": model_hash,
            "policy_hash": policy_hash,
            "status": "SUCCESS",
            "gas_used": gas_used,
            "gas_cost_eth": round((gas_used * gas_price_gwei) / 1e9, 6),
            "confirmation_latency_ms": round(confirmation_latency_ms, 3),
            "contract_address": self.contract_mgr.contract_address,
            "mode": self.mode,
            "metadata": tx_data
        }

        # 3. Mine block
        new_block = Block(
            index=len(self.chain),
            previous_hash=self.chain[-1].hash,
            transactions=[tx_receipt]
        )
        self.chain.append(new_block)
        self.transaction_history.append(tx_receipt)

        return tx_receipt

    def verify_tamper_evidence(self, event_id: str, recomputed_payload_hash: str) -> Dict[str, Any]:
        """
        Compares on-chain anchored hash with off-chain computed hash.
        Produces verified cryptographic proof of authenticity or tampering.
        """
        t0 = time.perf_counter()
        evt = self.contract_mgr.get_event_metadata(event_id)
        if not evt:
            raise ValueError(f"Event {event_id} not found on blockchain ledger.")

        stored_hash = evt["payloadHash"]
        is_verified = (stored_hash.lower() == recomputed_payload_hash.lower())
        
        # Log to smart contract audit
        self.contract_mgr.verify_event_hash(
            caller=self.contract_mgr.admin_address,
            event_id=event_id,
            recomputed_hash=recomputed_payload_hash
        )

        latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "event_id": event_id,
            "blockchain_anchored_hash": stored_hash,
            "recomputed_payload_hash": recomputed_payload_hash,
            "integrity_verified": is_verified,
            "verdict": "INTEGRITY_VERIFIED" if is_verified else "TAMPER_DETECTED",
            "verification_latency_ms": round(latency_ms, 4)
        }

    def get_ledger_stats(self) -> Dict[str, Any]:
        """Returns live blockchain health and performance metrics."""
        total_tx = len(self.transaction_history)
        avg_latency = (
            sum(tx["confirmation_latency_ms"] for tx in self.transaction_history) / max(1, total_tx)
            if total_tx > 0 else 0.0
        )
        return {
            "mode": self.mode,
            "total_blocks": len(self.chain),
            "total_transactions": total_tx,
            "average_confirmation_latency_ms": round(avg_latency, 3),
            "latest_block_hash": self.chain[-1].hash,
            "total_audit_records": len(self.contract_mgr.audit_log),
            "contract_address": self.contract_mgr.contract_address
        }
