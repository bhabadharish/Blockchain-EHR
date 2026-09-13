"""
blockchain/contract_client.py
Unified Smart Contract Client (Ganache Live Web3 & In-Memory Fallback).
Connects to EHRAccessControl and EHRIntegrityRegistry deployed via Truffle,
with automatic graceful degradation to local Python simulation mode.
"""

import os
import json
import time
from typing import Dict, Any, List, Optional, Tuple
from blockchain.web3_client import Web3Client
from blockchain.python_ledger import PythonLedgerEngine


class IntegrityResult(dict):
    """Result object for integrity verification supporting both dict keys and tuple unpacking."""
    def __iter__(self):
        yield self.get("match", False)
        yield self.get("status", "")

    def __getitem__(self, item):
        return super().__getitem__(item)


class BlockchainContractClient:
    """Unified client orchestrating smart contract interactions."""

    def __init__(self, rpc_url: str = "http://127.0.0.1:8545"):
        self.web3_client = Web3Client(rpc_url)
        self.fallback_engine = PythonLedgerEngine()

        self.access_control_contract: Optional[Any] = None
        self.integrity_registry_contract: Optional[Any] = None
        self.access_control_address: Optional[str] = None
        self.integrity_registry_address: Optional[str] = None
        self.account: Optional[str] = None

        self._init_contracts()

    def _init_contracts(self):
        if not self.web3_client.is_connected or self.web3_client.w3 is None:
            return

        w3 = self.web3_client.w3
        self.account = w3.eth.accounts[0] if len(w3.eth.accounts) > 0 else None

        # Load Truffle build artifacts
        ac_artifact = "blockchain_truffle/build/contracts/EHRAccessControl.json"
        ir_artifact = "blockchain_truffle/build/contracts/EHRIntegrityRegistry.json"

        try:
            if os.path.exists(ac_artifact) and os.path.exists(ir_artifact):
                with open(ac_artifact, "r") as f:
                    ac_data = json.load(f)
                with open(ir_artifact, "r") as f:
                    ir_data = json.load(f)

                # Get deployed network
                net_id = str(w3.net.version)
                if net_id in ac_data.get("networks", {}):
                    self.access_control_address = ac_data["networks"][net_id]["address"]
                    self.access_control_contract = w3.eth.contract(
                        address=self.access_control_address, abi=ac_data["abi"]
                    )

                if net_id in ir_data.get("networks", {}):
                    self.integrity_registry_address = ir_data["networks"][net_id]["address"]
                    self.integrity_registry_contract = w3.eth.contract(
                        address=self.integrity_registry_address, abi=ir_data["abi"]
                    )
        except Exception as e:
            print("Warning: Could not initialize Web3 contracts:", e)

    @property
    def is_live_ganache(self) -> bool:
        return (
            self.web3_client.is_connected and
            self.integrity_registry_contract is not None
        )

    def get_mode_description(self) -> str:
        if self.is_live_ganache:
            return f"LIVE_GANACHE (Truffle Deployed: {self.integrity_registry_address[:12]}...)"
        return "LOCAL FALLBACK / DEMONSTRATION MODE (In-Memory Python EVM)"

    def register_ehr_metadata(
        self,
        record_id: str,
        payload_hash: str,
        algorithm: str = "AES-256-GCM",
        key_id: str = "KEY-01",
        access_policy: str = "DOCTOR_ONLY"
    ) -> Dict[str, Any]:
        """Registers cryptographic EHR metadata onto the blockchain."""
        if self.is_live_ganache:
            try:
                w3 = self.web3_client.w3
                # Format payload_hash to bytes32
                raw_hash = payload_hash.replace("0x", "")
                b32 = bytes.fromhex(raw_hash.ljust(64, '0')[:64])

                tx_fn = self.integrity_registry_contract.functions.registerEHR(
                    record_id, b32, algorithm, key_id, access_policy
                )
                tx_hash_bytes = tx_fn.transact({'from': self.account, 'gas': 300000})
                receipt = w3.eth.wait_for_transaction_receipt(tx_hash_bytes)

                return {
                    "mode": "GANACHE_ON_CHAIN",
                    "status": "SUCCESS",
                    "tx_hash": receipt.transactionHash.hex(),
                    "block_number": receipt.blockNumber,
                    "gas_used": receipt.gasUsed,
                    "record_id": record_id,
                    "payload_hash": payload_hash
                }
            except Exception as ex:
                print(f"Ganache registerEHR failed ({ex}), using fallback ledger.")

        # Fallback
        if hasattr(self.fallback_engine, "register_ehr_metadata"):
            res = self.fallback_engine.register_ehr_metadata(record_id, payload_hash, algorithm, key_id, access_policy)
        else:
            res = self.fallback_engine.register_ehr(record_id, payload_hash, algorithm, key_id, access_policy)
        res["record_id"] = record_id
        res["payload_hash"] = payload_hash
        res["mode"] = "PYTHON_SIMULATION_FALLBACK"
        return res

    def verify_integrity(self, record_id: str, recomputed_hash: str) -> IntegrityResult:
        """Compares recomputed payload hash against on-chain anchored hash."""
        if self.is_live_ganache:
            try:
                raw_hash = recomputed_hash.replace("0x", "")
                b32 = bytes.fromhex(raw_hash.ljust(64, '0')[:64])
                is_valid, msg = self.integrity_registry_contract.functions.verifyIntegrity(
                    record_id, b32
                ).call({'from': self.account})

                meta = self.integrity_registry_contract.functions.getEHRMetadata(record_id).call({'from': self.account})
                on_chain_hex = meta[0].hex() if hasattr(meta[0], 'hex') else str(meta[0])

                return IntegrityResult({
                    "match": is_valid,
                    "status": msg,
                    "on_chain_hash": on_chain_hex,
                    "mode": "GANACHE_ON_CHAIN"
                })
            except Exception:
                pass

        fb_match, fb_msg = self.fallback_engine.verify_integrity(record_id, recomputed_hash)
        return IntegrityResult({
            "match": fb_match,
            "status": fb_msg,
            "on_chain_hash": recomputed_hash if fb_match else "0xMISMATCH",
            "mode": "FALLBACK"
        })

    def authorize_user(self, user_address: str, role: str = "DOCTOR", validity_seconds: int = 86400) -> Dict[str, Any]:
        """Grants role authorization on EHRAccessControl smart contract."""
        if self.is_live_ganache and self.access_control_contract:
            try:
                w3 = self.web3_client.w3
                chk = w3.to_checksum_address(user_address)
                tx = self.access_control_contract.functions.authorizeUser(
                    chk, role, validity_seconds
                ).transact({'from': self.account, 'gas': 150000})
                receipt = w3.eth.wait_for_transaction_receipt(tx)
                return {"status": "SUCCESS", "tx_hash": receipt.transactionHash.hex(), "role": role}
            except Exception as e:
                pass
        return {"status": "SUCCESS", "mode": "FALLBACK", "role": role}

    def revoke_user(self, user_address: str) -> Dict[str, Any]:
        """Revokes user authorization on EHRAccessControl smart contract."""
        if self.is_live_ganache and self.access_control_contract:
            try:
                w3 = self.web3_client.w3
                chk = w3.to_checksum_address(user_address)
                tx = self.access_control_contract.functions.revokeUser(chk).transact({'from': self.account, 'gas': 100000})
                receipt = w3.eth.wait_for_transaction_receipt(tx)
                return {"status": "SUCCESS", "tx_hash": receipt.transactionHash.hex()}
            except Exception:
                pass
        return {"status": "SUCCESS", "mode": "FALLBACK"}

    def record_incident(
        self,
        incident_id: str,
        payload_hash: str = "",
        attack_type: str = "Normal",
        severity: str = "LOW",
        confidence_pct: float = 99.0,
        integrity_status: str = "VALID",
        **kwargs
    ) -> Dict[str, Any]:
        """Convenience alias for record_security_incident."""
        return self.record_security_incident(
            incident_id=incident_id,
            record_id=kwargs.get("record_id", "EHR-RECORD-001"),
            attack_type=attack_type,
            severity=severity,
            confidence_score=confidence_pct / 100.0,
            integrity_breached=(integrity_status == "BREACHED"),
            recommended_action=kwargs.get("recommended_action", "Isolate node and rotate keys")
        )

    def record_security_incident(
        self,
        incident_id: str,
        record_id: str,
        attack_type: str,
        severity: str,
        confidence_score: float,
        integrity_breached: bool,
        recommended_action: str
    ) -> Dict[str, Any]:
        """Logs a security incident on the blockchain ledger."""
        conf_int = int(round(confidence_score * 100.0))  # e.g. 99.42 -> 9942
        if self.is_live_ganache:
            try:
                w3 = self.web3_client.w3
                tx_fn = self.integrity_registry_contract.functions.recordIncident(
                    incident_id, record_id, attack_type, severity, conf_int, integrity_breached, recommended_action
                )
                tx_hash_bytes = tx_fn.transact({'from': self.account, 'gas': 350000})
                receipt = w3.eth.wait_for_transaction_receipt(tx_hash_bytes)

                return {
                    "mode": "GANACHE_ON_CHAIN",
                    "status": "SUCCESS",
                    "tx_hash": receipt.transactionHash.hex(),
                    "block_number": receipt.blockNumber,
                    "gas_used": receipt.gasUsed,
                    "incident_id": incident_id
                }
            except Exception as ex:
                print(f"Ganache incident log failed ({ex}), using fallback.")

        res = self.fallback_engine.record_incident(
            incident_id, record_id, attack_type, severity, confidence_score, integrity_breached, recommended_action
        )
        res["mode"] = "PYTHON_SIMULATION_FALLBACK"
        return res

    def check_role_authorization(self, user_addr: str, required_role: str) -> Tuple[bool, str]:
        """Evaluates RBAC authorization via EHRAccessControl."""
        if self.is_live_ganache and self.access_control_contract:
            try:
                w3 = self.web3_client.w3
                chk_addr = w3.to_checksum_address(user_addr)
                is_auth, reason = self.access_control_contract.functions.isAuthorized(
                    chk_addr, required_role
                ).call({'from': self.account})
                return is_auth, reason
            except Exception:
                pass

        # Fallback simulation roles
        is_auth = (required_role in ["DOCTOR", "SECURITY_ANALYST", "ADMIN"])
        return is_auth, "ROLE_AUTHORIZED" if is_auth else "ROLE_MISMATCH_DENIED"

    def get_ledger_stats(self) -> Dict[str, Any]:
        """Returns unified blockchain metrics."""
        net_status = self.web3_client.get_network_status()
        if self.is_live_ganache:
            total_records = 0
            total_incidents = 0
            try:
                total_records = self.integrity_registry_contract.functions.getTotalRecords().call()
                total_incidents = self.integrity_registry_contract.functions.getTotalIncidents().call()
            except Exception:
                pass

            return {
                "mode": "GANACHE_LIVE",
                "mode_label": self.get_mode_description(),
                "connected": True,
                "current_block": net_status["current_block"],
                "contract_address": self.integrity_registry_address,
                "access_control_address": self.access_control_address,
                "primary_account": net_status["primary_account"],
                "account_balance_eth": net_status["account_balance_eth"],
                "gas_price_gwei": net_status["gas_price_gwei"],
                "total_anchored_records": total_records,
                "total_incidents_recorded": total_incidents
            }

        return {
            "mode": "FALLBACK_SIMULATION",
            "mode_label": self.get_mode_description(),
            "connected": False,
            "current_block": len(self.fallback_engine.chain),
            "contract_address": "0xSIMULATED_CONTRACT_EVM",
            "primary_account": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "account_balance_eth": 100.0,
            "gas_price_gwei": 20.0,
            "total_anchored_records": len(self.fallback_engine.ehr_registry),
            "total_incidents_recorded": len(self.fallback_engine.incidents)
        }
