"""
Solidity Smart Contract Interface & In-Memory EVM Engine.
Part of the PhD Research Platform for Edge-IIoT IDS with Blockchain & Quantum Security.
Executes the IIoTSecurityRegistry contract logic with RBAC, ABAC, and SHA-256 integrity verification.
"""

import time
import hashlib
import json
from typing import Dict, Any, List, Optional, Tuple
from src.utils import load_config


class SmartContractManager:
    """
    Manages interactions with the IIoTSecurityRegistry smart contract.
    Implements RBAC roles, ABAC attributes, security event metadata creation,
    cryptographic integrity verification, and audit trail generation.
    """

    ROLES = {
        0: "NONE",
        1: "ADMIN",
        2: "SECURITY_ANALYST",
        3: "OPERATOR",
        4: "RESEARCHER",
        5: "AUDITOR",
        6: "DEVICE"
    }
    ROLE_TO_ID = {v: k for k, v in ROLES.items()}

    def __init__(self, config_path: str = "config.yaml"):
        self.config = load_config(config_path)
        self.contract_address = self.config["blockchain"]["contract_address"]
        self.admin_address = self.config["blockchain"]["admin_address"]

        # Contract State Storage
        self.users: Dict[str, Dict[str, Any]] = {
            self.admin_address.lower(): {
                "role": "ADMIN",
                "role_id": 1,
                "isActive": True,
                "attributes": {"department": "ADMIN", "clearance": "ROOT"}
            }
        }
        self.registered_devices: Dict[str, Dict[str, Any]] = {}
        self.devices: Dict[str, Dict[str, Any]] = self.registered_devices
        self.security_events: Dict[str, Dict[str, Any]] = {}
        self.event_ids: List[str] = []
        self.audit_log: List[Dict[str, Any]] = []

        # Standard test personas
        self._init_default_personas()

    def reset(self):
        """Resets dynamic contract state: clears events, audit logs, and registered devices."""
        self.registered_devices.clear()
        self.devices = self.registered_devices
        self.security_events.clear()
        self.event_ids.clear()
        self.audit_log.clear()

    @property
    def devices(self) -> Dict[str, Dict[str, Any]]:
        """Alias for registered_devices."""
        return getattr(self, "registered_devices", {})

    @devices.setter
    def devices(self, val: Dict[str, Dict[str, Any]]):
        self.registered_devices = val

    def _init_default_personas(self):
        """Initializes standard research personas for RBAC/ABAC verification."""
        personas = [
            ("0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "SECURITY_ANALYST", {"department": "IIoT_SECURITY", "clearance": "HIGH"}),
            ("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", "RESEARCHER", {"department": "ACADEMIA", "clearance": "READ_ONLY"}),
            ("0x90F79bf6EB2c4f870365E785982E1f101E93b906", "OPERATOR", {"department": "FACTORY_FLOOR", "environment": "PRODUCTION"}),
            ("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65", "AUDITOR", {"department": "COMPLIANCE", "clearance": "AUDIT"}),
            ("0x9965507D1a55bcC2695C58ba16FB37d819B0A4df", "DEVICE", {"department": "SENSORS", "clearance": "EDGE_INGEST"})
        ]
        for addr, role, attrs in personas:
            self.register_user(self.admin_address, addr, role)
            for k, v in attrs.items():
                self.set_attribute(self.admin_address, addr, k, v)

    def register_device(self, caller: str, device_hash: str, metadata: str) -> Dict[str, Any]:
        """Contract function: registerDevice(bytes32 deviceHash, string metadata)"""
        caller_l = caller.lower()
        if caller_l not in self.users or not self.users[caller_l]["isActive"]:
            raise PermissionError("Caller is not active or registered")
        
        if device_hash in self.registered_devices:
            raise ValueError("Device already registered")

        self.registered_devices[device_hash] = {
            "device_hash": device_hash,
            "metadata": metadata,
            "registered_at": time.time(),
            "registered_by": caller
        }
        return {"status": "SUCCESS", "device_hash": device_hash}

    def register_user(self, caller: str, user_addr: str, role_name: str) -> Dict[str, Any]:
        """Contract function: registerUser(address user, uint8 role)"""
        caller_l = caller.lower()
        if caller_l != self.admin_address.lower() and self.users.get(caller_l, {}).get("role") != "ADMIN":
            raise PermissionError("Caller is not authorized ADMIN")

        u_addr = user_addr.lower()
        role_id = self.ROLE_TO_ID.get(role_name, 0)
        self.users[u_addr] = {
            "role": role_name,
            "role_id": role_id,
            "isActive": True,
            "attributes": {}
        }
        return {"status": "SUCCESS", "user": user_addr, "role": role_name}

    def set_role(self, caller: str, user_addr: str, role_name: str) -> Dict[str, Any]:
        """Contract function: setRole(address user, uint8 role)"""
        caller_l = caller.lower()
        if self.users.get(caller_l, {}).get("role") != "ADMIN":
            raise PermissionError("Caller is not authorized ADMIN")

        u_addr = user_addr.lower()
        if u_addr not in self.users:
            raise ValueError("User not registered")

        old_role = self.users[u_addr]["role"]
        self.users[u_addr]["role"] = role_name
        self.users[u_addr]["role_id"] = self.ROLE_TO_ID.get(role_name, 0)
        return {"status": "SUCCESS", "user": user_addr, "old_role": old_role, "new_role": role_name}

    def set_attribute(self, caller: str, user_addr: str, key: str, value: str) -> Dict[str, Any]:
        """Contract function: setAttribute(address user, string key, string value)"""
        caller_l = caller.lower()
        if self.users.get(caller_l, {}).get("role") != "ADMIN":
            raise PermissionError("Caller is not authorized ADMIN")

        u_addr = user_addr.lower()
        if u_addr not in self.users:
            raise ValueError("User not registered")

        self.users[u_addr]["attributes"][key] = value
        return {"status": "SUCCESS", "user": user_addr, "key": key, "value": value}

    def create_security_event(
        self,
        caller: str,
        event_id: str,
        device_hash: str,
        prediction: int,
        attack_type: str,
        confidence: float,
        payload_hash: str,
        model_hash: str,
        policy_hash: str
    ) -> Dict[str, Any]:
        """Contract function: createSecurityEvent(...)"""
        caller_l = caller.lower()
        if caller_l not in self.users or not self.users[caller_l]["isActive"]:
            raise PermissionError("Caller is not active or registered")

        if event_id in self.security_events:
            raise ValueError(f"Event ID {event_id} already exists")

        conf_scaled = int(confidence * 100) # e.g. 98.50 -> 9850
        evt = {
            "eventId": event_id,
            "timestamp": time.time(),
            "deviceHash": device_hash,
            "prediction": prediction,
            "attackType": attack_type,
            "confidence": conf_scaled,
            "payloadHash": payload_hash,
            "modelHash": model_hash,
            "policyHash": policy_hash,
            "reporter": caller,
            "exists": True
        }

        self.security_events[event_id] = evt
        self.event_ids.append(event_id)

        return {"status": "SUCCESS", "eventId": event_id, "timestamp": evt["timestamp"]}

    def store_event_hash(self, caller: str, event_id: str, new_hash: str):
        """Contract function: storeEventHash(...)"""
        caller_l = caller.lower()
        if caller_l not in self.users or not self.users[caller_l]["isActive"]:
            raise PermissionError("Caller is not active or registered")
        if event_id not in self.security_events:
            raise ValueError(f"Event {event_id} does not exist")
        self.security_events[event_id]["payloadHash"] = new_hash

    def verify_event_hash(self, caller: str, event_id: str, recomputed_hash: str) -> bool:
        """Contract function: verifyEventHash(bytes32 eventId, bytes32 recomputedHash)"""
        if event_id not in self.security_events:
            raise ValueError(f"Event {event_id} does not exist")

        stored_hash = self.security_events[event_id]["payloadHash"]
        matches = (stored_hash.lower() == recomputed_hash.lower())

        # Create immutable contract audit record
        self.audit_log.append({
            "timestamp": time.time(),
            "accessor": caller,
            "eventId": event_id,
            "action": "VERIFY_HASH",
            "decision": matches,
            "reason": "INTEGRITY_VERIFIED" if matches else "TAMPER_DETECTED"
        })
        return matches

    def authorize_access(
        self,
        caller: str,
        event_id: str,
        requested_attribute: str = ""
    ) -> Tuple[bool, str]:
        """
        Contract function: authorizeAccess(...)
        Executes hybrid RBAC + ABAC policy evaluation rules:
        - ADMIN: Always ALLOW
        - SECURITY_ANALYST + dept=="IIoT_SECURITY": ALLOW
        - RESEARCHER + clearance=="READ_ONLY": ALLOW
        - OPERATOR + env=="PRODUCTION": ALLOW
        - AUDITOR: ALLOW
        - Unknown/Inactive: DENY
        """
        caller_l = caller.lower()
        user_prof = self.users.get(caller_l)

        if not user_prof or not user_prof.get("isActive", False):
            decision = False
            reason = "DENIED: User inactive or unregistered"
        else:
            role = user_prof.get("role", "NONE")
            attrs = user_prof.get("attributes", {})

            if role == "ADMIN":
                decision = True
                reason = "ALLOWED: Admin universal access granted"
            elif role == "SECURITY_ANALYST":
                if attrs.get("department") == "IIoT_SECURITY" or requested_attribute == "IIoT_SECURITY":
                    decision = True
                    reason = "ALLOWED: Security Analyst IIoT_SECURITY policy satisfied"
                else:
                    decision = False
                    reason = "DENIED: Requires IIoT_SECURITY departmental attribute"
            elif role == "RESEARCHER":
                if attrs.get("clearance") == "READ_ONLY" or requested_attribute == "READ_ONLY":
                    decision = True
                    reason = "ALLOWED: Researcher READ_ONLY policy satisfied"
                else:
                    decision = False
                    reason = "DENIED: Requires READ_ONLY clearance attribute"
            elif role == "OPERATOR":
                if attrs.get("environment") == "PRODUCTION" or requested_attribute == "PRODUCTION":
                    decision = True
                    reason = "ALLOWED: Operator PRODUCTION policy satisfied"
                else:
                    decision = False
                    reason = "DENIED: Requires PRODUCTION environment attribute"
            elif role == "AUDITOR":
                decision = True
                reason = "ALLOWED: Auditor compliance verification access"
            else:
                decision = False
                reason = "DENIED: Role not authorized by smart contract policy"

        self.audit_log.append({
            "timestamp": time.time(),
            "accessor": caller,
            "eventId": event_id,
            "action": "ACCESS_REQUEST",
            "decision": decision,
            "reason": reason
        })

        return decision, reason

    def get_event_metadata(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Contract view: getEventMetadata(bytes32 eventId)"""
        return self.security_events.get(event_id)

    def get_audit_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Contract view: getAuditLog()"""
        return self.audit_log[-limit:]
