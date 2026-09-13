"""
ehr/payload.py
EHR Payload Container & Lifecycle Management.
Encapsulates clinical data, privacy exposure assessment, cryptographic representations,
and blockchain metadata anchoring.
"""

import time
import hashlib
from typing import Dict, Any, Optional, Union, List
import pandas as pd
from ehr.sanitizer import EHRSanitizer
from ehr.serializer import EHRSerializer


class EHRPayload:
    """Encapsulates an EHR record through preparation, exposure analysis, encryption, and anchoring."""

    def __init__(
        self,
        record_id: str,
        raw_data: Optional[Union[Dict[str, Any], pd.DataFrame, str]] = None,
        source_type: str = "MIMIC-III",
        patient_pseudonym: Optional[str] = None,
        raw_record: Optional[Dict[str, Any]] = None,
        masked_record: Optional[Dict[str, Any]] = None,
        sensitive_fields: Optional[List[str]] = None,
        privacy_risk: Optional[str] = None,
        canonical_bytes: Optional[bytes] = None,
        **kwargs
    ):
        self.record_id = record_id
        self.source_type = source_type
        self.created_at = time.time()
        self.patient_pseudonym = patient_pseudonym or f"PATIENT-{hashlib.sha256(record_id.encode()).hexdigest()[:6].upper()}"

        # Resolve raw data
        actual_raw = raw_data if raw_data is not None else (raw_record if raw_record is not None else {})
        self.raw_data = actual_raw
        self.raw_record = actual_raw if isinstance(actual_raw, dict) else {}

        # Masked record
        if masked_record is not None:
            self.sanitized_data = masked_record
            self.masked_record = masked_record
        elif isinstance(actual_raw, dict):
            self.sanitized_data = EHRSanitizer.mask_record(actual_raw)
            self.masked_record = self.sanitized_data
        else:
            self.sanitized_data = {}
            self.masked_record = {}

        self.sensitive_fields = sensitive_fields or []
        self.privacy_risk = privacy_risk or "HIGH"

        if isinstance(actual_raw, dict):
            self.privacy_metrics = EHRSanitizer.calculate_privacy_exposure(actual_raw)
        else:
            self.privacy_metrics = {"privacy_exposure_score": 75.0, "risk_tier": self.privacy_risk}

        # Canonical bytes and entropy
        if canonical_bytes is not None:
            self.plaintext_bytes = canonical_bytes
            self.canonical_bytes = canonical_bytes
        else:
            self.plaintext_bytes = EHRSerializer.to_canonical_bytes(self.raw_data)
            self.canonical_bytes = self.plaintext_bytes

        self.plaintext_size = len(self.plaintext_bytes)
        self.plaintext_entropy = EHRSerializer.calculate_shannon_entropy(self.plaintext_bytes)

        # Cryptographic SHA-256 Hash
        self.payload_hash = hashlib.sha256(self.plaintext_bytes).hexdigest()
        self.sha256_hash = self.payload_hash
        self.encrypted_ciphertext: Optional[bytes] = None

        # Encryption and Blockchain Metadata State
        self.encryption_receipt: Optional[Dict[str, Any]] = None
        self.blockchain_anchor: Optional[Dict[str, Any]] = None

    @classmethod
    def from_record(cls, record: Dict[str, Any], record_id: Optional[str] = None) -> "EHRPayload":
        rid = record_id or str(record.get("record_id", f"EHR-{int(time.time() * 1000) % 1000000}"))
        return cls(record_id=rid, raw_data=record, source_type="MIMIC-III")

    @classmethod
    def from_dataframe(cls, df: pd.DataFrame, table_name: str = "LABEVENTS") -> "EHRPayload":
        rid = f"EHR-TABLE-{table_name.upper()}-{len(df)}ROWS"
        return cls(record_id=rid, raw_data=df, source_type=f"MIMIC-III ({table_name})")

    def attach_encryption_receipt(self, receipt: Dict[str, Any]):
        """Binds encryption metadata (algorithm, ciphertext, nonce, tag, expansion)."""
        self.encryption_receipt = receipt

    def attach_blockchain_anchor(self, anchor: Dict[str, Any]):
        """Binds on-chain anchoring metadata (block number, tx hash, timestamp)."""
        self.blockchain_anchor = anchor

    def to_summary_dict(self) -> Dict[str, Any]:
        """Returns JSON-serializable summary for dashboard display."""
        res = {
            "record_id": self.record_id,
            "source_type": self.source_type,
            "plaintext_size_bytes": self.plaintext_size,
            "plaintext_entropy": self.plaintext_entropy,
            "payload_hash": self.payload_hash,
            "privacy_exposure_score": self.privacy_metrics.get("privacy_exposure_score", 0.0),
            "privacy_risk_tier": self.privacy_metrics.get("risk_tier", "UNKNOWN"),
            "is_encrypted": self.encryption_receipt is not None,
            "is_anchored": self.blockchain_anchor is not None
        }
        if self.encryption_receipt:
            res["algorithm"] = self.encryption_receipt.get("algorithm")
            res["ciphertext_size_bytes"] = self.encryption_receipt.get("ciphertext_size")
            res["ciphertext_entropy"] = self.encryption_receipt.get("ciphertext_entropy")
        if self.blockchain_anchor:
            res["block_number"] = self.blockchain_anchor.get("block_number")
            res["tx_hash"] = self.blockchain_anchor.get("tx_hash")
        return res
