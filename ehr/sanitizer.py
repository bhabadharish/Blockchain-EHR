"""
ehr/sanitizer.py
HIPAA Privacy Analyzer, Sensitive Field Detection, and Pseudonymization Module.
Evaluates plaintext exposure, quantifies privacy risks, and generates masked research records.
"""

import re
import hashlib
from typing import Dict, Any, List, Tuple


class EHRSanitizer:
    """Detects sensitive healthcare identifiers and provides privacy exposure metrics."""

    DIRECT_IDENTIFIERS = {
        "name", "patient_name", "ssn", "dod_ssn", "mrn", "phone", "email",
        "address", "zip", "zipcode", "physician_name"
    }

    QUASI_IDENTIFIERS = {
        "subject_id", "hadm_id", "dob", "dod", "admittime", "dischtime",
        "deathtime", "charttime", "gender", "ethnicity", "religion", "marital_status"
    }

    CLINICAL_SENSITIVE = {
        "valuenum", "value", "flag", "diagnosis", "icd9_code", "test_name",
        "prescription", "drug", "dose_val_rx", "procedure"
    }

    @classmethod
    def detect_sensitive_fields(cls, record: Dict[str, Any]) -> List[Dict[str, str]]:
        """Scans keys and values to classify HIPAA identifiers and clinical sensitive fields."""
        detected = []
        for k, v in record.items():
            kl = k.lower().strip()
            if kl in cls.DIRECT_IDENTIFIERS:
                detected.append({"field": k, "value": str(v), "category": "DIRECT_IDENTIFIER", "risk": "CRITICAL"})
            elif kl in cls.QUASI_IDENTIFIERS:
                detected.append({"field": k, "value": str(v), "category": "QUASI_IDENTIFIER", "risk": "HIGH"})
            elif kl in cls.CLINICAL_SENSITIVE:
                detected.append({"field": k, "value": str(v), "category": "CLINICAL_SENSITIVE", "risk": "HIGH"})
            else:
                detected.append({"field": k, "value": str(v), "category": "METADATA", "risk": "LOW"})
        return detected

    @classmethod
    def mask_record(cls, record: Dict[str, Any]) -> Dict[str, Any]:
        """Generates a masked/pseudonymized presentation copy of the record."""
        masked = {}
        for k, v in record.items():
            kl = k.lower().strip()
            if v is None:
                masked[k] = None
                continue

            v_str = str(v)
            if kl in ["subject_id", "hadm_id", "row_id"]:
                # Deterministic pseudonym
                h = hashlib.sha256(v_str.encode()).hexdigest()[:6].upper()
                masked[k] = f"PSN-{h}"
            elif kl in ["ssn", "dod_ssn"]:
                masked[k] = "***-**-****"
            elif kl in ["dob", "dod", "deathtime"]:
                # Year only
                masked[k] = v_str[:4] + "-**-**" if len(v_str) >= 4 else "****"
            elif kl in ["physician_id", "physician_name"]:
                masked[k] = "STAFF-ICU-***"
            else:
                masked[k] = v
        return masked

    @classmethod
    def calculate_privacy_exposure(cls, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates comprehensive privacy risk and entropy metrics prior to encryption.
        """
        fields = cls.detect_sensitive_fields(record)
        direct_cnt = sum(1 for f in fields if f["category"] == "DIRECT_IDENTIFIER")
        quasi_cnt = sum(1 for f in fields if f["category"] == "QUASI_IDENTIFIER")
        clinical_cnt = sum(1 for f in fields if f["category"] == "CLINICAL_SENSITIVE")
        total_fields = len(fields)

        # Raw exposure score: 0 to 100
        raw_score = (direct_cnt * 30.0 + quasi_cnt * 15.0 + clinical_cnt * 10.0)
        exposure_score = min(100.0, raw_score)

        if exposure_score >= 70.0 or direct_cnt > 0:
            risk_tier = "CRITICAL (Severe HIPAA Exposure)"
        elif exposure_score >= 45.0:
            risk_tier = "HIGH (Sensitive Quasi-Identifiers Visible)"
        elif exposure_score >= 25.0:
            risk_tier = "MODERATE (Limited Clinical Attributes)"
        else:
            risk_tier = "LOW"

        return {
            "total_fields": total_fields,
            "direct_identifiers_count": direct_cnt,
            "quasi_identifiers_count": quasi_cnt,
            "clinical_sensitive_count": clinical_cnt,
            "metadata_count": total_fields - (direct_cnt + quasi_cnt + clinical_cnt),
            "privacy_exposure_score": round(exposure_score, 1),
            "risk_tier": risk_tier,
            "risk_level": "HIGH" if (direct_cnt > 0 or exposure_score >= 50.0) else ("MEDIUM" if exposure_score >= 25.0 else "LOW"),
            "sensitive_field_count": direct_cnt + quasi_cnt + clinical_cnt,
            "direct_identifiers_present": direct_cnt > 0,
            "quasi_identifiers_present": quasi_cnt,
            "field_classifications": fields
        }

    def sanitize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Unified sanitizer pipeline returning masked copy, pseudonym, and exposure report."""
        masked = self.mask_record(record)
        exposure = self.calculate_privacy_exposure(record)
        
        # Generate stable pseudonym
        sid = str(record.get("subject_id", record.get("record_id", "ANON")))
        pseudonym = f"PATIENT-{hashlib.sha256(sid.encode()).hexdigest()[:6].upper()}"
        
        sensitive_fields = [
            f["field"] for f in exposure["field_classifications"]
            if f["category"] in ["DIRECT_IDENTIFIER", "QUASI_IDENTIFIER", "CLINICAL_SENSITIVE"]
        ]
        
        return {
            "pseudonym": pseudonym,
            "masked_data": masked,
            "sensitive_fields": sensitive_fields,
            "exposure_analysis": exposure
        }
