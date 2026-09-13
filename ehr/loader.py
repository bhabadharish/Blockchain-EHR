"""
ehr/loader.py
MIMIC-III / MIMIC-IV Clinical EHR Data Loader.
Discovers, parses, and provides realistic healthcare payloads from actual MIMIC tables
(LABEVENTS, CHARTEVENTS, PRESCRIPTIONS, ADMISSIONS, DIAGNOSES_ICD, PATIENTS).
"""

import os
import glob
import pandas as pd
from typing import Dict, Any, List, Optional, Tuple


class MIMICLoader:
    """Discovers and loads real-world MIMIC clinical records for privacy preservation demonstrations."""

    DEFAULT_SEARCH_PATHS = [
        "data/mimic/mimic-iii-clinical-database-demo-1.4",
        "data/mimic",
        "data/raw/mimic-iii-clinical-database-demo-1.4",
        "data/raw"
    ]

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = self._resolve_base_dir(base_dir)
        self._table_cache: Dict[str, pd.DataFrame] = {}

    def _resolve_base_dir(self, user_path: Optional[str]) -> str:
        if user_path and os.path.isdir(user_path):
            return user_path
        for p in self.DEFAULT_SEARCH_PATHS:
            if os.path.isdir(p) and len(glob.glob(os.path.join(p, "*.csv"))) > 0:
                return p
        # Fallback to current data/mimic
        return "data/mimic"

    def list_available_tables(self) -> List[Dict[str, Any]]:
        """Scans directory and returns inventory of available MIMIC tables."""
        if not os.path.exists(self.base_dir):
            return []
        
        tables = []
        csv_files = sorted(glob.glob(os.path.join(self.base_dir, "*.csv")))
        for cf in csv_files:
            fname = os.path.basename(cf)
            tname = fname.replace(".csv", "")
            sz = os.path.getsize(cf)
            tables.append({
                "table_name": tname,
                "file_name": fname,
                "file_path": cf,
                "size_bytes": sz,
                "size_mb": round(sz / (1024 * 1024), 2)
            })
        return tables

    def get_available_tables(self) -> List[str]:
        """Returns simple list of discovered table names."""
        return [t["table_name"] for t in self.list_available_tables()]

    def load_table(self, table_name: str, nrows: Optional[int] = None) -> pd.DataFrame:
        """Loads a specific MIMIC table as a pandas DataFrame."""
        clean_name = table_name.replace(".csv", "").upper()
        target_path = os.path.join(self.base_dir, f"{clean_name}.csv")
        if not os.path.exists(target_path):
            # Check lowercase
            alt_path = os.path.join(self.base_dir, f"{clean_name.lower()}.csv")
            if os.path.exists(alt_path):
                target_path = alt_path
            else:
                raise FileNotFoundError(f"MIMIC table '{clean_name}' not found in {self.base_dir}")

        cache_key = f"{clean_name}_{nrows}"
        if cache_key in self._table_cache:
            return self._table_cache[cache_key]

        df = pd.read_csv(target_path, nrows=nrows)
        if nrows is not None and nrows <= 500:
            self._table_cache[cache_key] = df
        return df

    def get_abnormal_lab_events(self, limit: int = 50) -> pd.DataFrame:
        """
        Extracts clinically significant abnormal laboratory events from LABEVENTS.csv
        joined with D_LABITEMS.csv for human-readable test names.
        """
        labs_df = self.load_table("LABEVENTS", nrows=5000)
        # Filter for abnormal flags
        if "flag" in labs_df.columns:
            abnormal = labs_df[labs_df["flag"].astype(str).str.lower() == "abnormal"].copy()
        else:
            abnormal = labs_df.dropna(subset=["valuenum"]).copy()

        # Try to map itemid to test name
        try:
            items_df = self.load_table("D_LABITEMS", nrows=1000)
            id_map = dict(zip(items_df["itemid"], items_df["label"]))
            abnormal["test_name"] = abnormal["itemid"].map(id_map).fillna("Unknown Clinical Assay")
        except Exception:
            abnormal["test_name"] = "Clinical Assay #" + abnormal["itemid"].astype(str)

        return abnormal.head(limit)

    def get_patient_summary(self, subject_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Constructs a comprehensive patient clinical summary across ADMISSIONS, DIAGNOSES, and LABS.
        """
        patients_df = self.load_table("PATIENTS", nrows=50)
        if subject_id is None:
            subject_id = int(patients_df.iloc[0]["subject_id"])

        p_row = patients_df[patients_df["subject_id"] == subject_id]
        if p_row.empty:
            p_row = patients_df.iloc[0]
            subject_id = int(p_row["subject_id"])
        else:
            p_row = p_row.iloc[0]

        # Admissions
        try:
            adm_df = self.load_table("ADMISSIONS", nrows=500)
            adms = adm_df[adm_df["subject_id"] == subject_id].to_dict(orient="records")
        except Exception:
            adms = []

        # Abnormal Labs
        try:
            ab_labs = self.get_abnormal_lab_events(limit=100)
            p_labs = ab_labs[ab_labs["subject_id"] == subject_id].to_dict(orient="records")
            if not p_labs:
                p_labs = ab_labs.head(5).to_dict(orient="records")
        except Exception:
            p_labs = []

        return {
            "subject_id": subject_id,
            "gender": str(p_row.get("gender", "U")),
            "dob": str(p_row.get("dob", "1960-01-01")),
            "expire_flag": int(p_row.get("expire_flag", 0)),
            "admissions_count": len(adms),
            "admissions": adms[:3],
            "abnormal_labs": p_labs[:5]
        }

    def get_demo_records(self) -> List[Dict[str, Any]]:
        """Returns 5 prepared representative clinical demonstration records."""
        ab_labs = self.get_abnormal_lab_events(limit=10)
        records = []
        for i, row in ab_labs.head(5).iterrows():
            records.append({
                "record_id": f"EHR-LAB-{int(row.get('row_id', 1000+i))}",
                "subject_id": int(row.get("subject_id", 10000)),
                "hadm_id": int(row.get("hadm_id", 100000)) if pd.notna(row.get("hadm_id")) else None,
                "test_name": str(row.get("test_name", "Clinical Assay")),
                "valuenum": float(row.get("valuenum", 0.0)) if pd.notna(row.get("valuenum")) else None,
                "valueuom": str(row.get("valueuom", "mg/dL")),
                "flag": str(row.get("flag", "abnormal")),
                "charttime": str(row.get("charttime", "2150-01-01 12:00:00")),
                "department": "Critical Care ICU",
                "physician_id": f"MD-{100 + (i % 7)}"
            })
        return records

    def get_demo_record(self, record_type: str = "CRITICAL_ICU_LAB") -> Dict[str, Any]:
        """Returns a specific prepared clinical demonstration record."""
        demos = {
            "CRITICAL_ICU_LAB": {
                "record_id": "MIMIC-ICU-CRIT-001",
                "subject_id": 10014,
                "hadm_id": 150242,
                "test_name": "Glucose (Serum/Plasma)",
                "label": "Glucose",
                "valuenum": 195.0,
                "valueuom": "mg/dL",
                "flag": "abnormal",
                "department": "Intensive Care Unit (ICU)",
                "charttime": "2154-04-12 08:30:00",
                "physician_id": "MD-4092",
                "diagnosis": "Diabetic Ketoacidosis / Severe Hyperglycemia"
            },
            "CARDIOLOGY_ENCOUNTER": {
                "record_id": "MIMIC-CARDIO-002",
                "subject_id": 10028,
                "hadm_id": 160384,
                "test_name": "Troponin T",
                "label": "Troponin T",
                "valuenum": 1.45,
                "valueuom": "ng/mL",
                "flag": "abnormal",
                "department": "Cardiology / CCU",
                "charttime": "2153-11-09 14:15:00",
                "physician_id": "MD-3108",
                "diagnosis": "Acute ST-Elevation Myocardial Infarction"
            },
            "NEONATAL_OBSERVATION": {
                "record_id": "MIMIC-NICU-003",
                "subject_id": 10052,
                "hadm_id": 178910,
                "test_name": "Bilirubin, Total",
                "label": "Bilirubin",
                "valuenum": 14.8,
                "valueuom": "mg/dL",
                "flag": "abnormal",
                "department": "Neonatal Intensive Care (NICU)",
                "charttime": "2152-07-22 19:45:00",
                "physician_id": "MD-2184",
                "diagnosis": "Neonatal Hyperbilirubinemia / Preterm Infant"
            }
        }
        if record_type in demos:
            return demos[record_type]
        all_recs = self.get_demo_records()
        return all_recs[0] if all_recs else demos["CRITICAL_ICU_LAB"]
