"""
02_EHR_Data.py
EHR Data Center: MIMIC-III Clinical Database Exploration & Payload Selection.
Allows selecting MIMIC clinical tables, uploading custom EHR CSVs, or loading prepared demonstration records.
"""

import streamlit as st
import pandas as pd
from src.ui_helpers import apply_soc_theme, get_shared_state
from ehr.loader import MIMICLoader
from ehr.sanitizer import EHRSanitizer
from ehr.serializer import EHRSerializer
from ehr.payload import EHRPayload

apply_soc_theme()
state = get_shared_state()
loader: MIMICLoader = state.mimic_loader
sanitizer: EHRSanitizer = state.ehr_sanitizer

st.markdown("""
<div style="margin-bottom: 20px;">
    <span class="soc-header-tag">CLINICAL DATA CENTER</span>
    <h1 style="margin: 4px 0; font-size: 2.0rem; font-weight: 800; color: #ffffff;">
        MIMIC Clinical Data Explorer & Payload Ingestion
    </h1>
    <p style="color: #8fa3bf; font-size: 0.92rem;">
        Scientific Data Isolation: Real clinical data from MIMIC-III is used solely for EHR payload construction and privacy evaluation.
        Cyberattack labels originate strictly from Edge-IIoTset network telemetry.
    </p>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# 1. Selection Mode Tabs
# -------------------------------------------------------------
tab_mimic, tab_prepared, tab_upload = st.tabs([
    "🏥 Explore MIMIC-III Tables",
    "🧪 Prepared Demonstration Records",
    "📤 Upload Custom EHR CSV"
])

with tab_mimic:
    avail_tables = loader.get_available_tables()
    col_t1, col_t2 = st.columns([1, 2])
    with col_t1:
        st.markdown("**Select Clinical Table:**")
        selected_table = st.selectbox("MIMIC Table", avail_tables, index=avail_tables.index("LABEVENTS") if "LABEVENTS" in avail_tables else 0)
        
        show_abnormal = False
        if selected_table in ["LABEVENTS", "CHARTEVENTS"]:
            show_abnormal = st.checkbox("Filter Abnormal Findings (flag == 'abnormal')", value=True)

        sample_n = st.slider("Preview Record Count", 5, 50, 15)

    with col_t2:
        df_preview = loader.load_table(selected_table, nrows=sample_n * 4)
        if show_abnormal and "flag" in df_preview.columns:
            df_preview = df_preview[df_preview["flag"].astype(str).str.lower() == "abnormal"]

        st.markdown(f"**Data Preview: `{selected_table}` ({len(df_preview)} rows)**")
        st.dataframe(df_preview.head(sample_n), use_container_width=True)

    if not df_preview.empty:
        st.markdown("---")
        st.markdown("##### 📌 Ingest Selected Row as Active EHR Payload")
        row_idx = st.number_input("Select Row Index to Ingest", 0, min(len(df_preview) - 1, sample_n - 1), 0)
        
        if st.button("Set as Active Protected EHR Payload", type="primary"):
            raw_rec = df_preview.iloc[row_idx].to_dict()
            sanitized = sanitizer.sanitize_record(raw_rec)
            canon_bytes = EHRSerializer.to_canonical_json_bytes(sanitized["masked_data"])
            
            payload = EHRPayload(
                record_id=f"MIMIC-{selected_table}-{row_idx:04d}",
                patient_pseudonym=sanitized["pseudonym"],
                raw_record=raw_rec,
                masked_record=sanitized["masked_data"],
                sensitive_fields=sanitized["sensitive_fields"],
                privacy_risk=sanitized["exposure_analysis"]["risk_level"],
                canonical_bytes=canon_bytes
            )
            state.active_ehr_payload = payload
            st.success(f"✅ Ingested `{payload.record_id}` as Active EHR Payload!")

with tab_prepared:
    st.markdown("##### Prepared Clinical Demonstration Payloads")
    st.markdown("Standardized multi-parameter patient records representing realistic high-risk clinical events:")
    
    col_p1, col_p2, col_p3 = st.columns(3)
    
    with col_p1:
        st.markdown("""
        <div class="soc-card">
            <h4 style="color: #ff3b30; margin-top: 0;">Critical ICU Lab</h4>
            <p style="font-size: 0.8rem; color: #8fa3bf;">
                Patient in intensive care with acute diabetic ketoacidosis. Severe glucose and potassium elevation.
            </p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Load Critical ICU Lab", use_container_width=True):
            rec = loader.get_demo_record("CRITICAL_ICU_LAB")
            sanitized = sanitizer.sanitize_record(rec)
            canon_bytes = EHRSerializer.to_canonical_json_bytes(sanitized["masked_data"])
            payload = EHRPayload(
                record_id=rec["record_id"],
                patient_pseudonym=sanitized["pseudonym"],
                raw_record=rec,
                masked_record=sanitized["masked_data"],
                sensitive_fields=sanitized["sensitive_fields"],
                privacy_risk=sanitized["exposure_analysis"]["risk_level"],
                canonical_bytes=canon_bytes
            )
            state.active_ehr_payload = payload
            st.success("✅ Active EHR Payload set to: Critical ICU Lab")

    with col_p2:
        st.markdown("""
        <div class="soc-card">
            <h4 style="color: #ffaa00; margin-top: 0;">Cardiology Encounter</h4>
            <p style="font-size: 0.8rem; color: #8fa3bf;">
                Acute ST-elevation myocardial infarction with troponin spike and high dosage heparin prescription.
            </p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Load Cardiology Encounter", use_container_width=True):
            rec = loader.get_demo_record("CARDIOLOGY_ENCOUNTER")
            sanitized = sanitizer.sanitize_record(rec)
            canon_bytes = EHRSerializer.to_canonical_json_bytes(sanitized["masked_data"])
            payload = EHRPayload(
                record_id=rec["record_id"],
                patient_pseudonym=sanitized["pseudonym"],
                raw_record=rec,
                masked_record=sanitized["masked_data"],
                sensitive_fields=sanitized["sensitive_fields"],
                privacy_risk=sanitized["exposure_analysis"]["risk_level"],
                canonical_bytes=canon_bytes
            )
            state.active_ehr_payload = payload
            st.success("✅ Active EHR Payload set to: Cardiology Encounter")

    with col_p3:
        st.markdown("""
        <div class="soc-card">
            <h4 style="color: #00f0ff; margin-top: 0;">Neonatal ICU Record</h4>
            <p style="font-size: 0.8rem; color: #8fa3bf;">
                Preterm neonate monitoring with oxygen saturation, bilirubin measurements, and gestational age.
            </p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Load Neonatal Record", use_container_width=True):
            rec = loader.get_demo_record("NEONATAL_OBSERVATION")
            sanitized = sanitizer.sanitize_record(rec)
            canon_bytes = EHRSerializer.to_canonical_json_bytes(sanitized["masked_data"])
            payload = EHRPayload(
                record_id=rec["record_id"],
                patient_pseudonym=sanitized["pseudonym"],
                raw_record=rec,
                masked_record=sanitized["masked_data"],
                sensitive_fields=sanitized["sensitive_fields"],
                privacy_risk=sanitized["exposure_analysis"]["risk_level"],
                canonical_bytes=canon_bytes
            )
            state.active_ehr_payload = payload
            st.success("✅ Active EHR Payload set to: Neonatal Record")

with tab_upload:
    st.markdown("##### Upload External EHR File (CSV / JSON)")
    uploaded_file = st.file_uploader("Choose an EHR CSV or JSON file", type=["csv", "json"])
    if uploaded_file is not None:
        try:
            if uploaded_file.name.endswith(".csv"):
                up_df = pd.read_csv(uploaded_file)
            else:
                up_df = pd.read_json(uploaded_file)
            st.dataframe(up_df.head(10), use_container_width=True)
            if st.button("Ingest Uploaded File (Row 0) as Active Payload"):
                raw_rec = up_df.iloc[0].to_dict()
                sanitized = sanitizer.sanitize_record(raw_rec)
                canon_bytes = EHRSerializer.to_canonical_json_bytes(sanitized["masked_data"])
                payload = EHRPayload(
                    record_id=f"UPLOAD-{uploaded_file.name[:8]}",
                    patient_pseudonym=sanitized["pseudonym"],
                    raw_record=raw_rec,
                    masked_record=sanitized["masked_data"],
                    sensitive_fields=sanitized["sensitive_fields"],
                    privacy_risk=sanitized["exposure_analysis"]["risk_level"],
                    canonical_bytes=canon_bytes
                )
                state.active_ehr_payload = payload
                st.success(f"✅ Ingested `{payload.record_id}` from uploaded file!")
        except Exception as e:
            st.error(f"Error parsing uploaded file: {e}")

# -------------------------------------------------------------
# Active Payload Summary Card
# -------------------------------------------------------------
if state.active_ehr_payload:
    p = state.active_ehr_payload
    st.markdown("---")
    st.markdown("### 📋 Currently Ingested Active EHR Payload")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"**Payload ID:** `{p.record_id}`")
    with c2:
        st.markdown(f"**Pseudonym:** `{p.patient_pseudonym}`")
    with c3:
        st.markdown(f"**Privacy Risk:** `{p.privacy_risk}`")
    with c4:
        st.markdown(f"**Canonical Size:** `{len(p.canonical_bytes)} bytes`")
