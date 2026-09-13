"""
03_Phase1_Before_Encryption.py
PHASE 1 — EHR BEFORE ENCRYPTION & PRIVACY EXPOSURE ANALYSIS.
Calculates HIPAA Safe Harbor exposure, identifier disclosure risk, and Shannon entropy on unencrypted plaintext.
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from src.ui_helpers import apply_soc_theme, get_shared_state
from ehr.sanitizer import EHRSanitizer
from ehr.serializer import EHRSerializer

apply_soc_theme()
state = get_shared_state()
payload = state.active_ehr_payload

st.markdown("""
<div style="margin-bottom: 20px;">
    <span class="soc-header-tag" style="background: rgba(255, 170, 0, 0.15); color: #ffaa00; border-color: #ffaa00;">
        PHASE 1 — PRIVACY ASSESSMENT
    </span>
    <h1 style="margin: 4px 0; font-size: 2.0rem; font-weight: 800; color: #ffffff;">
        EHR Plaintext & Privacy Exposure Analysis
    </h1>
    <p style="color: #8fa3bf; font-size: 0.92rem;">
        Detailed audit of unencrypted medical payload structure, HIPAA identifier exposure, and baseline privacy metrics.
    </p>
</div>
""", unsafe_allow_html=True)

# Warning Banner
st.warning("⚠️ **PLAINTEXT / ORIGINAL EHR REPRESENTATION DETECTED** — All patient metadata, timestamps, and clinical variables are currently in readable form. Immediate cryptographic encapsulation is required prior to network transmission.")

if not payload:
    st.error("No active EHR payload loaded. Please select one from the EHR Data Center.")
    st.stop()

# -------------------------------------------------------------
# 1. Plaintext Structure & Metrics Overview
# -------------------------------------------------------------
raw_dict = payload.raw_record
masked_dict = payload.masked_record
sanitizer = state.ehr_sanitizer
exposure = sanitizer.sanitize_record(raw_dict)["exposure_analysis"]
entropy = EHRSerializer.compute_entropy(payload.canonical_bytes)

col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Payload Size</div>
        <div class="kpi-value">{len(payload.canonical_bytes)} <span style="font-size: 0.9rem; font-weight: 400;">bytes</span></div>
        <div class="kpi-delta" style="color: #8fa3bf;">UTF-8 Plaintext</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Total Fields Exposed</div>
        <div class="kpi-value">{len(raw_dict)}</div>
        <div class="kpi-delta" style="color: #ffaa00;">100% Readable</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Sensitive Fields</div>
        <div class="kpi-value" style="color: #ff3b30;">{exposure['sensitive_field_count']}</div>
        <div class="kpi-delta" style="color: #ff3b30;">HIPAA Quasi-Identifiers</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Shannon Entropy</div>
        <div class="kpi-value">{entropy:.2f} <span style="font-size: 0.9rem; font-weight: 400;">/ 8.0</span></div>
        <div class="kpi-delta" style="color: #00f0ff;">Structured Plaintext</div>
    </div>
    """, unsafe_allow_html=True)

with col5:
    risk_color = "#ff3b30" if exposure['risk_level'] == "HIGH" else "#ffaa00"
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Exposure Risk</div>
        <div class="kpi-value" style="color: {risk_color};">{exposure['risk_level']}</div>
        <div class="kpi-delta" style="color: {risk_color};">Score: {exposure['privacy_exposure_score']}/100</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# -------------------------------------------------------------
# 2. Before-Encryption Visual Comparison Grid
# -------------------------------------------------------------
col_v1, col_v2 = st.columns(2)

with col_v1:
    st.markdown("#### 🔍 Plaintext Field Inspection (Masked Identifiers)")
    st.markdown("Direct patient identifiers (SSN, medical record number) are masked with cryptographic pseudonyms to prevent identity disclosure in the UI:")
    df_fields = pd.DataFrame([
        {"Field": k, "Plaintext Value": str(v), "Type": "Direct Identifier" if "id" in k.lower() else ("Clinical Variable" if any(c in k.lower() for c in ["val", "label", "diag", "dose"]) else "Metadata")}
        for k, v in masked_dict.items()
    ])
    st.dataframe(df_fields, use_container_width=True, height=320)

with col_v2:
    st.markdown("#### 🚨 Privacy Risk Breakdown (HIPAA Safe Harbor)")
    
    # Radar chart / Bar chart for Privacy Exposure
    categories = ["Direct ID Risk", "Quasi-ID Exposure", "Clinical Data Leak", "Timestamp Exposure", "Entropy Vulnerability"]
    scores = [
        95.0 if exposure['direct_identifiers_present'] else 20.0,
        min(100.0, exposure['quasi_identifiers_present'] * 30.0),
        min(100.0, exposure['sensitive_field_count'] * 20.0),
        85.0 if any("charttime" in k.lower() or "dob" in k.lower() for k in raw_dict) else 15.0,
        round((entropy / 8.0) * 100.0, 1)
    ]

    fig = go.Figure(data=go.Scatterpolar(
        r=scores,
        theta=categories,
        fill='toself',
        fillcolor='rgba(255, 59, 48, 0.25)',
        line=dict(color='#ff3b30', width=2)
    ))
    fig.update_layout(
        polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
        showlegend=False,
        template="plotly_dark",
        margin=dict(l=40, r=40, b=30, t=30),
        height=320
    )
    st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# -------------------------------------------------------------
# 3. Privacy Exposure Synthesis Box (Section 3 Visual)
# -------------------------------------------------------------
st.markdown("""
<div class="soc-card" style="border: 1px solid rgba(255, 170, 0, 0.3);">
    <h4 style="color: #ffaa00; margin-top: 0;">STATE BEFORE ENCRYPTION: UNPROTECTED TRANSMISSION RISK</h4>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; font-size: 0.88rem; color: #c4d1e2;">
        <div>
            <b>What an eavesdropper / passive attacker can read:</b>
            <ul style="color: #ff3b30; margin-top: 6px;">
                <li>Patient medical record numbers and ICU admission pseudonyms</li>
                <li>Critical diagnostic lab values (e.g. Glucose, Troponin, Potassium)</li>
                <li>Exact event timestamps, medication dosages, and caregiver codes</li>
                <li>Diagnostic ICD-9 / ICD-10 medical condition classifications</li>
            </ul>
        </div>
        <div>
            <b>Integrity & Tamper Vulnerabilities:</b>
            <ul style="color: #ffaa00; margin-top: 6px;">
                <li>No cryptographic authentication tag: data can be modified undetected</li>
                <li>No blockchain hash anchoring: sender can repudiate clinical orders</li>
                <li>No replay protection: valid transactions can be maliciously duplicated</li>
                <li>Access control is application-level only: zero defense-in-depth</li>
            </ul>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)
