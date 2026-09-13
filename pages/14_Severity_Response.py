"""
14_Severity_Response.py
Transparent Severity & Risk Scoring Engine & SOC Playbook Integration.
Demonstrates multi-signal threat severity determination and automated countermeasure mapping.
"""

import streamlit as st
import pandas as pd
from src.ui_helpers import apply_soc_theme, get_shared_state
from ids.risk import RiskScoringEngine
from ids.severity import SeverityEngine
from ids.response import ResponseRecommendationEngine

apply_soc_theme()
state = get_shared_state()

st.markdown("""
<div style="margin-bottom: 20px;">
    <span class="soc-header-tag">THREAT TRIAGE & MITIGATION</span>
    <h1 style="margin: 4px 0; font-size: 2.0rem; font-weight: 800; color: #ffffff;">
        Severity Scoring Engine & SOC Response Playbooks
    </h1>
    <p style="color: #8fa3bf; font-size: 0.92rem;">
        Transparent, rule-based security scoring. Threat severity is never determined by machine learning confidence alone;
        it correlates cryptographic integrity, access privileges, and clinical data sensitivity.
    </p>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# 1. Transparent Rule Evaluation Table
# -------------------------------------------------------------
st.markdown("### 📜 Transparent Severity Rule Table")

rules_df = pd.DataFrame([
    {"Rule ID": "RULE_CRIT_01", "Trigger Conditions": "Cryptographic hash mismatch + Unauthorized access attempt", "Assigned Severity": "CRITICAL 🛑", "Rationale": "Active tampering of ciphertext by an unauthorized entity."},
    {"Rule ID": "RULE_CRIT_02", "Trigger Conditions": "Cryptographic payload integrity failure alone", "Assigned Severity": "CRITICAL 🛑", "Rationale": "Payload modified in storage or transmission; corrupted clinical data."},
    {"Rule ID": "RULE_CRIT_03", "Trigger Conditions": "Ransomware / Backdoor detected with confidence >= 85%", "Assigned Severity": "CRITICAL 🛑", "Rationale": "Host infection threatens master key storage and clinical databases."},
    {"Rule ID": "RULE_HIGH_01", "Trigger Conditions": "MITM attack telemetry detected with confidence >= 80%", "Assigned Severity": "HIGH 🟠", "Rationale": "Communication channel compromised; immediate session key rotation required."},
    {"Rule ID": "RULE_HIGH_02", "Trigger Conditions": "SQL Injection or Web API exploit with confidence >= 80%", "Assigned Severity": "HIGH 🟠", "Rationale": "Host clinical query interface under exploit attempt."},
    {"Rule ID": "RULE_HIGH_03", "Trigger Conditions": "DDoS flood telemetry detected with confidence >= 85%", "Assigned Severity": "HIGH 🟠", "Rationale": "Perimeter network flood threatens hospital gateway availability."},
    {"Rule ID": "RULE_HIGH_04", "Trigger Conditions": "Repeated unauthorized access attempts >= 3", "Assigned Severity": "HIGH 🟠", "Rationale": "Credential brute-force attack against smart contract gateway."},
    {"Rule ID": "RULE_MED_01", "Trigger Conditions": "Port Scanning / Vulnerability Scanner telemetry", "Assigned Severity": "MEDIUM 🟡", "Rationale": "Perimeter reconnaissance probing for open ports."},
    {"Rule ID": "RULE_LOW_01", "Trigger Conditions": "Passive Fingerprinting telemetry or sub-threshold anomaly", "Assigned Severity": "LOW 🔵", "Rationale": "Benign banner grabbing or low-confidence anomaly; logged for SOC audit."},
    {"Rule ID": "RULE_SEC_01", "Trigger Conditions": "Normal telemetry + Valid on-chain hash match", "Assigned Severity": "SECURE 🟢", "Rationale": "Legitimate transaction with intact cryptographic integrity."}
])

st.dataframe(rules_df, use_container_width=True, hide_index=True)

st.markdown("---")

# -------------------------------------------------------------
# 2. Interactive Multi-Factor Threat Triage Simulator
# -------------------------------------------------------------
st.markdown("### 🎛️ Interactive Threat Severity & Risk Simulator")

col_i1, col_i2 = st.columns(2)

with col_i1:
    sim_attack = st.selectbox("Simulated Intrusion Class", [
        "Normal", "MITM", "DDoS_HTTP", "DDoS_TCP", "SQL_injection",
        "Ransomware", "Backdoor", "Password", "Port_Scanning", "Fingerprinting"
    ])
    sim_conf = st.slider("Model Prediction Confidence (%)", 10.0, 100.0, 95.0)
    sim_hash_fail = st.checkbox("Cryptographic Hash Mismatch (Integrity Failure)", value=False)
    sim_unauth = st.checkbox("Unauthorized Access Attempt (RBAC Rejection)", value=False)

with col_i2:
    sim_reps = st.slider("Repeated Access Attempts", 1, 10, 1)
    sim_sens = st.slider("Sensitive HIPAA Fields in Target Payload", 0, 15, 6)
    sim_role = st.selectbox("Accessor Role", ["DOCTOR", "ADMIN", "NURSE", "ANONYMOUS"])
    sim_avail = st.checkbox("Gateway Availability Impaired (High Bandwidth Load)", value=("DDoS" in sim_attack))

# Compute Risk and Severity live
sim_risk = RiskScoringEngine.calculate_risk(
    attack_type=sim_attack,
    confidence_pct=sim_conf,
    integrity_failed=sim_hash_fail,
    unauthorized_access=sim_unauth,
    repeated_attempts=sim_reps,
    sensitive_field_count=sim_sens,
    accessor_role=sim_role,
    availability_impact=sim_avail
)

sim_sev = SeverityEngine.evaluate(
    attack_type=sim_attack,
    confidence_pct=sim_conf,
    risk_score=sim_risk["risk_score"],
    integrity_failed=sim_hash_fail,
    unauthorized_access=sim_unauth,
    repeated_attempts=sim_reps,
    sensitive_fields=sim_sens
)

actions = ResponseRecommendationEngine.get_recommendations(
    attack_type=sim_attack,
    integrity_failed=sim_hash_fail,
    unauthorized_access=sim_unauth
)

st.markdown("---")

# -------------------------------------------------------------
# 3. Dynamic Evaluation Result Card
# -------------------------------------------------------------
st.markdown("### 🔍 Computed Triage Assessment")

r1, r2, r3 = st.columns(3)
with r1:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Calculated Risk Score</div>
        <div class="kpi-value" style="color: {sim_sev['color']};">{sim_risk['risk_score']} <span style="font-size: 0.9rem;">/ 100</span></div>
        <div class="kpi-delta" style="color: #8fa3bf;">Formula: Attack+Integrity+Access+Sens+Impact</div>
    </div>
    """, unsafe_allow_html=True)

with r2:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Assigned Severity</div>
        <div class="kpi-value" style="color: {sim_sev['color']};">{sim_sev['severity']}</div>
        <div class="kpi-delta" style="color: {sim_sev['color']};">{sim_sev['all_rules'][0]}</div>
    </div>
    """, unsafe_allow_html=True)

with r3:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Isolation Mandate</div>
        <div class="kpi-value" style="color: {'#ff3b30' if sim_sev['requires_immediate_isolation'] else '#00ff88'};">
            {'REQUIRED 🚨' if sim_sev['requires_immediate_isolation'] else 'STANDBY 🛡️'}
        </div>
        <div class="kpi-delta" style="color: #8fa3bf;">Automated SOC Containment</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div style="background: rgba(0, 240, 255, 0.08); border: 1px solid #00f0ff; border-radius: 8px; padding: 10px 14px; margin: 12px 0;">
        <b style="color: #00f0ff;">🛡️ Cryptographic Security Guarantee:</b>
        <span style="color: #c4d1e2; font-size: 0.86rem;">
            Even under elevated threat severity (<b>{sim_sev['severity']}</b>), the underlying clinical EHR payload remains 100% saved and confidential via AES-256-GCM encryption.
            The IDS flags the surrounding network hostility while authenticated cryptography prevents unauthorized medical plaintext disclosure.
        </span>
    </div>
    """, unsafe_allow_html=True)

st.markdown("#### 🛠️ Recommended SOC Playbook Actions:")
for a in actions:
    st.markdown(f"- **{a}**")
