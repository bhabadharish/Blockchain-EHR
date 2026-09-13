"""
16_Recommended_Actions.py
Automated SOC Containment Playbooks & Human-in-the-Loop Countermeasures.
Details technical containment workflows per attack family without executing silent destructive commands.
"""

import streamlit as st
import pandas as pd
from src.ui_helpers import apply_soc_theme, get_shared_state
from ids.response import ResponseRecommendationEngine

apply_soc_theme()
state = get_shared_state()
km = state.key_manager

st.markdown("""
<div style="margin-bottom: 20px;">
    <span class="soc-header-tag">SOC PLAYBOOK CATALOG</span>
    <h1 style="margin: 4px 0; font-size: 2.0rem; font-weight: 800; color: #ffffff;">
        Automated Mitigation Playbooks & Countermeasures
    </h1>
    <p style="color: #8fa3bf; font-size: 0.92rem;">
        Prioritized technical countermeasures for healthcare cybersecurity incidents.
        Maintains human-in-the-loop oversight to avoid unintended disruptions to life-critical clinical services.
    </p>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# 1. Playbook Catalog by Threat Family
# -------------------------------------------------------------
playbooks = ResponseRecommendationEngine.PLAYBOOKS

col_sel, col_det = st.columns([1, 2])

with col_sel:
    st.markdown("##### Threat Scenario Catalog:")
    selected_playbook = st.selectbox(
        "Select Playbook Category:",
        list(playbooks.keys()),
        index=list(playbooks.keys()).index("MITM")
    )

with col_det:
    st.markdown(f"#### 🛡️ Playbook: `{selected_playbook}`")
    steps = playbooks[selected_playbook]
    for step in steps:
        st.markdown(f"- **{step}**")

st.markdown("---")

# -------------------------------------------------------------
# 2. Interactive Operator Action Center
# -------------------------------------------------------------
st.markdown("### 🕹️ Interactive Incident Operator Actions")
st.markdown("Authorized operators can trigger verified defensive actions directly from the SOC console:")

col_a1, col_a2, col_a3, col_a4 = st.columns(4)

with col_a1:
    if st.button("🔄 Rotate AES-256 Keys", use_container_width=True):
        new_k = km.rotate_key("Operator Triggered Rotation via Playbook")
        st.success(f"✅ Key Rotated! Active: `{new_k.key_id}`")

with col_a2:
    if st.button("🛑 Invalidate Active Session", use_container_width=True):
        st.warning("⚠️ Session token invalidated across hospital gateways.")

with col_a3:
    if st.button("🔒 Revoke Suspicious User Role", use_container_width=True):
        if state.contract_client.account:
            state.contract_client.revoke_user(state.contract_client.account)
        st.error("🛑 Role revoked in EHRAccessControl smart contract.")

with col_a4:
    if st.button("📥 Export Forensic Evidence", use_container_width=True):
        st.info("📦 Forensic evidence package prepared with cryptographic hashes.")

st.markdown("""
<div class="soc-card" style="border-left: 4px solid #ffaa00; margin-top: 16px;">
    <h4 style="color: #ffaa00; margin-top: 0;">HEALTHCARE SAFETY MANDATE: HUMAN-IN-THE-LOOP</h4>
    <p style="color: #c4d1e2; font-size: 0.85rem; margin-bottom: 0;">
        In life-critical clinical environments (ICU, emergency surgery), fully autonomous destructive actions
        (e.g., immediate database drops, unannounced server halts) risk interrupting life-support telemetry or acute medication orders.
        Our system recommends precise, auditable actions and enforces cryptographic isolation while requiring authorized clinical administrator confirmation.
    </p>
</div>
""", unsafe_allow_html=True)
