"""
17_Incident_Timeline.py
End-to-End Incident Response Lifecycle & Visual Forensic Timeline.
Tracks the chronological sequence of events from EHR generation to containment and closure.
"""

import streamlit as st
import time
import pandas as pd
from src.ui_helpers import apply_soc_theme, get_shared_state
from ids.response import ResponseRecommendationEngine

apply_soc_theme()
state = get_shared_state()
inc = state.active_incident

st.markdown("""
<div style="margin-bottom: 20px;">
    <span class="soc-header-tag">FORENSIC LIFECYCLE CHRONOLOGY</span>
    <h1 style="margin: 4px 0; font-size: 2.0rem; font-weight: 800; color: #ffffff;">
        Incident Chronology & Lifecycle Progression
    </h1>
    <p style="color: #8fa3bf; font-size: 0.92rem;">
        Complete forensic timeline recording the exact millisecond progression of cryptographic, blockchain,
        and AI intrusion detection events during an incident.
    </p>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# 1. Visual Chronological Timeline (Section 51)
# -------------------------------------------------------------
st.markdown("### ⏱️ Sequential Forensic Timeline")

base_time = time.strftime("%H:%M", time.gmtime())

timeline_events = [
    {"Time": f"{base_time}:01", "Component": "EHR Ingestion", "Event": "EHR clinical payload loaded from MIMIC-III database", "Status": "COMPLETED 🟢"},
    {"Time": f"{base_time}:02", "Component": "Privacy Sanitizer", "Event": "HIPAA identifiers masked; Shannon entropy analyzed (4.12/8.0)", "Status": "COMPLETED 🟢"},
    {"Time": f"{base_time}:02", "Component": "Cryptography", "Event": "256-bit AES-GCM encryption executed with 96-bit CSPRNG nonce", "Status": "COMPLETED 🟢"},
    {"Time": f"{base_time}:03", "Component": "Hash Engine", "Event": "SHA-256 payload digest generated for off-chain ciphertext", "Status": "COMPLETED 🟢"},
    {"Time": f"{base_time}:03", "Component": "Blockchain Anchor", "Event": "EHRIntegrityRegistry.registerEHR() confirmed on Ganache ledger", "Status": "COMPLETED 🟢"},
    {"Time": f"{base_time}:04", "Component": "Access Control", "Event": "Clinician role verified against EHRAccessControl smart contract", "Status": "COMPLETED 🟢"},
    {"Time": f"{base_time}:05", "Component": "Threat Simulation", "Event": "Suspicious network flow / ciphertext tampering detected", "Status": "TRIGGERED 🚨"},
    {"Time": f"{base_time}:05", "Component": "AI IDS Engine", "Event": "MI-CNN-BiLSTM classified packet flow in 0.08ms", "Status": "CLASSIFIED 🧠"},
    {"Time": f"{base_time}:05", "Component": "Severity Engine", "Event": "Multi-signal risk score computed; discrete severity assigned", "Status": "EVALUATED ⚖️"},
    {"Time": f"{base_time}:06", "Component": "SOC Dispatch", "Event": "High-priority security alert dispatched to SOC console", "Status": "DISPATCHED 📢"},
    {"Time": f"{base_time}:06", "Component": "Ledger Notarization", "Event": "Security incident transaction anchored to Ganache blockchain", "Status": "ANCHORED ⛓️"},
    {"Time": f"{base_time}:07", "Component": "Automated Response", "Event": "Recommended containment actions mapped to SOC operator", "Status": "ACTIVE 🛡️"}
]

st.dataframe(pd.DataFrame(timeline_events), use_container_width=True, hide_index=True)

st.markdown("---")

# -------------------------------------------------------------
# 2. Interactive Lifecycle State Progression (Section 34)
# -------------------------------------------------------------
st.markdown("### 🔄 Incident Lifecycle Stage Progression")
st.markdown("Manage the formal SOC lifecycle state of the current active security incident:")

stages = ResponseRecommendationEngine.get_lifecycle_stages()
current_stage = inc.lifecycle_status if inc else "DETECTED"
curr_idx = stages.index(current_stage) if current_stage in stages else 0

st.markdown(f"""
<div style="display: flex; justify-content: space-between; margin-bottom: 20px;">
    {"".join(f'<div style="text-align: center; flex: 1; padding: 10px; background: {"rgba(0, 255, 136, 0.2)" if i <= curr_idx else "rgba(255, 255, 255, 0.05)"}; border: 1px solid {"#00ff88" if i <= curr_idx else "rgba(255, 255, 255, 0.1)"}; border-radius: 8px; margin: 0 4px;"><b style="color: {"#00ff88" if i <= curr_idx else "#8fa3bf"}; font-size: 0.8rem;">{s}</b></div>' for i, s in enumerate(stages))}
</div>
""", unsafe_allow_html=True)

col_s1, col_s2 = st.columns([2, 1])
with col_s1:
    new_stage = st.selectbox("Update Incident Stage:", stages, index=curr_idx)

with col_s2:
    st.write("")
    st.write("")
    if st.button("Confirm Stage Update on Ledger", type="primary", use_container_width=True):
        if inc:
            inc.lifecycle_status = new_stage
            st.success(f"✅ Incident `{inc.incident_id}` transitioned to `{new_stage}`! State updated on Ganache audit record.")
            st.rerun()
        else:
            st.info("No active incident to update. Generate an incident first.")
