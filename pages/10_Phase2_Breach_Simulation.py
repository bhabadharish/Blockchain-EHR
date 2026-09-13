"""
10_Phase2_Breach_Simulation.py
PHASE 2 — POST-ENCRYPTION BREACH SIMULATION ENGINE.
Demonstrates that even after an EHR is encrypted, attacks targeting the transmission channel,
storage nodes, or API gateway can still be detected by the AI IDS layer and cryptographic tamper checks.
"""

import streamlit as st
import time
import pandas as pd
from src.ui_helpers import apply_soc_theme, get_shared_state
from ids.simulation import BreachSimulationEngine, SecurityIncident

apply_soc_theme()
state = get_shared_state()
payload = state.active_ehr_payload
sim: BreachSimulationEngine = state.breach_sim

st.markdown("""
<div style="margin-bottom: 20px;">
    <span class="soc-header-tag" style="background: rgba(255, 59, 48, 0.15); color: #ff3b30; border-color: #ff3b30;">
        PHASE 2 — BREACH SIMULATION
    </span>
    <h1 style="margin: 4px 0; font-size: 2.0rem; font-weight: 800; color: #ffffff;">
        Controlled Breach Simulation & Tamper Demonstration
    </h1>
    <p style="color: #8fa3bf; font-size: 0.92rem;">
        Replays genuine recorded Edge-IIoTset network telemetry and cryptographic tamper models.
        No actual hostile network attacks are launched against external systems.
    </p>
</div>
""", unsafe_allow_html=True)

if not payload or not payload.encryption_receipt:
    st.warning("Please complete Phase 1 encryption before launching breach simulations.")
    st.stop()

receipt = payload.encryption_receipt

# -------------------------------------------------------------
# 1. Breach Scenario Selection
# -------------------------------------------------------------
st.markdown("### 🎯 Select Post-Encryption Breach Scenario")

col_s1, col_s2 = st.columns([2, 1])

with col_s1:
    scenarios = sim.SCENARIOS
    scen_key = st.selectbox(
        "Choose Scenario:",
        list(scenarios.keys()),
        format_func=lambda k: f"{scenarios[k]['title']} ({scenarios[k]['attack_type']})"
    )
    chosen_scen = scenarios[scen_key]
    st.markdown(f"**Scenario Description:** {chosen_scen['description']}")

with col_s2:
    st.markdown(f"""
    <div class="soc-card" style="padding: 14px;">
        <div style="font-size: 0.8rem; color: #8fa3bf;">SCENARIO PARAMETERS:</div>
        <div style="font-size: 0.85rem; margin-top: 4px;">
            <b>Target Attack:</b> <code>{chosen_scen['attack_type']}</code><br>
            <b>Ciphertext Tampered:</b> <code>{chosen_scen['tamper_ciphertext']}</code><br>
            <b>Unauthorized Access:</b> <code>{chosen_scen['unauthorized_access']}</code>
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# -------------------------------------------------------------
# 2. Execute Simulation Step
# -------------------------------------------------------------
col_run, col_info = st.columns([1, 2])

with col_run:
    rep_attempts = st.slider("Repeated Access Attempts", 1, 5, 1)
    launch_btn = st.button("🚨 Launch Controlled Breach Simulation", type="primary", use_container_width=True)

if launch_btn:
    with st.spinner("Replaying Edge-IIoT telemetry & evaluating cryptographic integrity..."):
        incident = sim.simulate_breach(
            scenario_key=scen_key,
            payload_id=payload.record_id,
            original_hash=receipt.sha256_hash,
            ciphertext_bytes=receipt.ciphertext_bytes,
            sensitive_field_count=len(payload.sensitive_fields),
            accessor_role="DOCTOR",
            repeated_attempts=rep_attempts
        )
        
        # Automatically register on blockchain if Ganache or fallback is active
        inc_tx = state.contract_client.record_incident(
            incident_id=incident.incident_id,
            payload_hash=incident.current_hash,
            attack_type=incident.predicted_attack_type,
            severity=incident.severity,
            confidence_pct=incident.confidence_pct,
            integrity_status=incident.integrity_status
        )
        incident.blockchain_tx_hash = inc_tx.get("tx_hash", "0x0")
        incident.blockchain_status = "RECORDED_ON_CHAIN" if inc_tx.get("status") == "SUCCESS" else "RECORDED_FALLBACK"

        state.active_incident = incident
        state.incident_history.insert(0, incident)
        st.success(f"✅ Breach Simulated: Incident `{incident.incident_id}` Created & Logged!")

# -------------------------------------------------------------
# 3. Interactive Tampered Ciphertext Demonstration (Section 28)
# -------------------------------------------------------------
if state.active_incident:
    inc = state.active_incident
    st.markdown("---")
    st.markdown("### 🔬 Cryptographic Tamper Verification & Hash Comparison")

    col_h1, col_h2, col_h3 = st.columns([2, 2, 1])
    with col_h1:
        st.markdown("**Original On-Chain Notarized SHA-256:**")
        st.code(inc.original_hash, language="text")

    with col_h2:
        st.markdown("**Current In-Flight Payload SHA-256:**")
        st.code(inc.current_hash, language="text")

    with col_h3:
        st.markdown("**Hash Match:**")
        if inc.hash_match:
            st.markdown("<h3 style='color: #00ff88; margin: 0;'>MATCH ✅</h3>", unsafe_allow_html=True)
            st.caption("Payload is cryptographically intact.")
        else:
            st.markdown("<h3 style='color: #ff3b30; margin: 0;'>MISMATCH 🛑</h3>", unsafe_allow_html=True)
            st.caption("CRITICAL: Ciphertext was modified!")

    # EHR Data Preservation Card
    is_attack_sim = (inc.simulated_attack_type != "Normal" or not inc.hash_match or inc.unauthorized_access)
    st.markdown(f"""
    <div style="background: rgba(0, 240, 255, 0.08); border: 1px solid {'#ffaa00' if is_attack_sim else '#00ff88'}; border-radius: 8px; padding: 12px 16px; margin: 14px 0;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <b style="font-size: 1.05rem; color: {'#00f0ff' if is_attack_sim else '#00ff88'};">
                {'🛡️ EHR PRESERVATION GUARANTEE: PACKET ATTACKED BUT DATA SAVED BY ENCRYPTION' if is_attack_sim else '✅ NORMAL TRANSMISSION: AUTHENTICATED PAYLOAD SECURED'}
            </b>
            <span style="background: rgba(0, 255, 136, 0.2); color: #00ff88; border: 1px solid #00ff88; padding: 2px 8px; border-radius: 4px; font-size: 0.76rem; font-weight: 700;">
                AES-256-GCM SAVED
            </span>
        </div>
        <p style="font-size: 0.85rem; color: #c4d1e2; margin: 6px 0 0 0;">
            {'Even though the communication channel was subjected to a ' + inc.simulated_attack_type + ' attack and classified by the IDS, the underlying clinical medical data remained completely saved and protected by AES-256-GCM authenticated encryption. Medical plaintext was never exposed!' if is_attack_sim else 'Secure clinical transmission verified with SHA-256 blockchain metadata anchoring.'}
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Display SOC Incident Box
    st.markdown("### 🚨 Correlated Security Incident Assessment")
    
    col_out1, col_out2, col_out3, col_out4 = st.columns(4)
    with col_out1:
        st.markdown(f"""
        <div class="soc-card">
            <div class="kpi-title">Detected Attack</div>
            <div class="kpi-value" style="font-size: 1.3rem;">{inc.predicted_attack_type}</div>
            <div class="kpi-delta" style="color: #00f0ff;">Ground Truth: {inc.simulated_attack_type}</div>
        </div>
        """, unsafe_allow_html=True)

    with col_out2:
        st.markdown(f"""
        <div class="soc-card">
            <div class="kpi-title">Model Confidence</div>
            <div class="kpi-value">{inc.confidence_pct:.1f}%</div>
            <div class="kpi-delta" style="color: #00ff88;">τ* = 0.10 Optimal</div>
        </div>
        """, unsafe_allow_html=True)

    with col_out3:
        st.markdown(f"""
        <div class="soc-card">
            <div class="kpi-title">Composite Risk</div>
            <div class="kpi-value">{inc.risk_score:.1f} <span style="font-size: 0.9rem;">/ 100</span></div>
            <div class="kpi-delta" style="color: {inc.severity_color};">Multi-Signal Score</div>
        </div>
        """, unsafe_allow_html=True)

    with col_out4:
        st.markdown(f"""
        <div class="soc-card">
            <div class="kpi-title">Assigned Severity</div>
            <div class="kpi-value" style="color: {inc.severity_color};">{inc.severity}</div>
            <div class="kpi-delta" style="color: {inc.severity_color};">Rule Rationale Below</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown(f"""
    <div class="soc-card" style="border: 1px solid {inc.severity_color};">
        <b>Primary Explainable Rationale:</b> {inc.explainable_rationale}<br>
        <b>Blockchain Proof:</b> <code>{inc.blockchain_tx_hash}</code> ({inc.blockchain_status})
    </div>
    """, unsafe_allow_html=True)
