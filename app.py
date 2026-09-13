"""
Main Application Entry Point & Executive SOC Master Router.
Part of the PhD Research Platform for Privacy-Preserving EHR Transmission with Cryptographic Protection,
Blockchain Integrity, and AI-Based Post-Encryption Breach Detection.
"""

import streamlit as st
from src.ui_helpers import apply_soc_theme, get_shared_state, reset_live_feed
from src.utils import get_hardware_info


# Master Page Configuration
st.set_page_config(
    page_title="EHR Privacy & Post-Encryption Blockchain IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

apply_soc_theme()
state = get_shared_state()
hw_info = get_hardware_info()

# Sidebar SOC Brand & Telemetry Header
with st.sidebar:
    st.markdown("""
    <div class="sidebar-soc-brand">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <span class="soc-header-tag" style="margin: 0; font-size: 0.68rem; padding: 2px 8px;">RESEARCH SOC</span>
            <span class="sidebar-telemetry-badge"><span class="pulse-dot"></span> LIVE</span>
        </div>
        <div style="font-size: 1.15rem; font-weight: 800; color: #ffffff; letter-spacing: 0.5px;">HEALTHCARE SOC</div>
        <div style="font-size: 0.72rem; color: #8fa3bf; margin-top: 2px;">
            EHR Privacy, Blockchain & Post-Encryption IDS
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Telemetry Status Card
    contract_client = getattr(state, "contract_client", None)
    if contract_client is None:
        from blockchain.contract_client import BlockchainContractClient
        st.session_state.contract_client = BlockchainContractClient()
        contract_client = st.session_state.contract_client
    is_live = getattr(contract_client, "is_live_ganache", False)
    device_name = getattr(state, "device_str", "CPU").upper()
    st.markdown(f"""
    <div style="background: rgba(14, 20, 33, 0.85); border: 1px solid rgba(0, 240, 255, 0.2); border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; font-size: 0.78rem;">
        <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
            <span style="color: #8fa3bf;">Ledger:</span>
            <span style="color: {'#00ff88' if is_live else '#ffaa00'}; font-weight: 600;">{'GANACHE (Port 8545)' if is_live else 'PYTHON FALLBACK'}</span>
        </div>
        <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
            <span style="color: #8fa3bf;">Cipher:</span>
            <span style="color: #00f0ff; font-weight: 600;">AES-256-GCM</span>
        </div>
        <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
            <span style="color: #8fa3bf;">IDS Engine:</span>
            <span style="color: #00f0ff; font-weight: 600;">CNN-BiLSTM-Attn</span>
        </div>
        <div style="display: flex; justify-content: space-between;">
            <span style="color: #8fa3bf;">Compute:</span>
            <span style="color: #ffffff; font-weight: 600;">{device_name}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Live Streaming Controls in Sidebar
    st.markdown("**⚡ Live Telemetry Stepper**")
    col_s1, col_s2 = st.columns(2)
    with col_s1:
        if st.button("▶️ Step Event", use_container_width=True, help="Ingest next real-time network flow"):
            new_evt = state.streamer.process_next_event()
            state.stream_events.insert(0, new_evt)
            if len(state.stream_events) > 50:
                state.stream_events.pop()
            st.rerun()
    with col_s2:
        if st.button("🔄 Reset Feed", use_container_width=True, help="Clear all entries and reset live state"):
            reset_live_feed(state)
            st.rerun()

    st.markdown("---")

# Master SOC Navigation Hierarchy (20 Pages Across Logical Groups)
pages = {
    "🛡️ Executive & Demonstration": [
        st.Page("pages/01_Overview.py", title="Executive Overview & 22-Step Demo", icon="🛡️", default=True),
        st.Page("pages/20_Complete_Architecture.py", title="Complete Layered Architecture & 3D", icon="🏛️"),
    ],
    "🏥 Phase 1: Secure EHR Protection": [
        st.Page("pages/02_EHR_Data.py", title="EHR Data Center (MIMIC-III)", icon="🏥"),
        st.Page("pages/03_Phase1_Before_Encryption.py", title="Phase 1: Before Encryption", icon="📋"),
        st.Page("pages/04_Phase1_Encryption.py", title="Phase 1: Authenticated Encryption", icon="🔒"),
        st.Page("pages/05_Phase1_After_Encryption.py", title="Phase 1: After Encryption", icon="📦"),
        st.Page("pages/06_Crypto_Comparison.py", title="Encryption Scheme Comparison", icon="⚖️"),
        st.Page("pages/07_Key_Management.py", title="Key Management & Quantum Sims", icon="🔑"),
    ],
    "⛓️ Blockchain & Smart Contracts": [
        st.Page("pages/08_Blockchain.py", title="Ganache Blockchain Live Status", icon="⛓️"),
        st.Page("pages/09_Smart_Contract.py", title="Smart Contracts & Multi-Role RBAC", icon="📜"),
    ],
    "🚨 Phase 2: Post-Encryption Breach Detection": [
        st.Page("pages/10_Phase2_Breach_Simulation.py", title="Phase 2: Breach Simulation", icon="🚨"),
        st.Page("pages/11_IDS_Detection.py", title="AI Intrusion Detection (IDS)", icon="📡"),
        st.Page("pages/12_Attack_Classification.py", title="15-Class Attack Classification", icon="🎯"),
        st.Page("pages/13_False_Positives_Negatives.py", title="False Positives & Negatives", icon="🔍"),
        st.Page("pages/14_Severity_Response.py", title="Severity & Risk Scoring Engine", icon="⚖️"),
        st.Page("pages/15_Alert_Center.py", title="SOC Alert Center & Evidence", icon="📢"),
        st.Page("pages/16_Recommended_Actions.py", title="Recommended Containment Playbooks", icon="🛠️"),
        st.Page("pages/17_Incident_Timeline.py", title="Forensic Incident Timeline", icon="⏱️"),
    ],
    "🔬 Research Insights & Benchmarks": [
        st.Page("pages/18_Explainable_AI.py", title="Explainable AI (SHAP)", icon="🔮"),
        st.Page("pages/19_Performance_Benchmarks.py", title="Security & System Benchmarks", icon="📊"),
    ],
}

nav = st.navigation(pages)
nav.run()
