"""
07_Key_Management.py
Cryptographic Key Management Lifecycle, BB84 Simulation & TC-QC Tensor Cryptography.
Demonstrates key derivation, rotation, revocation, software-simulated BB84 QKD, and TC-QC Kronecker transformations.
"""

import streamlit as st
import time
import pandas as pd
from src.ui_helpers import apply_soc_theme, get_shared_state
from crypto.key_management import KeyManager
from crypto.qkd_simulation import BB84Simulator
from crypto.tcqc_simulation import TCQCSimulator

apply_soc_theme()
state = get_shared_state()
km: KeyManager = state.key_manager

st.markdown("""
<div style="margin-bottom: 20px;">
    <span class="soc-header-tag">KEY MANAGEMENT SYSTEM</span>
    <h1 style="margin: 4px 0; font-size: 2.0rem; font-weight: 800; color: #ffffff;">
        Cryptographic Key Lifecycle & Software Quantum Simulations
    </h1>
    <p style="color: #8fa3bf; font-size: 0.92rem;">
        Complete lifecycle management for 256-bit symmetric keys, including automated rotation, revocation,
        and software simulations of BB84 Quantum Key Agreement and Tensor Category Cryptography (TC-QC).
    </p>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# 1. Key Lifecycle Management
# -------------------------------------------------------------
st.markdown("### 🔑 Cryptographic Key Lifecycle (KeyManager Vault)")

active_key = km.get_active_key()

col_k1, col_k2, col_k3 = st.columns([1, 1, 1])
with col_k1:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Active Key ID</div>
        <div class="kpi-value" style="font-size: 1.2rem; color: #00ff88;">{active_key.key_id}</div>
        <div class="kpi-delta" style="color: #00f0ff;">Status: {active_key.status}</div>
    </div>
    """, unsafe_allow_html=True)

with col_k2:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Key Algorithm</div>
        <div class="kpi-value" style="font-size: 1.2rem;">AES-256-GCM</div>
        <div class="kpi-delta" style="color: #8fa3bf;">256-bit Symmetric Key</div>
    </div>
    """, unsafe_allow_html=True)

with col_k3:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Key Usage Count</div>
        <div class="kpi-value" style="font-size: 1.2rem;">{active_key.usage_count} <span style="font-size: 0.8rem; font-weight: 400;">operations</span></div>
        <div class="kpi-delta" style="color: #ffaa00;">Vault Entries: {len(km.keys)}</div>
    </div>
    """, unsafe_allow_html=True)

col_act1, col_act2, col_act3 = st.columns(3)
with col_act1:
    if st.button("🔄 Rotate Active Session Key", use_container_width=True):
        new_key = km.rotate_key("Routine SOC Key Rotation")
        st.success(f"✅ Key Rotated! New Active Key: `{new_key.key_id}`")
        st.rerun()

with col_act2:
    if st.button("🛑 Revoke / Expire Current Key", use_container_width=True):
        km.revoke_key(active_key.key_id, "Compromise simulation")
        st.warning(f"⚠️ Key `{active_key.key_id}` Revoked. Fallback/New key generated.")
        st.rerun()

with col_act3:
    st.markdown(f"**Created:** `{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(active_key.created_at))}`")

st.markdown("---")

# -------------------------------------------------------------
# 2. BB84 Software Simulation
# -------------------------------------------------------------
st.markdown("### ⚛️ BB84 Quantum Key Agreement (Software Simulation)")
st.info("⚠️ **SCIENTIFIC CLARIFICATION:** This is a **BB84 SOFTWARE SIMULATION**. No physical quantum optical hardware (single-photon emitters or beam splitters) is used. It simulates quantum basis preparation, polarization measurement, sifting, and eavesdropping detection mathematically in software.")

col_q1, col_q2 = st.columns([1, 2])
with col_q1:
    qkd_bits = st.slider("Photons Sent (Simulated)", 128, 1024, 256, step=64)
    eve_present = st.checkbox("Simulate Eavesdropper Interception (Eve)", value=True)
    run_qkd = st.button("▶️ Simulate BB84 Key Agreement", type="primary", use_container_width=True)

with col_q2:
    if run_qkd:
        sim = BB84Simulator(num_bits=qkd_bits, eve_present=eve_present)
        res = sim.run_simulation()
        
        st.markdown(f"""
        **Photons Transmitted:** `{res['raw_bits_sent']}` | **Sifted Key Length:** `{res['sifted_key_length']} bits`  
        **Quantum Bit Error Rate (QBER):** `{res['qber_pct']:.2f}%` (Abortion Threshold: 11.0%)  
        **Eavesdropping Detected:** `{'🚨 YES (EVE DETECTED)' if res['eavesdropping_detected'] else '✅ NO (CHANNEL CLEAN)'}`  
        **Final Key Status:** `{'COMPROMISED (ABORTED)' if res['eavesdropping_detected'] else 'SECURE AGREED KEY'}`
        """)
        if not res['eavesdropping_detected']:
            st.code(f"Derived AES-256 Key (Hex): {res['derived_key_hex']}", language="text")
    else:
        st.caption("Click 'Simulate BB84 Key Agreement' to execute software simulation.")

st.markdown("---")

# -------------------------------------------------------------
# 3. TC-QC Tensor Cryptography Software Simulation
# -------------------------------------------------------------
st.markdown("### 🧬 Tensor Category Cryptography (TC-QC Software Simulation)")
st.info("⚠️ **SCIENTIFIC CLARIFICATION:** This is a **TC-QC SOFTWARE SIMULATION**. It models mathematical tensor category transformations (Kronecker matrix product expansion) for key obfuscation in software without physical quantum advantage.")

col_t1, col_t2 = st.columns([1, 2])
with col_t1:
    matrix_dim = st.selectbox("Base Tensor Dimension", [2, 4, 8], index=0)
    run_tcqc = st.button("▶️ Run TC-QC Tensor Expansion", use_container_width=True)

with col_t2:
    if run_tcqc:
        tc_sim = TCQCSimulator(dim=matrix_dim)
        tc_res = tc_sim.run_transformation(active_key.key_bytes)
        st.markdown(f"""
        **Input Key Size:** `{len(active_key.key_bytes)} bytes`  
        **Expanded Tensor Dimension:** `{tc_res['tensor_shape']}`  
        **Matrix Entropy:** `{tc_res['entropy']:.2f} / 8.0`  
        **Execution Time:** `{tc_res['latency_ms']:.4f} ms` [MEASURED]
        """)
    else:
        st.caption("Click to simulate Kronecker tensor product key transformation.")
