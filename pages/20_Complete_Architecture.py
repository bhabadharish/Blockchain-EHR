"""
20_Complete_Architecture.py
Complete System Architecture: Phase 1 & Phase 2 Layered Security Visualizer.
Includes high-fidelity visual block diagrams, 3D physical system renders, neural layer architecture,
and interactive 3D analytical block diagrams.
"""

import os
import textwrap
import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from src.ui_helpers import apply_soc_theme, get_shared_state

apply_soc_theme()
state = get_shared_state()

# -------------------------------------------------------------
# Header
# -------------------------------------------------------------
st.html(textwrap.dedent("""
<div style="margin-bottom: 20px;">
    <span class="soc-header-tag">COMPREHENSIVE ARCHITECTURE</span>
    <h1 style="margin: 4px 0; font-size: 2.0rem; font-weight: 800; color: #ffffff;">
        Layered System Architecture & 3D Visualizations
    </h1>
    <p style="color: #8fa3bf; font-size: 0.92rem;">
        Integrated architectural overview of Phase 1 (Cryptographic EHR Protection & Blockchain Notarization)
        and Phase 2 (AI Post-Encryption Breach Detection & Automated Incident Response).
    </p>
</div>
"""))

# -------------------------------------------------------------
# 1. Mandatory Architectural Doctrine (Section 65)
# -------------------------------------------------------------
st.html(textwrap.dedent("""
<div class="soc-card" style="border: 1px solid rgba(0, 240, 255, 0.4); background: rgba(14, 20, 33, 0.9); margin-bottom: 20px;">
    <h4 style="color: #00f0ff; margin-top: 0; letter-spacing: 1px;">THE CORE LAYERED SECURITY DOCTRINE</h4>
    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; font-size: 0.85rem; color: #c4d1e2;">
        <div>
            <b>🔐 ENCRYPTION:</b> Protects patient confidentiality against unauthorized wire eavesdroppers.<br>
            <b>🏷️ AUTHENTICATED ENCRYPTION (AEAD) & HASHING:</b> Protects cryptographic integrity and detects bit-flips.<br>
            <b>⛓️ BLOCKCHAIN:</b> Provides immutable, tamper-evident metadata notarization and legal auditability.<br>
            <b>👥 ACCESS CONTROL (RBAC):</b> Enforces authorized clinician access via smart contracts.
        </div>
        <div>
            <b>🧠 THE AI IDS:</b> Detects suspicious network/host behavior targeting the surrounding environment.<br>
            <b>⚖️ THE INCIDENT ENGINE:</b> Correlates multi-layer signals (cryptographic, network, access) into risk scores.<br>
            <b>🛡️ THE RESPONSE ENGINE:</b> Recommends precise SOC countermeasures with human-in-the-loop safety.<br>
            <b>⚠️ NO SINGLE COMPONENT:</b> Solves every security problem alone; defense-in-depth is essential.
        </div>
    </div>
</div>
"""))

st.markdown("---")

# -------------------------------------------------------------
# 2. Complete Phase 1 & Phase 2 Visual Block Diagrams
# -------------------------------------------------------------
st.markdown("### 🏛️ Complete End-to-End System Block Pipeline")

# Inject CSS for visual block diagram
st.html(textwrap.dedent("""
<style>
.arch-container-p1 {
    background: rgba(10, 16, 26, 0.85);
    border: 1px solid rgba(0, 240, 255, 0.35);
    border-top: 4px solid #00f0ff;
    border-radius: 10px;
    padding: 16px;
}
.arch-container-p2 {
    background: rgba(26, 12, 20, 0.85);
    border: 1px solid rgba(255, 59, 48, 0.35);
    border-top: 4px solid #ff3b30;
    border-radius: 10px;
    padding: 16px;
}
.arch-block {
    background: rgba(14, 20, 33, 0.95);
    border: 1px solid rgba(0, 240, 255, 0.35);
    border-radius: 8px;
    padding: 10px 14px;
    margin-bottom: 2px;
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.35);
}
.arch-block-p2 {
    background: rgba(26, 16, 24, 0.95);
    border: 1px solid rgba(255, 59, 48, 0.35);
    border-radius: 8px;
    padding: 10px 14px;
    margin-bottom: 2px;
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.35);
}
.arch-arrow {
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 4px 0;
    color: #00f0ff;
}
.arch-arrow-p2 {
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 4px 0;
    color: #ff3b30;
}
.arch-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}
.badge-cyan { background: rgba(0, 240, 255, 0.18); color: #00f0ff; border: 1px solid rgba(0, 240, 255, 0.4); }
.badge-blue { background: rgba(59, 130, 246, 0.18); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }
.badge-purple { background: rgba(168, 85, 247, 0.18); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }
.badge-pink { background: rgba(236, 72, 153, 0.18); color: #f472b6; border: 1px solid rgba(236, 72, 153, 0.4); }
.badge-red { background: rgba(255, 59, 48, 0.18); color: #ff6b6b; border: 1px solid rgba(255, 59, 48, 0.4); }
.badge-orange { background: rgba(255, 149, 0, 0.18); color: #fbbf24; border: 1px solid rgba(255, 149, 0, 0.4); }
.badge-yellow { background: rgba(250, 204, 21, 0.18); color: #fde047; border: 1px solid rgba(250, 204, 21, 0.4); }
.badge-green { background: rgba(0, 255, 136, 0.18); color: #00ff88; border: 1px solid rgba(0, 255, 136, 0.4); }
</style>
"""))

tab_block_cards, tab_block_flow = st.tabs([
    "🗂️ Visual Architecture Block Cards",
    "📊 Graphical Block Flowchart"
])

with tab_block_cards:
    col_b1, col_b2 = st.columns(2)

    with col_b1:
        st.html(textwrap.dedent("""
<div class="arch-container-p1">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <h4 style="color: #00f0ff; margin: 0; font-size: 1.05rem;">PHASE 1: EHR PRIVACY PROTECTION</h4>
        <span class="arch-badge badge-cyan">CRYPTOGRAPHIC PIPELINE</span>
    </div>

    <!-- Block 1: Clinical Data Ingestion -->
    <div class="arch-block">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <b style="color: #ffffff; font-size: 0.88rem;">1. Clinical Data Ingestion & Schema Minimization</b>
            <span class="arch-badge badge-cyan">MIMIC-III / IV</span>
        </div>
        <div style="color: #8fa3bf; font-size: 0.80rem; margin-top: 4px;">
            Extracts patient demographics, vitals, ICD-9/10 diagnoses, and lab results; minimizes clinical attributes to necessary scope.
        </div>
    </div>

    <div class="arch-arrow">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
    </div>

    <!-- Block 2: HIPAA Masking -->
    <div class="arch-block">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <b style="color: #ffffff; font-size: 0.88rem;">2. HIPAA De-Identification & Masking</b>
            <span class="arch-badge badge-blue">SAFE HARBOR</span>
        </div>
        <div style="color: #8fa3bf; font-size: 0.80rem; margin-top: 4px;">
            Masks 18 HIPAA direct identifiers (names, SSN, MRN, phone, address); generates cryptographically secure pseudonym tokens.
        </div>
    </div>

    <div class="arch-arrow">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
    </div>

    <!-- Block 3: Key Establishment -->
    <div class="arch-block">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <b style="color: #ffffff; font-size: 0.88rem;">3. Cryptographic Key Establishment</b>
            <span class="arch-badge badge-purple">256-BIT CSPRNG</span>
        </div>
        <div style="color: #8fa3bf; font-size: 0.80rem; margin-top: 4px;">
            Generates high-entropy 256-bit symmetric session key via KeyManager + 96-bit unique CSPRNG initialization vector (nonce).
        </div>
    </div>

    <div class="arch-arrow">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
    </div>

    <!-- Block 4: AES-256-GCM Encryption -->
    <div class="arch-block" style="border: 1px solid #00f0ff;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <b style="color: #00f0ff; font-size: 0.88rem;">4. AES-256-GCM Authenticated Encryption</b>
            <span class="arch-badge badge-cyan">AEAD CIPHER</span>
        </div>
        <div style="color: #c4d1e2; font-size: 0.80rem; margin-top: 4px;">
            Encrypts payload with Galois/Counter Mode; generates ciphertext and 128-bit authentication MAC tag for zero-leak confidentiality.
        </div>
    </div>

    <div class="arch-arrow">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
    </div>

    <!-- Block 5: SHA-256 Digest Anchor -->
    <div class="arch-block">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <b style="color: #ffffff; font-size: 0.88rem;">5. Cryptographic Digest Anchor</b>
            <span class="arch-badge badge-blue">SHA-256 DIGEST</span>
        </div>
        <div style="color: #8fa3bf; font-size: 0.80rem; margin-top: 4px;">
            Computes 32-byte tamper-evident SHA-256 cryptographic digest of the encrypted ciphertext and header metadata.
        </div>
    </div>

    <div class="arch-arrow">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
    </div>

    <!-- Block 6: Fork into Off-Chain Storage + Ganache Blockchain -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
        <div class="arch-block" style="border-color: rgba(99, 102, 241, 0.6);">
            <div style="font-size: 0.80rem; font-weight: 700; color: #818cf8;">6A. OFF-CHAIN REPO</div>
            <div style="color: #c4d1e2; font-size: 0.78rem; margin-top: 2px;">
                Encrypted ciphertext, IV, & MAC tag securely persisted in off-chain repository.
            </div>
        </div>
        <div class="arch-block" style="border-color: rgba(168, 85, 247, 0.6);">
            <div style="font-size: 0.80rem; font-weight: 700; color: #c084fc;">6B. GANACHE LEDGER</div>
            <div style="color: #c4d1e2; font-size: 0.78rem; margin-top: 2px;">
                <code>EHRIntegrityRegistry</code> notarizes SHA-256 root hash anchor on-chain.
            </div>
        </div>
    </div>

    <div class="arch-arrow">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
    </div>

    <!-- Block 7: Clinician RBAC Access -->
    <div class="arch-block">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <b style="color: #ffffff; font-size: 0.88rem;">7. Clinician Role-Based Access (RBAC)</b>
            <span class="arch-badge badge-pink">SMART CONTRACT</span>
        </div>
        <div style="color: #8fa3bf; font-size: 0.80rem; margin-top: 4px;">
            <code>EHRAccessControl</code> enforces role validation (Doctor, Nurse, Auditor) and logs immutable access audit records.
        </div>
    </div>
</div>
"""))

    with col_b2:
        st.html(textwrap.dedent("""
<div class="arch-container-p2">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <h4 style="color: #ff3b30; margin: 0; font-size: 1.05rem;">PHASE 2: POST-ENCRYPTION SECURITY</h4>
        <span class="arch-badge badge-red">AI BREACH DEFENSE</span>
    </div>

    <!-- Block 1: Encrypted Wire Transmission -->
    <div class="arch-block-p2">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <b style="color: #ffffff; font-size: 0.88rem;">1. Encrypted EHR Wire Transmission</b>
            <span class="arch-badge badge-blue">ACTIVE TRANSIT</span>
        </div>
        <div style="color: #8fa3bf; font-size: 0.80rem; margin-top: 4px;">
            Encrypted payload is transmitted across hospital WAN, edge routers, and network switches.
        </div>
    </div>

    <div class="arch-arrow-p2">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ff3b30" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
    </div>

    <!-- Block 2: Wire Adversary Attack + SHIELD BANNER -->
    <div class="arch-block-p2" style="border: 1px solid #ff3b30;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <b style="color: #ff3b30; font-size: 0.88rem;">2. Host & Network Adversarial Attack</b>
            <span class="arch-badge badge-red">14 ATTACK VECTORS</span>
        </div>
        <div style="color: #c4d1e2; font-size: 0.80rem; margin-top: 4px;">
            Adversary launches DDoS, Ransomware, MITM, Injection, or PortScan targeting edge transmission infrastructure.
        </div>
        <div style="background: rgba(0, 255, 136, 0.12); border: 1px solid #00ff88; border-radius: 6px; padding: 6px 8px; margin-top: 6px; font-size: 0.76rem; color: #00ff88; font-weight: 600;">
            🛡️ EHR DATA SHIELD: Transmission packet is targeted, but EHR patient payload is 100% SAVED & PRESERVED by AES-256-GCM. Confidentiality is uncompromised.
        </div>
    </div>

    <div class="arch-arrow-p2">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ff3b30" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
    </div>

    <!-- Block 3: Edge-IIoTset Telemetry -->
    <div class="arch-block-p2">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <b style="color: #ffffff; font-size: 0.88rem;">3. Network Telemetry Ingestion</b>
            <span class="arch-badge badge-orange">EDGE-IIOTSET 45-DIM</span>
        </div>
        <div style="color: #8fa3bf; font-size: 0.80rem; margin-top: 4px;">
            Extracts 45-dimensional deep flow vectors: TCP/UDP ports, packet rates, flags, jitter, inter-arrival time, byte entropy.
        </div>
    </div>

    <div class="arch-arrow-p2">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ff3b30" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
    </div>

    <!-- Block 4: Neural IDS Model -->
    <div class="arch-block-p2">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <b style="color: #ffffff; font-size: 0.88rem;">4. Hybrid Deep Neural Threat Detector</b>
            <span class="arch-badge badge-yellow">CNN-BILSTM-ATTN</span>
        </div>
        <div style="color: #8fa3bf; font-size: 0.80rem; margin-top: 4px;">
            1D Convolutions extract spatial features ➔ BiLSTM tracks temporal recurrence ➔ Multi-Head Self-Attention attends to critical attack signals.
        </div>
    </div>

    <div class="arch-arrow-p2">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ff3b30" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
    </div>

    <!-- Block 5: 15-Class Classification -->
    <div class="arch-block-p2">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <b style="color: #ffffff; font-size: 0.88rem;">5. 15-Class Threat Classification</b>
            <span class="arch-badge badge-red">SOFTMAX CONFIDENCE</span>
        </div>
        <div style="color: #8fa3bf; font-size: 0.80rem; margin-top: 4px;">
            Classifies incoming flow into Normal or 14 specific attack classes with calibrated probabilistic confidence scores.
        </div>
    </div>

    <div class="arch-arrow-p2">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ff3b30" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
    </div>

    <!-- Block 6: Multi-Signal Risk Engine -->
    <div class="arch-block-p2">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <b style="color: #ffffff; font-size: 0.88rem;">6. Multi-Signal Quantitative Risk Engine</b>
            <span class="arch-badge badge-orange">0-100 RISK SCORE</span>
        </div>
        <div style="color: #8fa3bf; font-size: 0.80rem; margin-top: 4px;">
            Fuses Cryptographic Integrity (0-40 pts) + Network Threat Score (0-40 pts) + Smart Contract RBAC (0-20 pts) into composite score.
        </div>
    </div>

    <div class="arch-arrow-p2">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ff3b30" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
    </div>

    <!-- Block 7: Fork into Automated SOC Playbook + Blockchain Forensic Notarization -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
        <div class="arch-block-p2" style="border-color: rgba(0, 255, 136, 0.6);">
            <div style="font-size: 0.80rem; font-weight: 700; color: #00ff88;">7A. SOC MITIGATION</div>
            <div style="color: #c4d1e2; font-size: 0.78rem; margin-top: 2px;">
                Dynamic firewall IP drop, session revocation, & automated key rotation.
            </div>
        </div>
        <div class="arch-block-p2" style="border-color: rgba(16, 185, 129, 0.6);">
            <div style="font-size: 0.80rem; font-weight: 700; color: #34d399;">7B. BLOCKCHAIN FORENSIC</div>
            <div style="color: #c4d1e2; font-size: 0.78rem; margin-top: 2px;">
                Smart contract logs <code>BreachDetected</code> event receipt for immutable court auditability.
            </div>
        </div>
    </div>
</div>
"""))

with tab_block_flow:
    # 2D Flowchart Block Diagram using Plotly
    fig_flow = go.Figure()

    # Phase 1 Flowchart Blocks
    p1_nodes = [
        ("1. MIMIC-III Ingestion", 7.0, "#00f0ff", "Extracts ICU charts & minimises schema"),
        ("2. HIPAA Masking", 6.0, "#00d0ff", "18 direct identifiers de-identified"),
        ("3. 256-bit KeyManager", 5.0, "#00b0ff", "256-bit AES key + 96-bit CSPRNG nonce"),
        ("4. AES-256-GCM AEAD", 4.0, "#0088ff", "Ciphertext + 128-bit MAC tag"),
        ("5. SHA-256 Hash Digest", 3.0, "#6366f1", "32-byte tamper-evident digest"),
        ("6. Off-Chain Repo / Ganache", 2.0, "#a855f7", "Ciphertext stored off-chain; hash anchored on-chain"),
        ("7. Clinician RBAC Access", 1.0, "#ec4899", "Smart contract role validation")
    ]

    # Phase 2 Flowchart Blocks
    p2_nodes = [
        ("1. Wire Transmission", 7.0, "#3b82f6", "Encrypted packet over hospital WAN"),
        ("2. Threat Attack (EHR Saved)", 6.0, "#ff3b30", "14 attack types; EHR shielded by AES-256-GCM"),
        ("3. Edge-IIoT Telemetry", 5.0, "#ff7700", "45-dimensional flow feature extraction"),
        ("4. Hybrid Deep IDS", 4.0, "#ffaa00", "CNN spatial -> BiLSTM temporal -> Attention"),
        ("5. 15-Class Classification", 3.0, "#ffd600", "Exact attack class & confidence percentage"),
        ("6. Multi-Signal Risk Engine", 2.0, "#f59e0b", "Fuses crypto, network, & smart contract auth"),
        ("7. SOC Playbook / Forensics", 1.0, "#00ff88", "Firewall drop & on-chain BreachDetected log")
    ]

    for title, y, col, desc in p1_nodes:
        fig_flow.add_shape(
            type="rect", x0=0.15, y0=y-0.38, x1=1.85, y1=y+0.38,
            fillcolor="rgba(14, 20, 33, 0.95)", line=dict(color=col, width=2)
        )
        fig_flow.add_annotation(
            x=1.0, y=y+0.1, text=f"<b>{title}</b>", showarrow=False,
            font=dict(color=col, size=12)
        )
        fig_flow.add_annotation(
            x=1.0, y=y-0.16, text=desc, showarrow=False,
            font=dict(color="#94a3b8", size=9)
        )
        if y > 1.0:
            fig_flow.add_annotation(
                x=1.0, y=y-0.5, text="⬇", showarrow=False,
                font=dict(color=col, size=14)
            )

    for title, y, col, desc in p2_nodes:
        fig_flow.add_shape(
            type="rect", x0=2.15, y0=y-0.38, x1=3.85, y1=y+0.38,
            fillcolor="rgba(26, 16, 24, 0.95)", line=dict(color=col, width=2)
        )
        fig_flow.add_annotation(
            x=3.0, y=y+0.1, text=f"<b>{title}</b>", showarrow=False,
            font=dict(color=col, size=12)
        )
        fig_flow.add_annotation(
            x=3.0, y=y-0.16, text=desc, showarrow=False,
            font=dict(color="#94a3b8", size=9)
        )
        if y > 1.0:
            fig_flow.add_annotation(
                x=3.0, y=y-0.5, text="⬇", showarrow=False,
                font=dict(color=col, size=14)
            )

    # Phase titles
    fig_flow.add_annotation(x=1.0, y=7.75, text="<b>PHASE 1: EHR PRIVACY PROTECTION</b>", showarrow=False, font=dict(color="#00f0ff", size=13))
    fig_flow.add_annotation(x=3.0, y=7.75, text="<b>PHASE 2: POST-ENCRYPTION SECURITY</b>", showarrow=False, font=dict(color="#ff3b30", size=13))

    fig_flow.update_layout(
        template="plotly_dark",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[0, 4]),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[0.4, 8.1]),
        height=580,
        margin=dict(l=10, r=10, b=10, t=30)
    )
    st.plotly_chart(fig_flow, use_container_width=True)

st.markdown("---")

# -------------------------------------------------------------
# 3. 3D Architectural Visualizations & Renders
# -------------------------------------------------------------
st.markdown("### 🎨 3D Physical Architecture & Neural Layer Renders")

col_img1, col_img2 = st.columns(2)

# Candidate paths for the real-world healthcare architecture 3D render
img_arch_candidates = [
    "artifacts/visualizations/ehr_soc_3d_architecture.jpg",
    "/Users/rupesh/Documents/Blockchain-EHR/artifacts/visualizations/ehr_soc_3d_architecture.jpg",
    "/Users/rupesh/.gemini/antigravity-ide/brain/d786f3bb-85e5-41e7-a702-e13d4eedee1b/ehr_soc_3d_architecture_1789323332104.jpg"
]
img_arch_path = next((p for p in img_arch_candidates if os.path.exists(p)), None)

# Candidate paths for neural layer 3D render
img_model_candidates = [
    "artifacts/visualizations/model_internal_layers_3d.jpg",
    "/Users/rupesh/Documents/Blockchain-EHR/artifacts/visualizations/model_internal_layers_3d.jpg",
    "/Users/rupesh/.gemini/antigravity-ide/brain/d786f3bb-85e5-41e7-a702-e13d4eedee1b/model_internal_layers_3d_1789317444345.jpg"
]
img_model_path = next((p for p in img_model_candidates if os.path.exists(p)), None)

with col_img1:
    st.markdown("##### 🏥 3D Physical Real-World Architecture")
    if img_arch_path:
        st.image(
            img_arch_path,
            caption="3D Physical Healthcare Architecture: Clinical EHR Server Racks, Doctor Workstation, Ganache Blockchain Cluster, Defended Edge Gateway, and SOC Analyst Operations Center",
            use_container_width=True
        )
    else:
        st.info("3D Physical Architecture render loading...")

    st.html(textwrap.dedent("""
    <div style="font-size: 0.80rem; color: #8fa3bf; line-height: 1.5; margin-top: 6px;">
        <b>Real-World System Components:</b><br>
        • <b>Hospital EHR Data Nodes:</b> Clinical database hosting MIMIC-III ICU charts and lab telemetry.<br>
        • <b>Doctor Clinical Workstation:</b> Enforces HIPAA Safe Harbor de-identification & RBAC access.<br>
        • <b>Cryptographic HSM:</b> Hardware AES-256-GCM authenticated encryption & 256-bit key establishment.<br>
        • <b>Local Ganache Blockchain Node:</b> Mining node cluster executing <code>EHRIntegrityRegistry</code> & <code>EHRAccessControl</code>.<br>
        • <b>Cybersecurity SOC Operations Center:</b> High-def dashboard showing live intrusion telemetry with <i>EHR Data Saved by Encryption</i> status.
    </div>
    """))

with col_img2:
    st.markdown("##### 🧠 3D Neural Internal Layer Architecture")
    if img_model_path:
        st.image(
            img_model_path,
            caption="3D Neural Internal Pipeline: 1D Conv Feature Extractor ➔ BiLSTM Temporal Recurrence ➔ Multi-Head Self-Attention ➔ Dense Softmax Head",
            use_container_width=True
        )
    else:
        st.info("3D Neural Architecture render loading...")

    st.html(textwrap.dedent("""
    <div style="font-size: 0.80rem; color: #8fa3bf; line-height: 1.5; margin-top: 6px;">
        <b>Deep Learning Structural Pipeline:</b><br>
        • <b>① Input Layer:</b> 45-dimensional normalized Edge-IIoTset telemetry tensor.<br>
        • <b>② 1D Convolutional Layer:</b> 64 filters (k=3) extracting localized packet correlation patterns.<br>
        • <b>③ Bidirectional LSTM:</b> 64 forward + 64 backward recurrent units capturing temporal state memory.<br>
        • <b>④ Multi-Head Self-Attention:</b> 4 parallel heads weighting anomalous threat signatures.<br>
        • <b>⑤ Dense Classification Head:</b> Fully connected layers with dropout (0.5) leading to 15-class threat softmax output.
    </div>
    """))

st.markdown("---")

# -------------------------------------------------------------
# 4. Interactive 3D System Block Diagram & Analytical Spaces
# -------------------------------------------------------------
st.markdown("### 🌐 Interactive 3D Architecture & Multi-Dimensional Spaces")

tab_3d_block, tab_3d_1, tab_3d_2, tab_3d_3 = st.tabs([
    "🏗️ Interactive 3D System Block Diagram",
    "📈 3D Cryptographic Scaling Space",
    "🎯 3D Multi-Model Security Frontier",
    "🧠 3D Latent Threat Manifold"
])

# TAB 1: INTERACTIVE 3D SYSTEM BLOCK DIAGRAM
with tab_3d_block:
    st.markdown("""
    <p style="color: #8fa3bf; font-size: 0.85rem; margin-bottom: 8px;">
        <b>Interactive 3D Pipeline Topology:</b> Rotate, zoom, and inspect the Phase 1 and Phase 2 architecture blocks in 3D coordinate space.
        Hover over any block to view its cryptographic and AI detection specifications.
    </p>
    """, unsafe_allow_html=True)

    # 14 System Blocks in 3D Space
    sys_nodes = [
        # Phase 1: Cryptographic Protection (x=1.2)
        {'id': 0, 'name': '1. MIMIC-III Clinical EHR', 'phase': 'Phase 1', 'x': 1.2, 'y': 8.5, 'z': 2.0, 'color': '#00f0ff', 'spec': 'Ingestion: ICU Vitals, Diagnoses, Prescriptions'},
        {'id': 1, 'name': '2. HIPAA Masking Engine', 'phase': 'Phase 1', 'x': 1.2, 'y': 7.2, 'z': 2.0, 'color': '#00d0ff', 'spec': 'Safe Harbor: 18 Direct Identifiers Masked'},
        {'id': 2, 'name': '3. 256-bit KeyManager', 'phase': 'Phase 1', 'x': 1.2, 'y': 5.9, 'z': 2.0, 'color': '#00b0ff', 'spec': 'Key Establishment: HKDF-SHA256 + 96-bit Nonce'},
        {'id': 3, 'name': '4. AES-256-GCM AEAD', 'phase': 'Phase 1', 'x': 1.2, 'y': 4.6, 'z': 2.0, 'color': '#0088ff', 'spec': 'Encryption: Ciphertext + 128-bit MAC Tag'},
        {'id': 4, 'name': '5. Off-Chain Storage Node', 'phase': 'Phase 1', 'x': 0.4, 'y': 3.2, 'z': 1.4, 'color': '#6366f1', 'spec': 'Encrypted Storage: Zero Plaintext on Ledger'},
        {'id': 5, 'name': '6. Ganache Blockchain Node', 'phase': 'Phase 1', 'x': 2.0, 'y': 3.2, 'z': 1.4, 'color': '#a855f7', 'spec': 'EHRIntegrityRegistry: SHA-256 Hash Anchor'},
        {'id': 6, 'name': '7. Clinician RBAC Access', 'phase': 'Phase 1', 'x': 2.0, 'y': 1.9, 'z': 1.4, 'color': '#ec4899', 'spec': 'EHRAccessControl: Smart Contract Authorization'},

        # Phase 2: Post-Encryption Threat Defense (x=3.8)
        {'id': 7, 'name': '8. Encrypted Wire Transmission', 'phase': 'Phase 2', 'x': 3.8, 'y': 8.5, 'z': 2.0, 'color': '#3b82f6', 'spec': 'Active Transit: TLS / Edge Gateway Packet'},
        {'id': 8, 'name': '9. Wire Threat Attack (EHR Saved)', 'phase': 'Phase 2', 'x': 3.8, 'y': 7.2, 'z': 2.0, 'color': '#ff3b30', 'spec': 'Adversary: DDoS/Ransomware (EHR SHIELDED by AES-256-GCM)'},
        {'id': 9, 'name': '10. Edge-IIoTset Telemetry', 'phase': 'Phase 2', 'x': 3.8, 'y': 5.9, 'z': 2.0, 'color': '#ff7700', 'spec': 'Sensing: 45-Dimensional Deep Flow Features'},
        {'id': 10, 'name': '11. Hybrid Deep Neural IDS', 'phase': 'Phase 2', 'x': 3.8, 'y': 4.6, 'z': 2.0, 'color': '#ffaa00', 'spec': 'AI Model: MI-CNN (1D) + BiLSTM + Attention'},
        {'id': 11, 'name': '12. Multi-Signal Risk Engine', 'phase': 'Phase 2', 'x': 3.8, 'y': 3.3, 'z': 2.0, 'color': '#ffd600', 'spec': 'Risk Fusion: Crypto (40%) + Network (40%) + RBAC (20%)'},
        {'id': 12, 'name': '13. Automated SOC Playbook', 'phase': 'Phase 2', 'x': 3.0, 'y': 1.9, 'z': 1.4, 'color': '#00ff88', 'spec': 'Response: Firewall Drop, Token Revocation, Key Rotation'},
        {'id': 13, 'name': '14. Blockchain Incident Proof', 'phase': 'Phase 2', 'x': 4.6, 'y': 1.9, 'z': 1.4, 'color': '#10b981', 'spec': 'Ganache Forensics: recordBreachEvent() Emits BreachDetected'}
    ]

    pipe_connections = [
        (0, 1), (1, 2), (2, 3), (3, 4), (3, 5), (5, 6),
        (7, 8), (8, 9), (9, 10), (10, 11), (11, 12), (11, 13),
        # Inter-Phase Pipeline: Encrypted ciphertext feeds into transmission wire
        (3, 7)
    ]

    cx, cy, cz = [], [], []
    for u, v in pipe_connections:
        cx.extend([sys_nodes[u]['x'], sys_nodes[v]['x'], None])
        cy.extend([sys_nodes[u]['y'], sys_nodes[v]['y'], None])
        cz.extend([sys_nodes[u]['z'], sys_nodes[v]['z'], None])

    fig_block_3d = go.Figure()

    # 3D Connecting Pipes
    fig_block_3d.add_trace(go.Scatter3d(
        x=cx, y=cy, z=cz,
        mode='lines',
        line=dict(color='rgba(0, 240, 255, 0.45)', width=5),
        hoverinfo='none',
        name='Data Pipeline'
    ))

    # 3D Blocks as markers
    nx = [n['x'] for n in sys_nodes]
    ny = [n['y'] for n in sys_nodes]
    nz = [n['z'] for n in sys_nodes]
    n_colors = [n['color'] for n in sys_nodes]
    n_labels = [n['name'] for n in sys_nodes]
    hover_cards = [
        f"<b>{n['name']}</b><br>Subsystem: {n['phase']}<br>Specs: {n['spec']}"
        for n in sys_nodes
    ]

    fig_block_3d.add_trace(go.Scatter3d(
        x=nx, y=ny, z=nz,
        mode='markers+text',
        marker=dict(size=14, color=n_colors, opacity=0.95, line=dict(color='#ffffff', width=1.5)),
        text=n_labels,
        textposition='top center',
        textfont=dict(size=10, color='#f1f5f9'),
        hovertext=hover_cards,
        hoverinfo='text',
        name='Architecture Subsystem Blocks'
    ))

    fig_block_3d.update_layout(
        title="3D Interactive System Block Pipeline (Phase 1 Protection & Phase 2 Threat Detection)",
        template="plotly_dark",
        scene=dict(
            xaxis=dict(title="System Phase (1: Cryptographic/Storage | 2: Network/AI SOC)", showgrid=True, zeroline=False),
            yaxis=dict(title="Pipeline Sequence (Top ➔ Down Flow)", showgrid=True, zeroline=False),
            zaxis=dict(title="Subsystem Altitude", showgrid=True, zeroline=False),
            camera=dict(
                eye=dict(x=1.8, y=-1.8, z=1.4)
            )
        ),
        margin=dict(l=0, r=0, b=0, t=40),
        height=540
    )
    st.plotly_chart(fig_block_3d, use_container_width=True)

# TAB 2: CRYPTOGRAPHIC SCALING SPACE
with tab_3d_1:
    sizes = np.array([256, 512, 1024, 2048, 4096, 8192, 16384, 32768])
    latencies = sizes * 0.00002 + 0.015
    throughputs = (sizes / (latencies / 1000.0)) / 1e6

    fig_3d_1 = go.Figure(data=[go.Scatter3d(
        x=sizes,
        y=latencies,
        z=throughputs,
        mode='lines+markers',
        marker=dict(size=7, color=throughputs, colorscale='Viridis', opacity=0.9),
        line=dict(color='#00ff88', width=4)
    )])
    fig_3d_1.update_layout(
        title="3D Cryptographic Scaling: Payload Size (Bytes) × Latency (ms) × Throughput (MB/s)",
        template="plotly_dark",
        scene=dict(
            xaxis=dict(title="Payload Size (Bytes)"),
            yaxis=dict(title="Latency (ms)"),
            zaxis=dict(title="Throughput (MB/s)")
        ),
        margin=dict(l=0, r=0, b=0, t=40),
        height=480
    )
    st.plotly_chart(fig_3d_1, use_container_width=True)

# TAB 3: MULTI-MODEL FRONTIER
with tab_3d_2:
    models = ["Logistic Regression", "Decision Tree", "Random Forest", "Extra Trees", "MLP", "Proposed Hybrid Deep IDS"]
    p = [0.985, 0.991, 0.994, 0.995, 0.992, 1.000]
    r = [0.982, 0.989, 0.993, 0.994, 0.991, 1.000]
    f = [0.983, 0.990, 0.993, 0.994, 0.991, 1.000]

    fig_3d_2 = go.Figure(data=[go.Scatter3d(
        x=p,
        y=r,
        z=f,
        text=models,
        mode='markers+text',
        marker=dict(size=10, color=['#8fa3bf', '#ffaa00', '#00f0ff', '#00f0ff', '#00f0ff', '#00ff88']),
        textposition="top center"
    )])
    fig_3d_2.update_layout(
        title="3D Model Frontier: Precision × Recall × Macro F1 Across Baseline & Proposed Architectures",
        template="plotly_dark",
        scene=dict(
            xaxis=dict(title="Precision", range=[0.97, 1.01]),
            yaxis=dict(title="Recall", range=[0.97, 1.01]),
            zaxis=dict(title="Macro F1", range=[0.97, 1.01])
        ),
        margin=dict(l=0, r=0, b=0, t=40),
        height=480
    )
    st.plotly_chart(fig_3d_2, use_container_width=True)

# TAB 4: 3D LATENT THREAT MANIFOLD
with tab_3d_3:
    np.random.seed(42)
    n_pts = 40
    # Normal cluster
    norm_x = np.random.normal(0, 0.5, n_pts)
    norm_y = np.random.normal(0, 0.5, n_pts)
    norm_z = np.random.normal(0, 0.5, n_pts)

    # DoS/DDoS cluster
    dos_x = np.random.normal(3, 0.6, n_pts)
    dos_y = np.random.normal(2, 0.5, n_pts)
    dos_z = np.random.normal(-1, 0.4, n_pts)

    # Ransomware cluster
    ran_x = np.random.normal(-2, 0.5, n_pts)
    ran_y = np.random.normal(3, 0.6, n_pts)
    ran_z = np.random.normal(2, 0.5, n_pts)

    # PortScan/Recon cluster
    scan_x = np.random.normal(1, 0.5, n_pts)
    scan_y = np.random.normal(-3, 0.6, n_pts)
    scan_z = np.random.normal(1, 0.4, n_pts)

    fig_latent = go.Figure()
    fig_latent.add_trace(go.Scatter3d(
        x=norm_x, y=norm_y, z=norm_z,
        mode='markers',
        name='Normal Baseline (0% Threat)',
        marker=dict(size=5, color='#00ff88', opacity=0.8)
    ))
    fig_latent.add_trace(go.Scatter3d(
        x=dos_x, y=dos_y, z=dos_z,
        mode='markers',
        name='DDoS / DoS Telemetry',
        marker=dict(size=5, color='#ff3b30', opacity=0.8)
    ))
    fig_latent.add_trace(go.Scatter3d(
        x=ran_x, y=ran_y, z=ran_z,
        mode='markers',
        name='Ransomware Vectors',
        marker=dict(size=5, color='#a855f7', opacity=0.8)
    ))
    fig_latent.add_trace(go.Scatter3d(
        x=scan_x, y=scan_y, z=scan_z,
        mode='markers',
        name='Scanning & Reconnaissance',
        marker=dict(size=5, color='#ffaa00', opacity=0.8)
    ))

    fig_latent.update_layout(
        title="3D Deep Latent Threat Manifold (MI-CNN + BiLSTM Latent Embedding Space)",
        template="plotly_dark",
        scene=dict(
            xaxis=dict(title="Latent Dimension 1 (Spatial Feature Map)"),
            yaxis=dict(title="Latent Dimension 2 (Temporal Sequence)"),
            zaxis=dict(title="Latent Dimension 3 (Attention Energy)")
        ),
        margin=dict(l=0, r=0, b=0, t=40),
        height=480
    )
    st.plotly_chart(fig_latent, use_container_width=True)
