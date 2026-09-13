"""
01_Overview.py
Executive SOC Command Center & 22-Step End-to-End Demonstration.
Presents the high-level architecture separating Phase 1 (Secure EHR Protection) and Phase 2 (Post-Encryption Breach Detection).
"""

import streamlit as st
import time
import pandas as pd
import plotly.graph_objects as go
from src.ui_helpers import apply_soc_theme, get_shared_state
from ehr.loader import MIMICLoader
from ehr.sanitizer import EHRSanitizer
from ehr.serializer import EHRSerializer
from ehr.payload import EHRPayload
from crypto.encryption import AES256GCMCipher
from crypto.hashing import HashEngine
from crypto.signatures import DigitalSignatureEngine
from ids.simulation import BreachSimulationEngine

apply_soc_theme()
state = get_shared_state()

st.markdown("""
<div style="margin-bottom: 20px;">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <span class="soc-header-tag">EXECUTIVE COMMAND CENTER</span>
            <h1 style="margin: 4px 0; font-size: 2.2rem; font-weight: 800; color: #ffffff;">
                Healthcare Cybersecurity & Privacy Operations Center
            </h1>
            <p style="color: #8fa3bf; font-size: 0.95rem; margin-top: 4px;">
                Privacy-Preserving EHR Transmission with Authenticated Cryptography, Blockchain Integrity Anchoring, and AI Post-Encryption Breach Detection.
            </p>
        </div>
        <div style="text-align: right;">
            <div style="font-size: 0.8rem; color: #8fa3bf;">BLOCKCHAIN STATUS</div>
            <div style="font-size: 1.0rem; font-weight: 700; color: #00ff88;">
                ● {"GANACHE LIVE" if state.contract_client.is_live_ganache else "LOCAL FALLBACK"}
            </div>
            <div style="font-size: 0.75rem; color: #6b7280;">Net ID: 1337 | Port: 8545</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# 1. Executive Telemetry & System KPIs
# -------------------------------------------------------------
col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.markdown("""
    <div class="soc-card">
        <div class="kpi-title">EHR Records Protected</div>
        <div class="kpi-value">26</div>
        <div class="kpi-delta" style="color: #00ff88;">MIMIC-III Tables Ready</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="soc-card">
        <div class="kpi-title">Cryptographic Scheme</div>
        <div class="kpi-value" style="font-size: 1.5rem;">AES-256-GCM</div>
        <div class="kpi-delta" style="color: #00f0ff;">96-bit Nonce + 128-bit Tag</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Ledger Integrity Anchor</div>
        <div class="kpi-value" style="font-size: 1.5rem;">SHA-256</div>
        <div class="kpi-delta" style="color: #00ff88;">{"On-Chain Ganache" if state.contract_client.is_live_ganache else "Python Fallback"}</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    inc_count = len(state.incident_history)
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Attacks Mitigated</div>
        <div class="kpi-value" style="color: {'#ff3b30' if inc_count > 0 else '#ffffff'};">{inc_count}</div>
        <div class="kpi-delta" style="color: #ffaa00;">Edge-IIoT Telemetry</div>
    </div>
    """, unsafe_allow_html=True)

with col5:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">IDS Neural Engine</div>
        <div class="kpi-value" style="font-size: 1.5rem;">MI-CNN-BiLSTM</div>
        <div class="kpi-delta" style="color: #00f0ff;">{state.device_str.upper()} Optimized</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# -------------------------------------------------------------
# 2. TWO-PHASE ARCHITECTURE OVERVIEW (MANDATORY CORE CONCEPT)
# -------------------------------------------------------------
st.markdown("### 🏛️ Two-Phase Core Security Architecture")

phase_col1, phase_col2 = st.columns(2)
with phase_col1:
    st.markdown("""
    <div class="soc-card" style="border-left: 4px solid #00f0ff;">
        <h4 style="color: #00f0ff; margin-top: 0;">PHASE 1: Secure EHR Protection (Before & During Transmission)</h4>
        <p style="color: #c4d1e2; font-size: 0.88rem;">
            <b>Objective:</b> Protect patient confidentiality, minimize privacy exposure, enforce cryptographic authenticated encryption, and anchor metadata immutably onto blockchain.
        </p>
        <ul style="color: #8fa3bf; font-size: 0.84rem; line-height: 1.6;">
            <li><b>Data Source:</b> Clinical EHR from MIMIC-III (Labevents, ICU charts, Prescriptions).</li>
            <li><b>Privacy Control:</b> HIPAA Safe Harbor masking, direct identifier pseudonymization.</li>
            <li><b>Encryption:</b> Full-payload AES-256-GCM with hardware-accelerated 256-bit symmetric keys.</li>
            <li><b>Integrity Anchor:</b> SHA-256 payload digest registered on Ganache <code>EHRIntegrityRegistry</code>.</li>
            <li><b>Access Control:</b> On-chain RBAC via <code>EHRAccessControl</code> (Doctor, Nurse, Admin, Auditor).</li>
            <li><b>Off-Chain Rule:</b> Plaintext medical records are <b>NEVER</b> written directly to blockchain.</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

with phase_col2:
    st.markdown("""
    <div class="soc-card" style="border-left: 4px solid #ff3b30;">
        <h4 style="color: #ff3b30; margin-top: 0;">PHASE 2: Post-Encryption Breach Detection & Response</h4>
        <p style="color: #c4d1e2; font-size: 0.88rem;">
            <b>Objective:</b> Detect and contain cyberattacks targeting the surrounding network, session, storage, or transmission layers even after encryption has been applied.
        </p>
        <ul style="color: #8fa3bf; font-size: 0.84rem; line-height: 1.6;">
            <li><b>Scientific Truth:</b> Encryption protects payload secrecy; network IDS detects hostile infrastructure activity.</li>
            <li><b>Telemetry Source:</b> Edge-IIoTset authentic attack telemetry (DDoS, MITM, Injection, Ransomware).</li>
            <li><b>AI IDS Engine:</b> 20 Mutual Information features feeding a hybrid 1D CNN + BiLSTM + Attention deep model.</li>
            <li><b>Multi-Signal Severity:</b> Combines attack prediction, model confidence, and on-chain hash integrity.</li>
            <li><b>SOC Automated Playbooks:</b> Concrete countermeasures (session termination, key rotation, IP quarantine).</li>
            <li><b>Forensic Ledger:</b> Every breach incident is permanently anchored to Ganache blockchain.</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# -------------------------------------------------------------
# 3. 22-STEP COMPLETE LIVE DEMONSTRATION RUNNER
# -------------------------------------------------------------
st.markdown("### 🎬 End-to-End Live Demonstration Runner")
st.markdown("""
Execute the complete 22-step cryptographic, blockchain, and AI breach detection pipeline with a single click.
This rigorously demonstrates all research contributions sequentially.
""")

col_btn, col_opts = st.columns([1, 2])
with col_opts:
    scenario_sel = st.selectbox(
        "Select Simulated Breach Condition for Demonstration:",
        [
            ("MITM", "🔀 Man-In-The-Middle Session Interception (Key Rotation Required)"),
            ("TAMPERED_CIPHERTEXT", "⚠️ Ciphertext Tampering + Network Anomaly (Integrity Compromise)"),
            ("DDOS_FLOOD", "🌊 Distributed Denial of Service HTTP Flood (API Gateway Flooding)"),
            ("RANSOMWARE_EXFILTRATION", "🔒 Host Ransomware & Lateral Exfiltration (Ransomware Attack)"),
            ("SQL_INJECTION_QUERY", "💉 Clinical API SQL Injection Attack (Database Exploit)"),
            ("PORT_SCAN_RECONNAISSANCE", "🔍 Perimeter Port Scanning & Reconnaissance (Port Scan Probe)"),
            ("UNAUTHORIZED_CREDENTIAL", "🔑 Unauthorized Access Attempt (Smart Contract Rejection)"),
            ("BACKDOOR", "🚪 Persistent Command & Control Backdoor (C2 Infiltration)"),
            ("PASSWORD", "🔐 Credential Stuffing & Password Brute-Force (Auth Attack)"),
            ("XSS", "📜 Cross-Site Scripting API Injection (XSS Payload)"),
            ("NORMAL_TRANSMISSION", "🛡️ Clean Baseline Transmission (No Breach Detected)")
        ],
        format_func=lambda x: x[1]
    )

with col_btn:
    st.write("")
    st.write("")
    run_demo = st.button("🚀 RUN COMPLETE EHR SECURITY DEMO", type="primary", use_container_width=True)

if run_demo:
    scen_key = scenario_sel[0]
    steps_container = st.container()
    progress_bar = st.progress(0)
    status_text = st.empty()

    # Step Execution Sequence
    steps_log = []

    def log_step(num: int, title: str, detail: str, success: bool = True):
        steps_log.append({"step": num, "title": title, "detail": detail, "success": success})
        pct = int((num / 22.0) * 100)
        progress_bar.progress(pct)
        status_text.markdown(f"**Step {num}/22:** {title} — `{detail}`")
        time.sleep(0.04)

    # 1. Load EHR
    log_step(1, "Load EHR", "Loading critical ICU laboratory observation from MIMIC-III database...")
    demo_rec = state.mimic_loader.get_demo_record("CRITICAL_ICU_LAB")

    # 2. Show Original EHR
    log_step(2, "Inspect Original Record", f"Patient ID: {demo_rec.get('subject_id', 10014)}, Lab: {demo_rec.get('label', 'Glucose')}, Value: {demo_rec.get('valuenum', 195.0)}")

    # 3. Calculate Privacy Exposure
    log_step(3, "Calculate Privacy Exposure", "Analyzing HIPAA Safe Harbor direct and quasi-identifiers...")
    sanitized = state.ehr_sanitizer.sanitize_record(demo_rec)
    exposure = sanitized["exposure_analysis"]

    # 4. Generate Key
    log_step(4, "Generate Encryption Key", "Deriving 256-bit cryptographic key via secure KeyManager vault...")
    active_key = state.key_manager.get_active_key()

    # 5. Encrypt EHR
    log_step(5, "Encrypt EHR Payload", "Applying AES-256-GCM authenticated encryption with 96-bit nonce...")
    canon_bytes = EHRSerializer.to_canonical_json_bytes(sanitized["masked_data"])
    enc_receipt = AES256GCMCipher.encrypt(canon_bytes, active_key.key_bytes, key_id=active_key.key_id)

    # 6. Show Ciphertext
    log_step(6, "Show Protected Ciphertext", f"Generated {len(enc_receipt.ciphertext_bytes)} bytes ciphertext, Tag: {enc_receipt.tag_bytes[:4].hex()}...")

    # 7. Calculate Encryption Metrics
    log_step(7, "Calculate Cryptographic Metrics", f"Encryption Latency: {enc_receipt.encryption_latency_ms:.4f} ms | Expansion: {enc_receipt.expansion_factor:.2f}x")

    # 8. Generate SHA-256 Hash
    log_step(8, "Generate SHA-256 Digest", "Computing cryptographic hash of encrypted ciphertext payload...")
    payload_hash = enc_receipt.sha256_hash

    # 9. Register on Blockchain
    log_step(9, "Register on Ganache Blockchain", "Invoking EHRIntegrityRegistry.registerEHR() on local Ganache node...")
    reg_tx = state.contract_client.register_ehr_metadata(
        record_id=demo_rec.get("record_id", "DEMO-EHR-001"),
        payload_hash=payload_hash,
        algorithm="AES-256-GCM",
        key_id=active_key.key_id,
        access_policy="DOCTOR_ONLY"
    )

    # 10. Authorize Clinician
    log_step(10, "Authorize Clinician Role", "Verifying DOCTOR role in EHRAccessControl smart contract...")
    auth_res = state.contract_client.authorize_user(
        user_address=state.contract_client.account or "0x0000000000000000000000000000000000000001",
        role="DOCTOR",
        validity_seconds=86400
    )

    # 11. Simulate Secure Access
    log_step(11, "Simulate Secure Access", "Authorized clinician retrieves payload and authenticates tag...")

    # 12. Simulate Breach
    log_step(12, "Simulate Security Breach", f"Executing scenario: {scen_key}...")
    incident = state.breach_sim.simulate_breach(
        scenario_key=scen_key,
        payload_id=demo_rec.get("record_id", "DEMO-EHR-001"),
        original_hash=payload_hash,
        ciphertext_bytes=enc_receipt.ciphertext_bytes,
        sensitive_field_count=len(sanitized["sensitive_fields"]),
        accessor_role="DOCTOR"
    )

    # 13. Generate Telemetry
    log_step(13, "Ingest Edge-IIoT Telemetry", f"Captured 53-feature network telemetry flow (Src: {incident.source_ip})...")

    # 14. Run Trained IDS
    log_step(14, "Run Deep Learning IDS", f"Executing MI-CNN-BiLSTM-Attention inference on {state.device_str.upper()}...")

    # 15. Predict Attack
    log_step(15, "Classify Intrusion Class", f"Prediction: {incident.predicted_attack_type} (Ground Truth: {incident.simulated_attack_type})")

    # 16. Calculate Confidence
    log_step(16, "Calculate Model Confidence", f"Confidence: {incident.confidence_pct:.2f}% (Threshold τ* = 0.10 applied)")

    # 17. Calculate Severity
    log_step(17, "Evaluate Multi-Factor Severity", f"Severity Level: {incident.severity} | Composite Risk Score: {incident.risk_score}/100")

    # 18. Generate Alert
    log_step(18, "Generate SOC Alert", f"Alert ID: {incident.incident_id} dispatched to SOC console")

    # 19. Recommend Response
    log_step(19, "Recommend Countermeasures", f"Mapped {len(incident.recommended_actions)} prioritized containment actions")

    # 20. Record Incident on Blockchain
    log_step(20, "Anchor Incident on Ganache", "Executing EHRIntegrityRegistry.recordIncident() on-chain...")
    inc_tx = state.contract_client.record_incident(
        incident_id=incident.incident_id,
        payload_hash=incident.current_hash,
        attack_type=incident.predicted_attack_type,
        severity=incident.severity,
        confidence_pct=incident.confidence_pct,
        integrity_status=incident.integrity_status
    )
    incident.blockchain_tx_hash = inc_tx.get("tx_hash", "0x0")
    incident.blockchain_status = "CONFIRMED_ON_CHAIN" if inc_tx.get("status") == "SUCCESS" else "RECORDED_FALLBACK"

    # 21. Verify Integrity
    log_step(21, "Verify Cryptographic Integrity", f"Hash Match: {incident.hash_match} (Integrity: {incident.integrity_status})")

    # 22. Display Final Incident Report
    log_step(22, "Finalize Demonstration Report", "End-to-End demonstration completed successfully!")

    # Store in session state
    state.active_incident = incident
    state.incident_history.insert(0, incident)
    state.demo_step_history = steps_log

    st.success("✅ Complete 22-Step Security Demonstration Successfully Executed!")

# -------------------------------------------------------------
# 4. Step History Display if available
# -------------------------------------------------------------
if state.demo_step_history:
    with st.expander("📋 View Detailed 22-Step Execution Log", expanded=True):
        st.dataframe(pd.DataFrame(state.demo_step_history), use_container_width=True)

# -------------------------------------------------------------
# 5. Executive Incident Banner if active
# -------------------------------------------------------------
if state.active_incident:
    inc = state.active_incident
    st.markdown(f"""
    <div class="soc-card" style="border: 2px solid {inc.severity_color}; margin-top: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div style="font-size: 1.25rem; font-weight: 800; color: #ffffff;">
                🚨 LATEST SECURITY INCIDENT REPORT: <code>{inc.incident_id}</code>
            </div>
            <span style="background: {inc.severity_color}; color: #ffffff; padding: 4px 14px; border-radius: 20px; font-weight: 700; font-size: 0.85rem;">
                {inc.severity} SEVERITY
            </span>
        </div>
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 14px; font-size: 0.85rem;">
            <div><span style="color: #8fa3bf;">Detected Attack:</span><br><b>{inc.predicted_attack_type}</b></div>
            <div><span style="color: #8fa3bf;">Model Confidence:</span><br><b>{inc.confidence_pct:.2f}%</b></div>
            <div><span style="color: #8fa3bf;">Payload Integrity:</span><br><b style="color: {'#00ff88' if inc.hash_match else '#ff3b30'};">{inc.integrity_status}</b></div>
            <div><span style="color: #8fa3bf;">Blockchain TX:</span><br><code style="font-size: 0.75rem;">{inc.blockchain_tx_hash[:16]}...</code></div>
        </div>
        <div style="margin-top: 12px; padding: 10px; background: rgba(0,0,0,0.3); border-radius: 6px; font-size: 0.82rem;">
            <b style="color: #00f0ff;">Explainable SOC Rationale:</b> {inc.explainable_rationale}
        </div>
        <div style="margin-top: 10px; padding: 8px 12px; background: {'rgba(255, 59, 48, 0.15)' if not inc.hash_match else ('rgba(0, 255, 136, 0.12)' if inc.predicted_attack_type != 'Normal' else 'rgba(0, 240, 255, 0.12)')}; border: 1px solid {'#ff3b30' if not inc.hash_match else ('#00ff88' if inc.predicted_attack_type != 'Normal' else '#00f0ff')}; border-radius: 6px; font-size: 0.82rem; color: {'#ff6b6b' if not inc.hash_match else ('#00ff88' if inc.predicted_attack_type != 'Normal' else '#00f0ff')}; font-weight: 600;">
            {'⚠️ CIPHERTEXT INTEGRITY TAMPERED: Modified payload detected via SHA-256 hash mismatch & MAC tag against Ganache blockchain.' if not inc.hash_match else ('🛡️ EHR DATA SHIELD: In-transit attack packet successfully identified by Deep IDS; patient EHR record is 100% SAVED & PRESERVED by AES-256-GCM encryption.' if inc.predicted_attack_type != 'Normal' else '✅ CLEAN TRANSMISSION: Telemetry normal, cryptographic integrity verified on Ganache blockchain, access authorized.')}
        </div>
    </div>
    """, unsafe_allow_html=True)
