"""
15_Alert_Center.py
Security Operations Center (SOC) Alert Center & Incident Dispatch.
Formats, displays, and dispatches high-priority cybersecurity alerts with blockchain evidence anchors.
"""

import streamlit as st
import pandas as pd
from src.ui_helpers import apply_soc_theme, get_shared_state

apply_soc_theme()
state = get_shared_state()
incidents = state.incident_history

st.markdown("""
<div style="margin-bottom: 20px;">
    <span class="soc-header-tag">SOC INCIDENT DISPATCH</span>
    <h1 style="margin: 4px 0; font-size: 2.0rem; font-weight: 800; color: #ffffff;">
        Security Operations Center (SOC) Alert Center
    </h1>
    <p style="color: #8fa3bf; font-size: 0.92rem;">
        Real-time dispatch of formal SOC security alerts correlating AI intrusion classifications,
        cryptographic hash verifications, and immutable Ganache blockchain incident proofs.
    </p>
</div>
""", unsafe_allow_html=True)

if not incidents:
    st.info("🛡️ No active security incidents in memory. You can generate one via Phase 2 — Breach Simulation or the 22-Step Demo on the Executive Overview.")
    st.stop()

# -------------------------------------------------------------
# 1. Active High-Priority Alert Banner (Section 32 Format)
# -------------------------------------------------------------
latest_inc = incidents[0]

st.markdown(f"""
<div class="soc-card" style="border: 2px solid {latest_inc.severity_color}; background: rgba(18, 26, 43, 0.9);">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <span style="font-size: 1.3rem; font-weight: 800; color: {latest_inc.severity_color};">
            🚨 {latest_inc.severity} EHR SECURITY ALERT
        </span>
        <span style="background: {latest_inc.severity_color}; color: #ffffff; padding: 4px 12px; border-radius: 16px; font-weight: 700; font-size: 0.8rem;">
            INCIDENT ID: {latest_inc.incident_id}
        </span>
    </div>
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; font-size: 0.88rem;">
        <div><span style="color: #8fa3bf;">Protected Record:</span><br><code>{latest_inc.payload_id}</code></div>
        <div><span style="color: #8fa3bf;">Detected Attack:</span><br><b>{latest_inc.predicted_attack_type}</b></div>
        <div><span style="color: #8fa3bf;">Model Confidence:</span><br><b>{latest_inc.confidence_pct:.2f}%</b></div>
        <div><span style="color: #8fa3bf;">Integrity Status:</span><br><b style="color: {'#00ff88' if latest_inc.hash_match else '#ff3b30'};">{latest_inc.integrity_status}</b></div>
        <div><span style="color: #8fa3bf;">Timestamp:</span><br>{latest_inc.iso_time}</div>
        <div><span style="color: #8fa3bf;">Source / Host IP:</span><br><code>{latest_inc.source_ip}</code></div>
        <div><span style="color: #8fa3bf;">Blockchain Proof:</span><br><code style="font-size: 0.75rem;">{latest_inc.blockchain_tx_hash or '0xPending'}</code></div>
        <div><span style="color: #8fa3bf;">Ledger Status:</span><br><b style="color: #00ff88;">{latest_inc.blockchain_status}</b></div>
        <div><span style="color: #8fa3bf;">EHR Payload Security:</span><br><b style="color: #00ff88;">SAVED (AES-256-GCM)</b></div>
    </div>
    <div style="margin-top: 16px; padding: 12px; background: rgba(0,0,0,0.3); border-radius: 8px;">
        <b style="color: #00f0ff;">Priority Recommended Actions:</b>
        <ol style="margin-top: 6px; margin-bottom: 0; padding-left: 20px; font-size: 0.84rem; color: #c4d1e2;">
            {"".join(f"<li>{a}</li>" for a in latest_inc.recommended_actions[:6])}
        </ol>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# -------------------------------------------------------------
# 2. Historical Alerts Table
# -------------------------------------------------------------
st.markdown(f"### 📋 Incident History & Audit Log ({len(incidents)} Total Recorded)")

df_history = pd.DataFrame([
    {
        "Incident ID": inc.incident_id,
        "Timestamp": inc.iso_time,
        "Payload ID": inc.payload_id,
        "Attack Type": inc.predicted_attack_type,
        "Confidence": f"{inc.confidence_pct:.2f}%",
        "Risk Score": f"{inc.risk_score:.1f}/100",
        "Severity": inc.severity,
        "Integrity": inc.integrity_status,
        "EHR Data Status": "🛡️ SAVED (AES-256-GCM)" if inc.predicted_attack_type != "Normal" else "✅ CLEAN",
        "Lifecycle": inc.lifecycle_status,
        "Blockchain TX": (inc.blockchain_tx_hash[:16] + "...") if inc.blockchain_tx_hash else "N/A"
    }
    for inc in incidents
])

st.dataframe(df_history, use_container_width=True, hide_index=True)
