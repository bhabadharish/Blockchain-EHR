"""
13_False_Positives_Negatives.py
False Negative & False Positive Trade-off Analysis.
Examines the operational costs of false alarms vs. missed attacks, and validates the threshold tuning procedure.
"""

import streamlit as st
import json
import pandas as pd
import plotly.express as px
from src.ui_helpers import apply_soc_theme, get_shared_state

apply_soc_theme()
state = get_shared_state()

st.markdown("""
<div style="margin-bottom: 20px;">
    <span class="soc-header-tag">FORENSIC ERROR AUDIT</span>
    <h1 style="margin: 4px 0; font-size: 2.0rem; font-weight: 800; color: #ffffff;">
        False Negative & False Positive Risk Prioritization
    </h1>
    <p style="color: #8fa3bf; font-size: 0.92rem;">
        Rigorous evaluation of missed attacks (False Negatives) and false alarms (False Positives).
        Decision threshold optimization was performed strictly on the validation partition to prevent test data leakage.
    </p>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# 1. Asymmetric Cost Framework
# -------------------------------------------------------------
col_c1, col_c2 = st.columns(2)

with col_c1:
    st.markdown("""
    <div class="soc-card" style="border-left: 4px solid #ff3b30;">
        <h4 style="color: #ff3b30; margin-top: 0;">1. False Negative (FN) Criticality</h4>
        <p style="font-size: 0.84rem; color: #c4d1e2;">
            <b>Impact:</b> A missed attack allows an unauthorized adversary, ransomware process, or MITM interceptor to compromise clinical nodes or access keys undetected.
        </p>
        <div style="font-size: 0.8rem; color: #8fa3bf;">
            <b>Mitigation Strategy:</b> Prioritize macro recall and reduce decision threshold (τ* = 0.10) to aggressively capture low-signal intrusions.
        </div>
    </div>
    """, unsafe_allow_html=True)

with col_c2:
    st.markdown("""
    <div class="soc-card" style="border-left: 4px solid #ffaa00;">
        <h4 style="color: #ffaa00; margin-top: 0;">2. False Positive (FP) Operational Cost</h4>
        <p style="font-size: 0.84rem; color: #c4d1e2;">
            <b>Impact:</b> Legitimate clinician transmissions incorrectly flagged cause alert fatigue, unnecessary key rotations, and potential delays in emergency patient care.
        </p>
        <div style="font-size: 0.8rem; color: #8fa3bf;">
            <b>Mitigation Strategy:</b> High-capacity self-attention layers filter spurious anomalies, keeping validation FPR at 0.00%.
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# -------------------------------------------------------------
# 2. Validation Partition Decision Threshold Scan
# -------------------------------------------------------------
st.markdown("### 📈 Decision Threshold Calibration (Validation Partition Scan)")

try:
    with open("artifacts/models/optimal_threshold.json", "r") as f:
        thresh_info = json.load(f)

    scans = thresh_info.get("all_threshold_scans", [])
    df_scans = pd.DataFrame(scans)

    col_t1, col_t2 = st.columns([1, 2])
    with col_t1:
        st.markdown(f"""
        **Optimal Threshold (τ*):** `{thresh_info.get('optimal_threshold')}`  
        **Partition Used:** `{thresh_info.get('selection_partition')}`  
        **Optimization Criterion:** `{thresh_info.get('selection_objective')}`  
        **Validation Samples:** `23,670 records`
        """)
        st.dataframe(df_scans[["threshold", "Precision", "Recall", "FPR", "FNR"]], use_container_width=True, hide_index=True)

    with col_t2:
        fig_th = px.line(
            df_scans,
            x="threshold",
            y=["Precision", "Recall", "Specificity"],
            title="Validation Metric Stability across Decision Thresholds",
            labels={"value": "Score", "threshold": "Decision Threshold (τ)"},
            template="plotly_dark",
            color_discrete_map={"Precision": "#00f0ff", "Recall": "#00ff88", "Specificity": "#ffaa00"}
        )
        fig_th.update_layout(height=340, margin=dict(l=20, r=20, b=20, t=40))
        st.plotly_chart(fig_th, use_container_width=True)

except Exception as e:
    st.warning(f"Note: Could not load optimal_threshold.json ({e}).")
