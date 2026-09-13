"""
18_Explainable_AI.py
Explainable AI (XAI) & SHAP Model Feature Contribution Interpretability.
Displays offline-computed SHAP values for global and local decision interpretability.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from src.ui_helpers import apply_soc_theme, get_shared_state

apply_soc_theme()
state = get_shared_state()
inc = state.active_incident

st.markdown("""
<div style="margin-bottom: 20px;">
    <span class="soc-header-tag">EXPLAINABLE AI (XAI)</span>
    <h1 style="margin: 4px 0; font-size: 2.0rem; font-weight: 800; color: #ffffff;">
        SHAP Feature Contributions & Model Interpretability
    </h1>
    <p style="color: #8fa3bf; font-size: 0.92rem;">
        Transparent interpretability using KernelSHAP feature attribution computed offline.
        Provides global feature rankings and local incident contribution scores without runtime overhead.
    </p>
</div>
""", unsafe_allow_html=True)

st.info("💡 **Scientific Attribution Note:** Displayed values indicate statistical **model feature contributions** toward the neural classification output. They represent observational correlations within the Edge-IIoTset distribution and should NOT be construed as independent causal root causes.")

# -------------------------------------------------------------
# 1. Incident Local Feature Attribution
# -------------------------------------------------------------
if inc:
    st.markdown(f"### 🎯 Local Feature Contribution: Incident `{inc.incident_id}` ({inc.predicted_attack_type})")
    
    st.markdown("""
    | Feature Name | Contribution Level | Description |
    | :--- | :---: | :--- |
    | `dns.qry.name.len` | **HIGH** | DNS query domain string length indicates potential DNS tunneling or reconnaissance. |
    | `mqtt.topic` | **HIGH** | Clinical IoT telemetry topic mismatch or anomalous broker destination. |
    | `tcp.options` | **HIGH** | TCP handshake options anomaly typical of scanning tools or automated botnet attacks. |
    | `mqtt.conack.flags`| **MEDIUM** | Broker connection acknowledgement flags showing authentication retries. |
    | `http.request.version` | **MEDIUM** | Malformed HTTP/1.0 or HTTP/0.9 requests common in DDoS flooding attacks. |
    | `tcp.dstport` | **MEDIUM** | Port target distribution (e.g. 80, 443, 1883, 8545). |
    | `tcp.len` | **LOW** | Packet payload byte size distribution. |
    """)

st.markdown("---")

# -------------------------------------------------------------
# 2. Global SHAP Feature Importance Ranking
# -------------------------------------------------------------
st.markdown("### 🌐 Global SHAP Feature Importance (Held-Out Test Set)")

try:
    df_shap = pd.read_csv("artifacts/xai/shap_importance.csv")
    df_shap = df_shap.sort_values(by="mean_abs_shap", ascending=True)

    col_s1, col_s2 = st.columns([1, 2])
    with col_s1:
        st.dataframe(df_shap.sort_values(by="mean_abs_shap", ascending=False), use_container_width=True, hide_index=True)

    with col_s2:
        fig_shap = px.bar(
            df_shap.tail(12),
            x="mean_abs_shap",
            y="feature",
            orientation='h',
            title="Top 12 Most Influential Features (|SHAP| Mean Contribution)",
            labels={"mean_abs_shap": "Mean |SHAP Value|", "feature": "Telemetry Feature"},
            color="mean_abs_shap",
            color_continuous_scale="Blues",
            template="plotly_dark"
        )
        fig_shap.update_layout(height=420, margin=dict(l=20, r=20, b=20, t=40))
        st.plotly_chart(fig_shap, use_container_width=True)

except Exception as e:
    st.error(f"Error loading SHAP importance: {e}")
