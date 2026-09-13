"""
12_Attack_Classification.py
Attack Classification Taxonomy & Multi-Class Forensic Confusion Matrix.
Presents the 15-class Edge-IIoTset attack breakdown, per-class metrics, and error matrices.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from src.ui_helpers import apply_soc_theme, get_shared_state

apply_soc_theme()
state = get_shared_state()

st.markdown("""
<div style="margin-bottom: 20px;">
    <span class="soc-header-tag">ATTACK CLASSIFICATION TAXONOMY</span>
    <h1 style="margin: 4px 0; font-size: 2.0rem; font-weight: 800; color: #ffffff;">
        15-Class Attack Classification & Confusion Matrix
    </h1>
    <p style="color: #8fa3bf; font-size: 0.92rem;">
        Fine-grained classification of cybersecurity intrusions targeting the transmission and IoT gateway layers.
        All metrics derived strictly from the held-out test partition.
    </p>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# 1. Per-Class Performance Table
# -------------------------------------------------------------
st.markdown("### 📊 Per-Class Evaluation Metrics (Held-Out Test Set)")

try:
    df_per_class = pd.read_csv("artifacts/results/per_class_metrics.csv")
    st.dataframe(df_per_class, use_container_width=True, hide_index=True)
except Exception as e:
    st.warning(f"Note: Could not load per_class_metrics.csv ({e}).")

st.markdown("---")

# -------------------------------------------------------------
# 2. Multi-Class Confusion Matrix Heatmap
# -------------------------------------------------------------
st.markdown("### 🎯 Multi-Class Confusion Matrix Heatmap")

# Interactive display controls
col_ctrl1, col_ctrl2, col_ctrl3 = st.columns([1.5, 1.2, 1.3])
with col_ctrl1:
    cm_view_mode = st.radio(
        "Matrix Data Metric:",
        ["Normalized Recall (0.00 – 1.00)", "Raw Sample Counts (Integers)"],
        horizontal=True,
        key="cm_view_mode"
    )

with col_ctrl2:
    zero_display = st.selectbox(
        "Zero Values Display:",
        ["Show All Values (0.00 / 0)", "Blank Zero Cells (Clean View)"],
        index=0,
        key="zero_display"
    )

with col_ctrl3:
    color_theme = st.selectbox(
        "Color Palette:",
        ["Viridis (Perceptual)", "Plasma", "Turbo", "Blues", "Tealgrn"],
        index=0,
        key="color_theme"
    )

palette_map = {
    "Viridis (Perceptual)": "Viridis",
    "Plasma": "Plasma",
    "Turbo": "Turbo",
    "Blues": "Blues",
    "Tealgrn": "Tealgrn"
}
selected_palette = palette_map[color_theme]

try:
    if "Normalized" in cm_view_mode:
        df_cm = pd.read_csv("artifacts/results/normalized_confusion_matrix.csv", index_col=0)
        z_label = "Recall"
        chart_title = "Normalized Multi-Class Confusion Matrix (Row Recall with Cell Values)"
        
        if zero_display == "Show All Values (0.00 / 0)":
            text_matrix = [[f"{val:.2f}" for val in row] for row in df_cm.values]
        else:
            text_matrix = [[f"{val:.2f}" if val > 0.0001 else "" for val in row] for row in df_cm.values]
    else:
        df_cm = pd.read_csv("artifacts/results/multiclass_confusion_matrix.csv", index_col=0)
        z_label = "Sample Count"
        chart_title = "Multi-Class Confusion Matrix (Raw Test Partition Sample Counts)"
        
        if zero_display == "Show All Values (0.00 / 0)":
            text_matrix = [[f"{int(val):,d}" for val in row] for row in df_cm.values]
        else:
            text_matrix = [[f"{int(val):,d}" if val > 0 else "" for val in row] for row in df_cm.values]

    fig_cm = px.imshow(
        df_cm,
        labels=dict(x="Predicted Class", y="Actual Class", color=z_label),
        x=df_cm.columns,
        y=df_cm.index,
        color_continuous_scale=selected_palette,
        title=chart_title,
        template="plotly_dark",
        aspect="auto"
    )
    
    fig_cm.update_traces(
        text=text_matrix,
        texttemplate="%{text}",
        textfont=dict(size=10, family="monospace, 'SF Mono', Consolas, sans-serif"),
        hovertemplate="<b>Actual:</b> %{y}<br><b>Predicted:</b> %{x}<br><b>" + z_label + ":</b> %{z}<extra></extra>"
    )
    
    fig_cm.update_layout(
        height=680,
        xaxis=dict(
            tickangle=-45,
            title_font=dict(size=13, color="#ffffff"),
            tickfont=dict(size=10.5, color="#c4d1e2")
        ),
        yaxis=dict(
            title_font=dict(size=13, color="#ffffff"),
            tickfont=dict(size=10.5, color="#c4d1e2")
        ),
        coloraxis_colorbar=dict(
            title=z_label,
            tickfont=dict(size=10, color="#c4d1e2")
        ),
        margin=dict(l=60, r=40, b=90, t=50)
    )
    
    st.plotly_chart(fig_cm, use_container_width=True)
except Exception as e:
    st.error(f"Error loading confusion matrix: {e}")

st.markdown("---")

# -------------------------------------------------------------
# 3. 5 High-Level Attack Categories Mapping
# -------------------------------------------------------------
st.markdown("### 🏷️ Mapping to High-Level Edge-IIoT Threat Families")

threat_df = pd.DataFrame([
    {"Threat Family": "DDoS / DoS Flooding", "Edge-IIoT Sub-Classes": "DDoS_HTTP, DDoS_TCP, DDoS_UDP, DDoS_ICMP", "Target Layer": "Network & Gateway Availability", "Primary Impact": "Denial of clinical transmission"},
    {"Threat Family": "Man-In-The-Middle (MITM)", "Edge-IIoT Sub-Classes": "MITM, ARP Poisoning, DNS Spoofing", "Target Layer": "Session & Transmission Integrity", "Primary Impact": "Ciphertext interception / replay"},
    {"Threat Family": "Injection & Web API Attacks", "Edge-IIoT Sub-Classes": "SQL_injection, XSS, Uploading", "Target Layer": "Application & EHR Query API", "Primary Impact": "Unauthorized data extraction"},
    {"Threat Family": "Malware & Ransomware", "Edge-IIoT Sub-Classes": "Ransomware, Backdoor", "Target Layer": "Storage Node & Host OS", "Primary Impact": "Host volume encryption / key theft"},
    {"Threat Family": "Information Gathering", "Edge-IIoT Sub-Classes": "Port_Scanning, Vulnerability_scanner, Fingerprinting", "Target Layer": "Reconnaissance / Perimeter", "Primary Impact": "Pre-attack vulnerability mapping"}
])
st.dataframe(threat_df, use_container_width=True, hide_index=True)
