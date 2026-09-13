"""
Streamlit UI/UX Theme, Glassmorphism Styling, Precomputed Artifact Caching, and State Coordinator.
Part of the PhD Research Platform for Edge-IIoT IDS with Blockchain & Quantum Security.

CRITICAL ARCHITECTURAL GUARANTEE:
Streamlit NEVER trains models, fits scalers, or recalculates MI/SHAP at runtime.
All expensive operations are loaded from artifacts/ via @st.cache_resource and @st.cache_data.
"""

import os
import time
import json
import hashlib
import joblib
import numpy as np
import pandas as pd
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, Any, List, Optional, Tuple

import torch
from src.deep_models import HybridIDSNet
from src.blockchain import BlockchainEngine
from src.crypto import CryptographicEngine
from src.streaming import LiveStreamSimulator
from src.utils import get_hardware_info, get_device

# -------------------------------------------------------------
# Dark Cybersecurity SOC CSS Theme
# -------------------------------------------------------------
SOC_CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

code, pre {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Glassmorphism SOC Cards */
.soc-card {
    background: rgba(18, 26, 43, 0.75);
    border: 1px solid rgba(0, 240, 255, 0.2);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 16px;
    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    transition: border-color 0.3s ease, transform 0.2s ease;
}

.soc-card:hover {
    border-color: rgba(0, 240, 255, 0.5);
    transform: translateY(-2px);
}

.soc-card-danger {
    background: rgba(43, 18, 26, 0.75);
    border: 1px solid rgba(255, 59, 48, 0.3);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 16px;
    box-shadow: 0 8px 32px 0 rgba(255, 59, 48, 0.15);
}

.soc-header-tag {
    display: inline-block;
    padding: 4px 12px;
    background: rgba(0, 240, 255, 0.12);
    color: #00f0ff;
    border: 1px solid #00f0ff;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
}

.kpi-title {
    font-size: 0.85rem;
    color: #8fa3bf;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 4px;
}

.kpi-value {
    font-size: 2.1rem;
    font-weight: 800;
    color: #ffffff;
    line-height: 1.1;
}

.kpi-delta {
    font-size: 0.8rem;
    color: #00ff88;
    margin-top: 4px;
}

.kpi-delta-danger {
    font-size: 0.8rem;
    color: #ff3b30;
    margin-top: 4px;
}

.badge-pill {
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 600;
}
.badge-pass { background: rgba(0, 255, 136, 0.15); color: #00ff88; border: 1px solid #00ff88; }
.badge-warn { background: rgba(255, 204, 0, 0.15); color: #ffcc00; border: 1px solid #ffcc00; }
.badge-fail { background: rgba(255, 59, 48, 0.15); color: #ff3b30; border: 1px solid #ff3b30; }

.section-callout {
    border-left: 4px solid #00f0ff;
    background: rgba(0, 240, 255, 0.05);
    padding: 12px 16px;
    border-radius: 0 8px 8px 0;
    margin: 12px 0;
    font-size: 0.9rem;
}

/* Sidebar Navigation Enhancements */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0b111e 0%, #060a12 100%) !important;
    border-right: 1px solid rgba(0, 240, 255, 0.15) !important;
}

[data-testid="stSidebarNav"] {
    padding-top: 0.5rem;
}

[data-testid="stSidebarNav"] span {
    font-size: 0.85rem !important;
    font-weight: 500 !important;
    letter-spacing: 0.2px;
}

[data-testid="stSidebarNav"] a {
    border-radius: 8px !important;
    margin: 2px 4px !important;
    padding: 6px 12px !important;
    transition: all 0.25s ease !important;
    border: 1px solid transparent !important;
}

[data-testid="stSidebarNav"] a:hover {
    background: rgba(0, 240, 255, 0.08) !important;
    border: 1px solid rgba(0, 240, 255, 0.35) !important;
    transform: translateX(4px);
}

[data-testid="stSidebarNav"] a[aria-current="page"] {
    background: linear-gradient(90deg, rgba(0, 240, 255, 0.16) 0%, rgba(0, 255, 136, 0.08) 100%) !important;
    border: 1px solid #00f0ff !important;
    box-shadow: 0 0 14px rgba(0, 240, 255, 0.25) !important;
}

[data-testid="stSidebarNav"] a[aria-current="page"] span {
    color: #00f0ff !important;
    font-weight: 700 !important;
}

/* Sidebar Branding & Telemetry Cards */
.sidebar-soc-brand {
    background: rgba(18, 26, 43, 0.85);
    border: 1px solid rgba(0, 240, 255, 0.3);
    border-radius: 10px;
    padding: 14px;
    margin-bottom: 12px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
}

.sidebar-telemetry-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    background: rgba(0, 255, 136, 0.1);
    color: #00ff88;
    border: 1px solid rgba(0, 255, 136, 0.3);
    border-radius: 12px;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.5px;
}

.pulse-dot {
    width: 7px;
    height: 7px;
    background: #00ff88;
    border-radius: 50%;
    box-shadow: 0 0 8px #00ff88;
    display: inline-block;
}
</style>
"""

def apply_soc_theme():
    """Injects dark SOC CSS stylesheet."""
    st.markdown(SOC_CUSTOM_CSS, unsafe_allow_html=True)


# -------------------------------------------------------------
# STAGE 2: Cached Artifact Loaders (@st.cache_resource)
# -------------------------------------------------------------
@st.cache_resource
def load_production_model() -> Tuple[Any, str, bool]:
    """
    Loads production model. Falls back to classical model if deep model unavailable.
    Returns: (model, device_str, is_fallback_flag)
    """
    pt_path = "artifacts/models/production_model/production_model.pt"
    cfg_path = "artifacts/models/production_model/model_config.json"
    fb_path = "artifacts/models/production_model/production_model_classical_fallback.joblib"

    device = get_device()
    device_str = str(device)

    # Try PyTorch Deep Learning Model
    if os.path.exists(pt_path) and os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r") as f:
                cfg = json.load(f)
            input_dim = cfg.get("input_dim", 20)
            net = HybridIDSNet(
                input_dim=input_dim,
                num_classes=2,
                conv_filters=cfg.get("conv_filters", 64),
                lstm_hidden_dim=cfg.get("lstm_hidden", 64),
                attention_heads=cfg.get("attention_heads", 4),
                dense_dim=cfg.get("dense_dim", 128),
                dropout=cfg.get("dropout", 0.25)
            ).to(device)
            net.load_state_dict(torch.load(pt_path, map_location=device))
            net.eval()
            return net, device_str, False
        except Exception as e:
            st.warning(f"Note: Deep Learning model failed to load ({e}). Using classical fallback.")

    # Classical fallback
    if os.path.exists(fb_path):
        fallback_model = joblib.load(fb_path)
        return fallback_model, "CPU", True
    elif os.path.exists("artifacts/models/baseline_models/random_forest.joblib"):
        fallback_model = joblib.load("artifacts/models/baseline_models/random_forest.joblib")
        return fallback_model, "CPU", True
    else:
        raise FileNotFoundError("CRITICAL ARTIFACT ERROR: Neither production PyTorch model nor fallback model could be found.")


@st.cache_resource
def load_preprocessor():
    """Loads training-fitted unified PreprocessingPipeline."""
    p_path = "artifacts/preprocessing/preprocessor.joblib"
    if not os.path.exists(p_path):
        raise FileNotFoundError(f"Preprocessor artifact not found at {p_path}. Run train_offline.py first.")
    return joblib.load(p_path)


@st.cache_resource
def load_label_encoder():
    """Loads label encoder for 15 multiclass attack categories."""
    le_path = "artifacts/preprocessing/label_encoder.joblib"
    if not os.path.exists(le_path):
        raise FileNotFoundError(f"Label encoder artifact not found at {le_path}.")
    return joblib.load(le_path)


@st.cache_resource
def load_blockchain_engine() -> BlockchainEngine:
    """Instantiates and caches local blockchain engine and smart contract registry."""
    return BlockchainEngine()


@st.cache_resource
def load_crypto_engine() -> CryptographicEngine:
    """Instantiates and caches quantum-resistant cryptographic engine."""
    return CryptographicEngine()


# -------------------------------------------------------------
# STAGE 2: Cached Data & Metadata Loaders (@st.cache_data)
# -------------------------------------------------------------
@st.cache_data
def load_model_manifest() -> Dict[str, Any]:
    with open("artifacts/models/model_manifest.json", "r") as f:
        return json.load(f)

@st.cache_data
def load_selected_features() -> Dict[str, Any]:
    with open("artifacts/features/selected_features.json", "r") as f:
        return json.load(f)

@st.cache_data
def load_benchmark_data() -> pd.DataFrame:
    return pd.read_csv("artifacts/results/model_benchmark.csv")

@st.cache_data
def load_ablation_data() -> pd.DataFrame:
    return pd.read_csv("artifacts/results/ablation_results.csv")

@st.cache_data
def load_live_samples() -> pd.DataFrame:
    return pd.read_csv("artifacts/demo/live_samples.csv")

@st.cache_data
def load_data_quality() -> Dict[str, Any]:
    with open("artifacts/reports/data_quality.json", "r") as f:
        return json.load(f)

@st.cache_data
def load_leakage_report() -> Dict[str, Any]:
    with open("artifacts/reports/leakage_audit.json", "r") as f:
        return json.load(f)

@st.cache_data
def load_shap_importance() -> pd.DataFrame:
    return pd.read_csv("artifacts/xai/shap_importance.csv")

@st.cache_data
def load_test_predictions() -> pd.DataFrame:
    return pd.read_csv("artifacts/results/test_predictions.csv")

@st.cache_data
def load_inference_benchmark() -> Dict[str, Any]:
    with open("artifacts/results/inference_benchmark.json", "r") as f:
        return json.load(f)

@st.cache_data
def load_manuscript_reference() -> Dict[str, Any]:
    with open("artifacts/benchmarks/manuscript_reference.json", "r") as f:
        return json.load(f)

@st.cache_data
def load_hardware_report() -> Dict[str, Any]:
    with open("artifacts/reports/hardware_report.json", "r") as f:
        return json.load(f)


# -------------------------------------------------------------
# Runtime Artifact Integrity Verification
# -------------------------------------------------------------
def validate_runtime_artifacts() -> Tuple[bool, List[str]]:
    """Checks model hash, feature count, and essential artifacts on Streamlit startup."""
    diagnostics = []
    is_valid = True

    required_files = [
        "artifacts/models/production_model/production_model.pt",
        "artifacts/models/model_manifest.json",
        "artifacts/preprocessing/preprocessor.joblib",
        "artifacts/features/selected_features.json",
        "artifacts/results/model_benchmark.csv",
        "artifacts/demo/live_samples.csv"
    ]
    for rf in required_files:
        if not os.path.exists(rf):
            diagnostics.append(f"MISSING: {rf}")
            is_valid = False

    if is_valid:
        # Check model hash
        with open("artifacts/models/production_model/production_model.pt", "rb") as f:
            curr_hash = hashlib.sha256(f.read()).hexdigest()
        manifest = load_model_manifest()
        expected_hash = manifest.get("model_hash")
        if curr_hash != expected_hash:
            diagnostics.append(f"HASH MISMATCH: Expected {expected_hash[:12]}..., found {curr_hash[:12]}...")
            is_valid = False

        # Check feature count
        sel = load_selected_features()
        top_20 = sel.get("top_20", [])
        if len(top_20) != manifest.get("feature_count", 20):
            diagnostics.append(f"FEATURE COUNT MISMATCH: Expected {manifest.get('feature_count')}, found {len(top_20)}")
            is_valid = False

    return is_valid, diagnostics


# -------------------------------------------------------------
# Streamlit Shared State Coordinator
# -------------------------------------------------------------
def get_shared_state():
    """Initializes and returns cached system objects in st.session_state without ANY runtime training."""
    if "is_validated" not in st.session_state:
        valid, diags = validate_runtime_artifacts()
        st.session_state.is_validated = valid
        st.session_state.validation_diags = diags
        if not valid:
            st.error("🚨 MODEL ARTIFACT VALIDATION ERROR")
            for d in diags:
                st.error(f"- {d}")
            st.info("Execute offline pipeline: python prepare_dataset.py && python train_offline.py")

    if "model" not in st.session_state:
        model, device_str, is_fb = load_production_model()
        st.session_state.model = model
        st.session_state.device_str = device_str
        st.session_state.is_fallback = is_fb

    if "pipeline" not in st.session_state:
        st.session_state.pipeline = load_preprocessor()

    if "label_encoder" not in st.session_state:
        st.session_state.label_encoder = load_label_encoder()

    if "selected_features" not in st.session_state:
        sel = load_selected_features()
        st.session_state.selected_features = sel.get("top_20", [])

    if "blockchain" not in st.session_state:
        st.session_state.blockchain = load_blockchain_engine()

    if "crypto" not in st.session_state:
        st.session_state.crypto = load_crypto_engine()

    if "live_samples" not in st.session_state:
        st.session_state.live_samples = load_live_samples()

    if "streamer" not in st.session_state:
        st.session_state.streamer = LiveStreamSimulator(
            raw_df=st.session_state.live_samples,
            pipeline=st.session_state.pipeline,
            feature_selector=None,
            model=st.session_state.model,
            ranking_data={},
            blockchain_engine=st.session_state.blockchain,
            crypto_engine=st.session_state.crypto,
            top_k=len(st.session_state.selected_features),
            selected_features=st.session_state.selected_features,
            device=st.session_state.device_str
        )

    if "stream_events" not in st.session_state or not st.session_state.stream_events:
        # Pre-seed with 6 diverse non-duplicate streaming events from interleaved live_samples
        seed_evts = []
        base_time = time.time()
        for i in range(6):
            evt = st.session_state.streamer.process_next_event()
            # Stagger timestamps sequentially so logs do not have identical seconds
            evt["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(base_time - (5 - i) * 6))
            seed_evts.append(evt)
        st.session_state.stream_events = list(reversed(seed_evts))

    # Initialize Phase 1 & Phase 2 EHR, Cryptography, Contract, and Incident States
    if "mimic_loader" not in st.session_state:
        from ehr.loader import MIMICLoader
        st.session_state.mimic_loader = MIMICLoader()

    if "ehr_sanitizer" not in st.session_state:
        from ehr.sanitizer import EHRSanitizer
        st.session_state.ehr_sanitizer = EHRSanitizer()

    if "key_manager" not in st.session_state:
        from crypto.key_management import KeyManager
        st.session_state.key_manager = KeyManager()

    if "contract_client" not in st.session_state:
        from blockchain.contract_client import BlockchainContractClient
        st.session_state.contract_client = BlockchainContractClient()

    if "ids_preprocessor" not in st.session_state:
        from ids.preprocessing import IDSPreprocessor
        st.session_state.ids_preprocessor = IDSPreprocessor()

    if "ids_engine" not in st.session_state:
        from ids.inference import IDSInferenceEngine
        st.session_state.ids_engine = IDSInferenceEngine()

    if "breach_sim" not in st.session_state:
        from ids.simulation import BreachSimulationEngine
        st.session_state.breach_sim = BreachSimulationEngine(
            preprocessor=st.session_state.ids_preprocessor,
            inference_engine=st.session_state.ids_engine
        )

    if "active_ehr_payload" not in st.session_state:
        # Pre-load a default clinical demonstration record
        demo_rec = st.session_state.mimic_loader.get_demo_record("CRITICAL_ICU_LAB")
        from ehr.payload import EHRPayload
        from ehr.serializer import EHRSerializer
        sanitized = st.session_state.ehr_sanitizer.sanitize_record(demo_rec)
        canon_bytes = EHRSerializer.to_canonical_json_bytes(sanitized["masked_data"])
        payload = EHRPayload(
            record_id=demo_rec.get("record_id", "DEMO-EHR-001"),
            patient_pseudonym=sanitized["pseudonym"],
            raw_record=demo_rec,
            masked_record=sanitized["masked_data"],
            sensitive_fields=sanitized["sensitive_fields"],
            privacy_risk=sanitized["exposure_analysis"]["risk_level"],
            canonical_bytes=canon_bytes
        )
        st.session_state.active_ehr_payload = payload

    if "active_incident" not in st.session_state:
        st.session_state.active_incident = None

    if "incident_history" not in st.session_state:
        st.session_state.incident_history = []

    if "demo_step_history" not in st.session_state:
        st.session_state.demo_step_history = []

    return st.session_state


def reset_live_feed(state):
    """
    Completely clears all streaming event entries, resets the blockchain ledger back
    to genesis state, clears smart contract dynamic events and audit logs, and resets
    the stream simulator counters so all live metrics dynamically synchronize from zero.
    """
    state.stream_events = []
    if hasattr(state, "blockchain") and state.blockchain is not None:
        state.blockchain.reset()
    if hasattr(state, "streamer") and state.streamer is not None:
        state.streamer.reset()
    if hasattr(state, "crypto") and state.crypto is not None and hasattr(state.crypto, "offchain_storage"):
        state.crypto.offchain_storage.clear()



# -------------------------------------------------------------
# 3D Interactive Plotly Helpers
# -------------------------------------------------------------
def plot_3d_blockchain_blocks(chain_blocks: List[Any]) -> go.Figure:
    """Requirement #25: 3D Blockchain Visualization (Block Index vs TX Count vs Latency)."""
    indices = [b.index for b in chain_blocks]
    tx_counts = [len(b.transactions) for b in chain_blocks]
    latencies = [b.transactions[0].get("confirmation_latency_ms", 0.05) if len(b.transactions) > 0 else 0.05 for b in chain_blocks]

    fig = go.Figure(data=[go.Scatter3d(
        x=indices,
        y=tx_counts,
        z=latencies,
        mode='lines+markers',
        line=dict(color="#00f0ff", width=4),
        marker=dict(size=8, color="#00ff88", symbol='diamond')
    )])

    fig.update_layout(
        title="3D Blockchain Ledger: Block Index × Transaction Count × Confirmation Latency (ms)",
        template="plotly_dark",
        scene=dict(
            xaxis=dict(title="Block Index"),
            yaxis=dict(title="Transactions"),
            zaxis=dict(title="Latency (ms)")
        ),
        margin=dict(l=0, r=0, b=0, t=40)
    )
    return fig
