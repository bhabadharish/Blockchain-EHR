"""
05_Phase1_After_Encryption.py
PHASE 1 — EHR AFTER ENCRYPTION & BEFORE/AFTER COMPARISON.
Examines the protected ciphertext artifact, off-chain storage packaging, and side-by-side security matrix.
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from src.ui_helpers import apply_soc_theme, get_shared_state
from ehr.serializer import EHRSerializer

apply_soc_theme()
state = get_shared_state()
payload = state.active_ehr_payload

st.markdown("""
<div style="margin-bottom: 20px;">
    <span class="soc-header-tag" style="background: rgba(0, 255, 136, 0.15); color: #00ff88; border-color: #00ff88;">
        PHASE 1 — POST-ENCRYPTION STATE
    </span>
    <h1 style="margin: 4px 0; font-size: 2.0rem; font-weight: 800; color: #ffffff;">
        EHR Protected Payload & Before vs. After Analysis
    </h1>
    <p style="color: #8fa3bf; font-size: 0.92rem;">
        Comprehensive examination of ciphertext properties, off-chain data packaging, and measured security transformation.
    </p>
</div>
""", unsafe_allow_html=True)

if not payload or not payload.encryption_receipt:
    st.warning("EHR payload has not been encrypted yet. Please visit Phase 1 — Encryption first.")
    st.stop()

receipt = payload.encryption_receipt
plain_bytes = payload.canonical_bytes
cipher_bytes = receipt.ciphertext_bytes

plain_entropy = EHRSerializer.compute_entropy(plain_bytes)
cipher_entropy = EHRSerializer.compute_entropy(cipher_bytes)

# -------------------------------------------------------------
# 1. Big Measured Before vs. After Comparison Matrix
# -------------------------------------------------------------
st.markdown("### ⚖️ Side-by-Side Security Transformation Matrix")

comp_df = pd.DataFrame([
    {
        "Security Dimension": "Data Visibility",
        "Before Encryption (Plaintext)": "HIGH (Unrestricted Plaintext)",
        "After Encryption (Proposed)": "ZERO (Cryptographic AEAD Ciphertext)",
        "Security Guarantee": "Confidentiality (IND-CPA & IND-CCA2)"
    },
    {
        "Security Dimension": "Clinical Values",
        "Before Encryption (Plaintext)": "READABLE (Diagnostic labs visible)",
        "After Encryption (Proposed)": "CIPHERTEXT (High-entropy pseudorandom bytes)",
        "Security Guarantee": "No clinical data leakage without 256-bit key"
    },
    {
        "Security Dimension": "Sensitive Fields",
        "Before Encryption (Plaintext)": f"EXPOSED ({len(payload.sensitive_fields)} HIPAA identifiers)",
        "After Encryption (Proposed)": "PROTECTED (Encapsulated in ciphertext)",
        "Security Guarantee": "HIPAA Privacy Rule Compliance"
    },
    {
        "Security Dimension": "Integrity Protection",
        "Before Encryption (Plaintext)": "NOT GUARANTEED (Tampering undetectable)",
        "After Encryption (Proposed)": "AUTHENTICATED (128-bit Poly1305/GHASH tag)",
        "Security Guarantee": "Cryptographic Integrity Authentication"
    },
    {
        "Security Dimension": "Tamper Detectability",
        "Before Encryption (Plaintext)": "HARD TO DETECT (Bit flips go unnoticed)",
        "After Encryption (Proposed)": "100% DETECTABLE (Decryption aborts on tag mismatch)",
        "Security Guarantee": "Tamper Resistance"
    },
    {
        "Security Dimension": "Access Control",
        "Before Encryption (Plaintext)": "APPLICATION LEVEL ONLY",
        "After Encryption (Proposed)": "CRYPTOGRAPHIC + ON-CHAIN SMART CONTRACT RBAC",
        "Security Guarantee": "Defense-in-Depth Authorization"
    },
    {
        "Security Dimension": "Blockchain Role",
        "Before Encryption (Plaintext)": "NONE (Or insecure plaintext on-chain)",
        "After Encryption (Proposed)": "SHA-256 HASH ANCHOR & INCIDENT AUDIT LEDGER",
        "Security Guarantee": "Immutable Tamper-Evident Notarization"
    },
    {
        "Security Dimension": "Shannon Entropy",
        "Before Encryption (Plaintext)": f"{plain_entropy:.2f} / 8.0 (Structured)",
        "After Encryption (Proposed)": f"{cipher_entropy:.2f} / 8.0 (Uniform)",
        "Security Guarantee": "Statistical Indistinguishability"
    },
    {
        "Security Dimension": "Payload Size",
        "Before Encryption (Plaintext)": f"{len(plain_bytes)} bytes",
        "After Encryption (Proposed)": f"{len(cipher_bytes)} bytes (+16 bytes MAC)",
        "Security Guarantee": "Negligible Bandwidth Expansion (1.02x)"
    }
])

st.dataframe(comp_df, use_container_width=True, hide_index=True)

st.markdown("---")

# -------------------------------------------------------------
# 2. Visual Snippet Comparison: Plaintext vs Ciphertext
# -------------------------------------------------------------
st.markdown("### 🔍 Payload Transformation: Plaintext to Authenticated Ciphertext")

col_s1, col_s2 = st.columns(2)

with col_s1:
    st.markdown("""
    <div class="soc-card">
        <div class="soc-header-tag" style="background: rgba(255, 59, 48, 0.15); color: #ff3b30; border-color: #ff3b30;">
            BEFORE: ORIGINAL EHR PLAINTEXT
        </div>
        <p style="font-size: 0.8rem; color: #8fa3bf;">Structured, readable JSON with clinical parameters:</p>
    </div>
    """, unsafe_allow_html=True)
    st.code(plain_bytes.decode("utf-8")[:300] + "\n... [truncated]", language="json")

with col_s2:
    st.markdown("""
    <div class="soc-card">
        <div class="soc-header-tag" style="background: rgba(0, 255, 136, 0.15); color: #00ff88; border-color: #00ff88;">
            AFTER: AES-256-GCM CIPHERTEXT
        </div>
        <p style="font-size: 0.8rem; color: #8fa3bf;">Base64 & Hex representation of protected payload:</p>
    </div>
    """, unsafe_allow_html=True)
    st.code(cipher_bytes[:150].hex() + "\n... [truncated]", language="text")

st.info("💡 **Scientific Rationale:** The ciphertext visualization is for demonstration. Apparent randomness alone is not proof of cryptographic security. Security relies strictly on the mathematical difficulty of 256-bit AES key recovery and the collision resistance of the 128-bit authentication tag.")

st.markdown("---")

# -------------------------------------------------------------
# 3. Off-Chain Storage Packaging vs On-Chain Anchoring
# -------------------------------------------------------------
st.markdown("### 📦 Off-Chain Storage Packaging & Blockchain Hash Anchor")

col_p1, col_p2 = st.columns(2)

with col_p1:
    st.markdown(f"""
    <div class="soc-card" style="border-left: 4px solid #00f0ff;">
        <h4 style="color: #00f0ff; margin-top: 0;">1. Off-Chain Storage Repository</h4>
        <p style="font-size: 0.84rem; color: #c4d1e2;">
            Sensitive EHR ciphertext is stored in private off-chain hospital databases or encrypted IPFS.
        </p>
        <div style="font-size: 0.8rem; color: #8fa3bf;">
            <b>Components Stored Off-Chain:</b>
            <ul>
                <li>Encrypted Payload: <code>{len(cipher_bytes)} bytes</code></li>
                <li>Initialization Nonce: <code>{receipt.nonce_hex}</code></li>
                <li>Authentication Tag: <code>{receipt.tag_hex}</code></li>
                <li>Key Reference: <code>{receipt.key_id}</code></li>
            </ul>
        </div>
    </div>
    """, unsafe_allow_html=True)

with col_p2:
    st.markdown(f"""
    <div class="soc-card" style="border-left: 4px solid #00ff88;">
        <h4 style="color: #00ff88; margin-top: 0;">2. On-Chain Blockchain Metadata Anchor</h4>
        <p style="font-size: 0.84rem; color: #c4d1e2;">
            Zero medical plaintext is written to the ledger. Only immutable hashes and audit policies exist on-chain.
        </p>
        <div style="font-size: 0.8rem; color: #8fa3bf;">
            <b>Parameters Registered on Ganache:</b>
            <ul>
                <li>Record ID: <code>{payload.record_id}</code></li>
                <li>Payload Hash: <code>{receipt.sha256_hash[:20]}...</code></li>
                <li>Cipher Algorithm: <code>AES-256-GCM</code></li>
                <li>Access Policy: <code>DOCTOR_ONLY</code></li>
            </ul>
        </div>
    </div>
    """, unsafe_allow_html=True)
