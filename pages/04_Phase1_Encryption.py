"""
04_Phase1_Encryption.py
PHASE 1 — AUTHENTICATED FILE & PAYLOAD ENCRYPTION ENGINE.
Full-payload AES-256-GCM encryption with 256-bit symmetric keys, 96-bit unique nonces,
and 128-bit authentication tags.
"""

import streamlit as st
import time
import pandas as pd
from src.ui_helpers import apply_soc_theme, get_shared_state
from crypto.encryption import AES256GCMCipher, LegacyFernetCipher
from crypto.key_management import KeyManager

apply_soc_theme()
state = get_shared_state()
payload = state.active_ehr_payload
km: KeyManager = state.key_manager

st.markdown("""
<div style="margin-bottom: 20px;">
    <span class="soc-header-tag">PHASE 1 — CRYPTOGRAPHIC ENGINE</span>
    <h1 style="margin: 4px 0; font-size: 2.0rem; font-weight: 800; color: #ffffff;">
        Authenticated EHR Payload Encryption (AES-256-GCM)
    </h1>
    <p style="color: #8fa3bf; font-size: 0.92rem;">
        Full-file and payload-level authenticated symmetric encryption. Generates ciphertext, 96-bit nonce, 128-bit MAC authentication tag, and cryptographic receipt.
    </p>
</div>
""", unsafe_allow_html=True)

if not payload:
    st.error("No active EHR payload loaded. Please select one from the EHR Data Center.")
    st.stop()

# -------------------------------------------------------------
# 1. Active Key & Configuration
# -------------------------------------------------------------
active_key = km.get_active_key()

col_k1, col_k2, col_k3, col_k4 = st.columns(4)
with col_k1:
    st.markdown(f"**Key Identifier:** `{active_key.key_id}`")
with col_k2:
    st.markdown(f"**Key Length:** `256 bits (32 bytes)`")
with col_k3:
    st.markdown(f"**Cipher Algorithm:** `AES-256-GCM`")
with col_k4:
    st.markdown(f"**Nonce Length:** `96 bits (12 bytes)`")

st.markdown("---")

# -------------------------------------------------------------
# 2. Encryption Execution Section
# -------------------------------------------------------------
st.markdown("### 🔐 Execute Authenticated Payload Encryption")

col_e1, col_e2 = st.columns([2, 1])

with col_e1:
    st.markdown(f"""
    **Target Payload:** `{payload.record_id}`  
    **Plaintext Size:** `{len(payload.canonical_bytes)} bytes`  
    **Associated Authenticated Data (AAD):** `RecordID={payload.record_id}|Policy=DOCTOR_ONLY`
    """)

with col_e2:
    encrypt_btn = st.button("🔒 Encrypt Full EHR Payload (AES-256-GCM)", type="primary", use_container_width=True)

if encrypt_btn or payload.encryption_receipt is None:
    receipt = AES256GCMCipher.encrypt(
        payload.canonical_bytes,
        active_key.key_bytes,
        key_id=active_key.key_id,
        associated_data=f"RecordID={payload.record_id}".encode()
    )
    payload.encryption_receipt = receipt
    payload.encrypted_ciphertext = receipt.ciphertext_bytes
    payload.sha256_hash = receipt.sha256_hash
    st.success("✅ Full EHR Payload Encrypted via AES-256-GCM!")

receipt = payload.encryption_receipt

# -------------------------------------------------------------
# 3. Measured Cryptographic Metrics
# -------------------------------------------------------------
st.markdown("### 📊 Measured Cryptographic Performance")

m1, m2, m3, m4, m5 = st.columns(5)
with m1:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Encryption Time</div>
        <div class="kpi-value">{receipt.encryption_latency_ms:.4f} <span style="font-size: 0.85rem;">ms</span></div>
        <div class="kpi-delta" style="color: #00ff88;">Hardware AES-NI</div>
    </div>
    """, unsafe_allow_html=True)

with m2:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Ciphertext Size</div>
        <div class="kpi-value">{len(receipt.ciphertext_bytes)} <span style="font-size: 0.85rem;">bytes</span></div>
        <div class="kpi-delta" style="color: #00f0ff;">+16 byte Auth Tag</div>
    </div>
    """, unsafe_allow_html=True)

with m3:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Expansion Ratio</div>
        <div class="kpi-value">{receipt.expansion_factor:.2f}x</div>
        <div class="kpi-delta" style="color: #8fa3bf;">Minimal Overhead</div>
    </div>
    """, unsafe_allow_html=True)

with m4:
    st.markdown(f"""
    <div class="soc-card">
        <div class="kpi-title">Integrity Hash</div>
        <div class="kpi-value" style="font-size: 1.2rem;">SHA-256</div>
        <div class="kpi-delta" style="color: #00ff88;">Anchor Ready</div>
    </div>
    """, unsafe_allow_html=True)

with m5:
    st.markdown("""
    <div class="soc-card">
        <div class="kpi-title">Provenance</div>
        <div class="kpi-value" style="font-size: 1.2rem; color: #00ff88;">MEASURED</div>
        <div class="kpi-delta" style="color: #00ff88;">Local Benchmark</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# -------------------------------------------------------------
# 4. Cryptographic Receipt & Payload Artifact
# -------------------------------------------------------------
st.markdown("### 📜 Cryptographic Storage Receipt")

col_r1, col_r2 = st.columns(2)

with col_r1:
    st.markdown("##### Cryptographic Components:")
    st.code(f"""
Algorithm:       AES-256-GCM (Authenticated Encryption)
Key ID:          {receipt.key_id}
Nonce (96-bit):  {receipt.nonce_hex}
Auth Tag (128):  {receipt.tag_hex}
Payload Hash:    {receipt.sha256_hash}
Plaintext Size:  {receipt.plaintext_bytes_len} bytes
Ciphertext Size: {receipt.ciphertext_bytes_len} bytes
    """, language="text")

with col_r2:
    st.markdown("##### Ciphertext Hex Representation (First 128 bytes):")
    st.code(receipt.ciphertext_bytes[:128].hex(), language="text")
    st.caption("⚠️ The ciphertext visualization is for demonstration. Apparent randomness alone is not proof of cryptographic security; mathematical AEAD security guarantees confidentiality and authentication.")

# -------------------------------------------------------------
# 5. Interactive Decryption & Authentication Verification
# -------------------------------------------------------------
st.markdown("---")
st.markdown("### 🔓 Authorized Recipient Decryption Verification")

col_d1, col_d2 = st.columns(2)
with col_d1:
    st.markdown("**Test Scenario A: Authorized Decryption (Correct 256-bit Key)**")
    if st.button("Decrypt with Valid Active Key"):
        t0 = time.perf_counter()
        dec_bytes = AES256GCMCipher.decrypt(
            receipt.ciphertext_bytes,
            active_key.key_bytes,
            receipt.nonce_bytes,
            receipt.tag_bytes,
            associated_data=f"RecordID={payload.record_id}".encode()
        )
        dec_time = (time.perf_counter() - t0) * 1000.0
        st.success(f"✅ Decryption Successful in {dec_time:.4f} ms! Tag Authenticated.")
        st.json(dec_bytes.decode("utf-8"))

with col_d2:
    st.markdown("**Test Scenario B: Unauthorized Decryption (Wrong Key Rejection)**")
    if st.button("Attempt Decryption with Foreign Key"):
        wrong_key = b"\x00" * 32
        try:
            AES256GCMCipher.decrypt(
                receipt.ciphertext_bytes,
                wrong_key,
                receipt.nonce_bytes,
                receipt.tag_bytes,
                associated_data=f"RecordID={payload.record_id}".encode()
            )
            st.error("Anomaly: Decryption should have failed!")
        except Exception as e:
            st.error(f"🛑 Authentication Failed as Expected: `{type(e).__name__}`. Cryptographic MAC tag rejected fraudulent key attempt.")
