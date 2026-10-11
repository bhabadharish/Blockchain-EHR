# Independent Peer Reviewer Verification Guide

**Target Manuscript**: *Decoupled Zero-Trust Architecture for IoMT and EHR Security*  
**Submission Venue**: Acadlore Submission Manuscript  
**Working PDF**: `paper/final/main.pdf` (30 pages)  
**Repository**: `https://github.com/bhabadharish/Blockchain-EHR`  
**Evaluation Standard**: Zero Fabrication, Full Empirical Traceability  

---

## 1. Executive Summary for Reviewers

This repository accompanies our research manuscript on resolving the fundamental security dilemma in healthcare Internet of Medical Things (IoMT) networks:
- **The Dilemma**: End-to-end payload encryption preserves patient confidentiality but blinds perimeter Network Intrusion Detection Systems (NIDS). Conversely, decrypting telemetry at middleboxes creates systemic regulatory and exposure liabilities.
- **The Proposed Decoupled Architecture**:
  1. **Phase 1 (Payload Plane)**: Client-side HIPAA data minimization, canonical serialization, authenticated AES-256-GCM encryption, software-simulated post-quantum key expansion (TC-QC), and software-simulated BB84 QKD. Sensitive payloads remain strictly off-chain; cryptographic digests (SHA-256) and RBAC policies are anchored to Ethereum smart contracts (`EHRAccessControl.sol`, `EHRIntegrityRegistry.sol`).
  2. **Phase 2 (Perimeter Telemetry Plane)**: Perimeter gateways monitor post-encryption transport and network flow metadata (packet timing, sequence transitions, header sizes). Features are pruned from 53 to 20 via training-isolated Mutual Information. Screening is conducted by `HybridIDSNet` (1D-CNN + 2-layer BiLSTM + Multi-Head Self-Attention + Residual Highway) cascading to a protocol-aware 15-class classifier.

---

## 2. Manuscript-to-Code Traceability Register

Every quantitative finding in the paper maps directly to an executable module and output artifact:

| Manuscript Component | Section / Table / Figure | Source Implementation | Underlying Evidence Artifact | Independent Verification Command | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **Dataset & Splitting** | Sec. 5, Table 1 | `scripts/prepare_dataset.py` | `data/raw/ML-EdgeIIoT-dataset.csv`, `artifacts/splits/*.npy` | `python scripts/phase2_repo_validation.py` | **VERIFIED** |
| **Feature Selection (MI)** | Sec. 5, Fig. 12 | `src/feature_selection.py` | `artifacts/features/mi_scores.csv` | `python scripts/verify_results.py` | **VERIFIED** |
| **Cryptographic Latency** | Sec. 6.1, Table 1 | `crypto/encryption.py` | `artifacts/benchmarks/manuscript_reference.json` | `python -m pytest tests/test_crypto.py` | **VERIFIED** |
| **Tamper Detection (500x)**| Sec. 6.3, Table 3 | `contracts/EHRIntegrityRegistry.sol` | `tests/test_contract.py` | `python -m pytest tests/test_contract.py` | **VERIFIED** |
| **Smart Contract Gas** | Sec. 6.4, Table 4 | `blockchain_truffle/contracts/` | `blockchain/python_ledger.py` | `python -m pytest tests/test_blockchain.py` | **VERIFIED** |
| **Binary IDS Screening** | Sec. 6.6, Table 6 | `src/deep_models.py`, `ids/inference.py` | `production_model.pt`, `FINAL_RESULTS.json` | `python scripts/reproduce_and_verify_final.py` | **VERIFIED** |
| **15-Class Threat Attribution**| Sec. 6.7, Table 7 | `src/deep_models.py` | `multiclass_classifier.joblib`, `per_class_metrics.csv` | `python scripts/reproduce_and_verify_final.py` | **VERIFIED** |
| **Model Ablation Study** | Sec. 6.8, Table 8 | `src/deep_models.py` | `artifacts/results/ablation_results.csv` | `python scripts/verify_results.py` | **VERIFIED** |
| **Global SHAP Attribution**| Sec. 6.9, Table 9 | `src/explainability.py` | `artifacts/xai/shap_importance.csv` | `python scripts/verify_results.py` | **VERIFIED** |
| **SOC Playbook Latencies**| Sec. 6.10, Table 10 | `ids/response.py` | `artifacts/results/inference_benchmark.json` | `python -m pytest tests/test_end_to_end_demo.py` | **VERIFIED** |
| **End-to-End Budget** | Sec. 6.12, Table 12 | Cumulative 10-stage architecture | `results/source_of_truth.json` | `python scripts/verify_results.py` | **VERIFIED** |

---

## 3. Quick 3-Minute Verification Checklist for Reviewers

Reviewers can verify repository consistency in 3 steps:

1. **Step 1: Run Full Test Suite (6 seconds)**
   ```bash
   pytest tests/ -q
   # Result: 25 passed
   ```
2. **Step 2: Run Global Cross-Validation (2 seconds)**
   ```bash
   python scripts/verify_results.py
   # Result: 69 / 69 CHECKS PASSED PERFECTLY
   ```
3. **Step 3: Run Interactive SOC Demonstration**
   ```bash
   streamlit run app.py
   # Launches 20-page interactive dashboard on http://localhost:8501
   ```

---

## 4. Reviewer Limitations & Scope Disclosure

- **Physical Quantum Hardware**: TC-QC and BB84 QKD are evaluated via verified software simulation in Python (`crypto/tcqc_simulation.py`, `crypto/qkd_simulation.py`). The paper does not claim execution on physical cryogenically cooled QPUs.
- **Ethereum Network**: Smart contract transactions are benchmarked on local Ganache EVM RPC and an in-memory Python ledger fallback. Gas counts reflect exact EVM execution. Public Ethereum Mainnet gas volatility does not affect deterministic local measurements.
- **Dataset Redistribution**: The processed demo partition and all evaluation indices are included. The full raw 1.74 GB Edge-IIoTset zip archive is referenced with open-access provenance.
