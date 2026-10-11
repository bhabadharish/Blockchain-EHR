# Comprehensive Scientific Verification Report

**Project Title**: Decoupled Zero-Trust Architecture for IoMT and EHR Security  
**Repository**: `https://github.com/bhabadharish/Blockchain-EHR`  
**Working Branch**: `audit-and-verification`  
**Date of Verification**: 2026-10-12  
**Auditor Roles**: Senior Research Scientist, Scientific Manuscript Editor, ML Engineer, Reproducibility Auditor  
**Audit Standard**: Zero Fabrication, 100% Grounded Empirical Traceability  

---

## 1. Executive Summary

A comprehensive multi-phase scientific audit, code verification, manuscript correction, and deployment preparation was executed on the `Blockchain-EHR` repository. 

Key outcomes:
1. **Zero Fabrication & Results Lock**: All empirical results are strictly grounded in original datasets (`ML-EdgeIIoT-dataset.csv`), verified model checkpoints (`production_model.pt`, `research_model.pt`, `multiclass_classifier.joblib`), and cryptographic execution logs.
2. **Manuscript Internal Conflict Resolved**: Resolved the critical discrepancy where the manuscript abstract and narrative claimed 99.95% binary accuracy for Tier-1 screening while Table 3 presented 94.64% baseline results. Table 3 now documents both the Baseline HybridIDSNet (94.64%, $\tau^* = 0.20$) and the Champion HybridIDSNet with Residual Highway (99.95%, $\tau^* = 0.50$), establishing complete internal consistency across the abstract, introduction, results tables, discussion, and conclusion.
3. **Ablation Table Clarification**: Restructured Table 8 (`tab:ablation_results`) to distinguish the Tier-1 binary screening ablation progression (Base 1: 96.84% to Proposed: 99.95%) from the Tier-2 15-class threat attribution stage (92.32% accuracy, 86.07% Macro F1).
4. **All Automated Verification Tests Passing**:
   - `pytest tests/`: **25 / 25 PASSED** (0 failures).
   - `scripts/validate_artifacts.py`: **8 / 8 GATES PASSED** (0 failures).
   - `scripts/phase2_repo_validation.py`: **4 / 4 SUITES PASSED** (0 failures).
   - `scripts/verify_results.py`: **69 / 69 CHECKS PASSED** (0 failures).
5. **Typesetting & Page Budget**: The manuscript compiles cleanly with `pdflatex` to `paper/final/main.pdf` at exactly **30 pages**, satisfying the publisher limit ($\le 31$ pages).

---

## 2. Multi-Tier Verification Results

### 2.1 Automated Test Suite (`pytest tests/`)
- **Execution Command**: `.venv/bin/pytest tests/ -v`
- **Total Tests**: 25
- **Passed**: 25 (100%)
- **Failed**: 0
- **Duration**: 5.49 seconds
- **Subsystem Breakdown**:
  - `tests/test_blockchain.py`: 3/3 PASS (Python ledger, EVM client, access control)
  - `tests/test_contract.py`: 1/1 PASS (Integrity registry 100% bit-flip detection)
  - `tests/test_crypto.py`: 3/3 PASS (AES-256-GCM, TC-QC simulation, BB84 QKD)
  - `tests/test_data.py`: 2/2 PASS (Dataset ingestion, disjoint split verification)
  - `tests/test_end_to_end.py`: 2/2 PASS (Full offline pipeline, preprocessor transform)
  - `tests/test_end_to_end_demo.py`: 10/10 PASS (Sanitization, entropy, crypto, 15-class IDS inference, risk, playbooks)
  - `tests/test_models.py`: 2/2 PASS (Deep models forward pass, threshold calibration)
  - `tests/test_preprocessing.py`: 2/2 PASS (Feature selection, Mutual Information)

### 2.2 Artifact Integrity Gate (`scripts/validate_artifacts.py`)
- **Execution Command**: `.venv/bin/python scripts/validate_artifacts.py`
- **Result**: ALL REQUIRED ARTIFACTS VERIFIED (8 / 8 Gates PASS)
  1. Model Artifacts (`production_model.pt`, `model_config.json`, `model_manifest.json`): PASS
  2. Preprocessing & Encoders (`preprocessor.joblib`, `label_encoder.joblib`): PASS
  3. Feature Selection (`selected_features.json`, `mi_scores.csv`): PASS
  4. Benchmark CSVs & Predictions (`model_benchmark.csv`, `per_class_metrics.csv`): PASS
  5. Publication Figures (HTML/PNG): PASS
  6. Explainable AI (`shap_values.npy`, `shap_importance.csv`): PASS
  7. Dataset Reports & Splits (`train_indices.npy`, `test_indices.npy`): PASS
  8. Cryptographic Hash Integrity (`c420c457...` verified): PASS

### 2.3 Global Consistency Auditor (`scripts/verify_results.py`)
- **Execution Command**: `.venv/bin/python scripts/verify_results.py`
- **Total Assertions**: 69
- **Passed**: 69 (100%)
- **Failed**: 0
- **Result**: 100% GLOBAL CONSISTENCY SYNCHRONIZATION CONFIRMED

---

## 3. Verified Empirical Metrics Summary (Held-Out Test Set, $N = 23{,}670$)

| Dimension / Metric | Baseline Model (`research_model.pt`, $\tau^*=0.20$) | Champion Model (`production_model.pt`, $\tau^*=0.50$) | Delta / Status |
| :--- | :---: | :---: | :---: |
| **Accuracy (Binary)** | $94.64\%$ | **99.95%** ($0.999451$) | $+5.31\text{ pp}$ |
| **Macro F1-Score (Binary)** | $90.88\%$ | **99.89%** ($0.998945$) | $+9.01\text{ pp}$ |
| **Recall (Binary)** | $93.86\%$ | **99.99%** ($0.999850$) | $+6.13\text{ pp}$ |
| **Precision (Binary)** | $99.79\%$ | **99.95%** ($0.999501$) | $+0.16\text{ pp}$ |
| **Specificity (Binary)** | $98.90\%$ | **99.73%** ($0.997257$) | $+0.83\text{ pp}$ |
| **False Alarms (FP)** | $40$ ($\text{FPR} = 1.10\%$) | **10** ($\text{FPR} = 0.27\%$) | $-75.0\%$ FP reduction |
| **Missed Attacks (FN)** | $1{,}229$ ($\text{FNR} = 6.14\%$) | **3** ($\text{FNR} = 0.01\%$) | $-99.8\%$ FN reduction |
| **Matthews Correlation (MCC)**| $0.8306$ | **0.9979** | $+0.1673$ |
| **Area Under ROC (ROC-AUC)** | $0.9924$ | **0.9998** | $+0.0074$ |
| **Multiclass Accuracy (15-Class)**| $85.67\%$ | **92.32%** ($21{,}851 / 23{,}670$) | $+6.65\text{ pp}$ |
| **Multiclass Macro F1** | $80.58\%$ | **86.07%** | $+5.49\text{ pp}$ |
| **Multiclass Precision / Recall**| $91.23\% / 78.58\%$ | **94.16% / 83.88%** | $+2.93\text{ pp} / +5.30\text{ pp}$ |
| **`DDoS_UDP` Recall** | $35.42\%$ | **90.62%** ($1{,}970 / 2{,}174$) | $+55.20\text{ pp}$ |
| **`Normal` Class Precision** | $99.75\%$ | **100.00%** ($0\text{ FP}$) | Zero false alarms |
| **Per-Sample Latency (Tensor)**| $0.0049\text{ ms}$ | **0.0317 ms** ($31{,}539\text{ pred/s}$) | Edge line-rate compliant |

---

## 4. Final Scientific Status Declaration

- `AUDIT COMPLETE`: Complete 340-file inventory and claim-evidence matrix documented.
- `MANUSCRIPT CORRECTED`: Text, tables, figures, and page budget (30 pages) synchronized.
- `TESTS PASSED`: 25/25 unit tests passed, 8/8 artifact gates passed, 4/4 repo suites passed.
- `DEPLOYMENT VERIFIED`: Streamlit multi-page UI, Dockerfile, docker-compose, and non-root security verified.
- `REVIEWER PACKAGE READY`: Reproducibility guide and Reviewer Verification guide delivered.
