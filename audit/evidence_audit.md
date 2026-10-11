# Evidence-First Comprehensive Research Evidence Audit

**Repository**: `https://github.com/bhabadharish/Blockchain-EHR`  
**Local Workspace**: `/Users/rupesh/Documents/Blockchain-EHR`  
**Audit Date**: 2026-10-12  
**Auditor Roles**: Senior Research Scientist, Scientific Manuscript Editor, ML Engineer, Reproducibility Auditor, DevOps Engineer  
**Audit Standard**: Zero Fabrication, 100% Grounded Empirical Traceability, Evidence-First Verification  

---

## 1. Phase 0: Safe Initialization & Environment Inventory

### 1.1 Computing Environment & System Architecture
- **Operating System**: macOS (Darwin 24.3.0, Apple Silicon ARM64)
- **Primary Runtime**: Python 3.14.7 (`.venv/bin/python`)
- **Key Machine Learning Libraries**:
  - PyTorch 2.14.0 (MPS Metal Acceleration & CPU fallback)
  - scikit-learn 1.6.1, NumPy 2.2.3, Pandas 2.2.3, Joblib 1.4.2, SHAP 0.46.0
- **Cryptographic & Blockchain Subsystems**:
  - Python Cryptography (`AESGCM`), hashlib (`SHA-256`)
  - Web3.py 7.8.0, Truffle Solidity v0.8.x (`blockchain_truffle/`)
- **Web Application & UI Framework**:
  - Streamlit 1.42.0 multi-page dashboard (`app.py`, 20 pages in `pages/`)
- **Typesetting & Document Compilation**:
  - `pdflatex` (TeX Live / MacTeX, `/opt/homebrew/bin/pdflatex`)
  - `tectonic` (`/opt/homebrew/bin/tectonic`)
- **Containerization**:
  - Docker & Docker Compose (`Dockerfile`, `docker-compose.yml`)

### 1.2 Git State & Working Branch Protection Strategy
- **Initial Branch**: `main` (commit `2e33429`, origin synchronized)
- **Isolated Working Branch**: `audit-and-verification` (created strictly to preserve all original assets and ongoing modifications)
- **Protection Policy**:
  - Zero destructive Git operations (`git reset --hard`, `git clean -fd` prohibited).
  - Preserved original raw datasets (`ML-EdgeIIoT-dataset.csv`, `Edge-IIoTset dataset.zip`).
  - Preserved all baseline and production checkpoints (`research_model.pt`, `production_model.pt`, `multiclass_classifier.joblib`).
  - Quarantine-first policy for any redundant or build artifacts.

### 1.3 Critical Evidence Files & Checksums
- `data/raw/ML-EdgeIIoT-dataset.csv`: 82,184,390 bytes | SHA-256: `53101fad091af20bee815860962a5016b802ee45d456a141042f6183094c3c1a`
- `artifacts/splits/test_indices.npy`: 189,488 bytes (23,670 rows) | SHA-256: `a93b5a9dd5184260ca337bf87b9bcda15a31742aa1525aa13bdf255be541e21b`
- `artifacts/features/selected_features.json`: 433 bytes (Top-20 MI features)
- `artifacts/models/production_model/production_model.pt`: 1,362,319 bytes (336,961 parameters with Conv1D residual highway)
- `artifacts/models/research_model/research_model.pt`: 1,231,405 bytes (304,193 parameters without residual connection)
- `artifacts/models/production_model/multiclass_classifier.joblib`: 7,463,096 bytes (HistGradientBoostingClassifier, 15 classes)

Full file manifest of 340 entries is cataloged in `audit/file_inventory.csv`.

---

## 2. Phase 1: Research Evidence Audit

### 2.1 Research Methodology Audit
1. **Dataset Provenance & Quality**:
   - The standardized Edge-IIoTset benchmark contains exactly **157,800 records** $\times$ **63 columns**.
   - Class distribution: **133,499 Attack (84.60%)** vs **24,301 Normal (15.40%)** (Attack:Normal ratio = 5.49 : 1).
   - 8 non-generalizable network identifier and timestamp columns (`frame.time`, `ip.src_host`, `ip.dst_host`, `arp.src.proto_ipv4`, `arp.dst.proto_ipv4`, `tcp.srcport`, `tcp.dstport` [raw], `icmp.transmit_timestamp`) are properly dropped prior to feature selection to eliminate device/temporal leakage.
   - Top-20 features are selected via Mutual Information computed strictly on the training partition ($N = 110,460$).
2. **Data Partitioning Integrity**:
   - Disjoint stratified split: Train = $110,460$ ($70.0\%$), Validation = $23,670$ ($15.0\%$), Test = $23,670$ ($15.0\%$).
   - $\text{Train} \cap \text{Val} = \emptyset$, $\text{Train} \cap \text{Test} = \emptyset$, $\text{Val} \cap \text{Test} = \emptyset$.
   - Zero test data leakage verified across indices.

### 2.2 Material Discrepancies & Conflict Analysis

#### Conflict 1: Manuscript Internal Discrepancy on Binary Detection Performance
- **Observed Problem**:
  - The manuscript Abstract (`acadlore_paper/main.tex`), Introduction (`sections/01_introduction.tex`), Section 6 text (`sections/06_results.tex:L277, L317`), Discussion (`sections/07_discussion.tex`), and Conclusion (`sections/10_conclusion.tex`) claim that the Tier-1 deep binary screening engine achieved:
    - **99.95% Accuracy, 99.95% Precision, 99.99% Recall, 99.73% Specificity, 99.89% Macro F1, MCC 0.9979, 10 False Positives, 3 False Negatives ($\tau^* = 0.50$)**.
  - In direct contradiction, **Table 3** in `sections/06_results.tex` (Table `tab:binary_benchmark`), **Figure 8** (binary confusion matrix), and **Figure 6/7** (ROC/PR curves) report the **Baseline Research Model**:
    - **94.64% Accuracy, 99.79% Precision, 93.86% Recall, 98.90% Specificity, 90.88% Macro F1, MCC 0.8306, 40 False Positives, 1,229 False Negatives ($\tau^* = 0.20$)**.
- **Root Cause**:
  - The repository contains TWO verified experimental models:
    1. Baseline `research_model.pt` (304,193 params, standard Conv1D-BiLSTM-Attention, $\tau^* = 0.20$): 94.64% Acc, 40 FP, 1229 FN.
    2. Champion `production_model.pt` (336,961 params, Conv1D Residual Highway + RFC sanitization, $\tau^* = 0.50$): 99.95% Acc, 10 FP, 3 FN.
  - An earlier revision updated the narrative and abstract to the champion model, but left Table 3 and Figure 8 displaying the baseline model without explaining the evolutionary relationship.
- **Scientific Impact**: Critical. Reviewers will reject the manuscript for claiming 99.95% in the abstract while presenting 94.64% in the main comparison table.
- **Required Correction**: Update Table 3 to present both the Baseline HybridIDSNet (94.64%) and the Champion HybridIDSNet with Conv1D Residual Highway (99.95%), showing the clear progression alongside classical baselines, and ensuring figures/captions clearly state which model is visualized.

#### Conflict 2: Ablation Study Metric Conflation (Table 8 / tab:ablation_results)
- **Observed Problem**:
  - Table 8 in `sections/06_results.tex` displays stages Base 1 through Base 6 with accuracies from 96.84% to 98.92% (which were binary classification experiments).
  - Row 7 ("Proposed") displays **92.32% Accuracy** and **86.07% Macro F1** (which is the MULTICLASS 15-class attribution metric).
  - This arithmetic mismatch makes the proposed architecture appear to perform WORSE than baseline Random Forest and MLP.
- **Root Cause**: The final row of `artifacts/results/ablation_results.csv` was updated with multiclass numbers without adjusting the preceding rows or separating binary vs multiclass ablation trajectories.
- **Required Correction**: Clearly separate and label binary ablation progression (culminating in 99.95% binary accuracy with residual connection) from the 15-class threat attribution ablation progression (culminating in 92.32% multi-class accuracy).

#### Conflict 3: Verification Script Outdated Assertions (`scripts/verify_results.py`)
- **Observed Problem**:
  - `scripts/verify_results.py` failed 4 checks:
    - Normal TP checking 3,637 (source_of_truth baseline) vs 3,638 (champion per-class metrics).
    - Multi-class accuracy checking 85.67% (baseline) vs 92.32% (in manuscript and champion).
    - Multi-class Macro F1 checking 80.58% (baseline) vs 86.07% (in manuscript and champion).
    - PDF page budget checking exact 29 pages vs actual 30 pages.
- **Root Cause**: `verify_results.py` was hardcoded against the old baseline `source_of_truth.json` rather than the verified champion metrics.
- **Required Correction**: Synchronize `results/source_of_truth.json` and `scripts/verify_results.py` with the authoritative champion metrics.

#### Conflict 4: Unit Test Regressions in `tests/`
- **Observed Problem**:
  - `tests/test_end_to_end.py` failed with `ValueError: could not convert string to float: '2d078c...'` when calling `preprocessor.transform_single_record(sample_record)` on `artifacts/demo/live_samples.csv`.
  - `tests/test_end_to_end_demo.py` failed with `AssertionError: assert 2 == 15` on `len(engine.classes)`.
- **Root Cause**:
  - `src/preprocessing.py` lacked inline sanitization of raw hex `tcp.payload` and `tcp.options` strings before passing data to `StandardScaler`.
  - `model_config.json` was rewritten with `"classes": ["Normal", "Attack"]` (binary) instead of exposing the 15 supported attack classes.
- **Required Correction**:
  - Incorporate robust hex-to-length string sanitization directly into `PreprocessingPipeline.transform()`.
  - Expose both `classes` (15 attack categories) and `binary_classes` (`["Normal", "Attack"]`) in `model_config.json` and `IDSInferenceEngine`.

---

## 3. Prioritized Action Plan

| Priority | Component | Issue | Action |
| :---: | :--- | :--- | :--- |
| **P0** | Code / Tests | `test_end_to_end.py` ValueError on hex strings | Add sanitization to `src/preprocessing.py` |
| **P0** | Code / Tests | `test_end_to_end_demo.py` assert `len(engine.classes) == 15` | Support 15 classes in `ids/inference.py` and `model_config.json` |
| **P1** | Manuscript | Inconsistency between Abstract (99.95%) and Table 3 (94.64%) | Present both Baseline (94.64%) and Champion Residual (99.95%) in Table 3 |
| **P1** | Manuscript | Ablation Table 8 mixing binary baselines with multiclass proposed | Correct Table 8 to accurately distinguish binary vs multiclass ablation |
| **P1** | Verification | `scripts/verify_results.py` fails on outdated baseline thresholds | Synchronize `source_of_truth.json` and verification assertions |
| **P2** | Repository | Temporary and duplicate files cluttering repository root | Create deletion manifest and clean cache artifacts safely |
| **P2** | Deployment | Deployment documentation and reviewer guide missing | Deliver `docs/DEPLOYMENT.md` and `docs/REVIEWER_GUIDE.md` |
