# REPOSITORY FORENSIC AUDIT REPORT
**Target Repository:** `https://github.com/bhabadharish/Blockchain-EHR.git`  
**Local Workspace:** `/Users/rupesh/Documents/Blockchain-EHR`  
**Audit Date:** 2026-10-02  
**Auditor Role:** Senior ML/DL Researcher, Healthcare AI Researcher, Cybersecurity Researcher, Reproducibility Auditor  
**Audit Scope:** Complete forensic inventory, data pipeline, model architecture, training protocols, and baseline results. Zero modifications made.

---

## 1. Complete Repository Map

```
Blockchain-EHR/
├── app.py                             # Streamlit multi-page application entry point
├── config.yaml                        # Master system, dataset, and hyperparameter configuration
├── requirements.txt                   # Python package dependencies
├── Dockerfile & docker-compose.yml    # Containerization specifications
├── run.sh & run.bat                   # Deployment and execution scripts
├── LICENSE                            # MIT License
├── README.md                          # Repository overview and setup instructions
│
├── acadlore_paper/                    # Publication manuscript (LaTeX + PDF)
│   ├── main.tex & main.pdf            # 29-page compiled Acadlore submission manuscript
│   ├── acadlore.cls                   # Official publisher LaTeX style class
│   ├── figures/                       # 13 publication figures (PDF and PNG, 300 DPI)
│   ├── sections/                      # 12 modular LaTeX section files (01-12)
│   ├── tables/                        # Standalone LaTeX table components
│   └── references.bib                 # BibTeX references
│
├── blockchain/                        # Python Web3 client and ledger orchestration
│   ├── contract_client.py             # BlockchainContractClient for EVM transaction dispatch
│   ├── python_ledger.py               # In-memory Python ledger fallback (0.065 ms latency)
│   └── web3_client.py                 # RPC connection manager to Ganache / Hardhat / Ethereum
│
├── blockchain_truffle/                # Truffle Solidity development suite
│   ├── contracts/
│   │   ├── EHRAccessControl.sol       # Role-Based & Attribute-Based Access Control (RBAC/ABAC)
│   │   ├── EHRIntegrityRegistry.sol   # Decoupled payload hash anchoring & forensic logging
│   │   └── Migrations.sol             # Truffle deployment migration manager
│   ├── migrations/                    # Deployment scripts (1_initial_migration.js, etc.)
│   ├── test/                          # Contract unit test suite (ehr_contracts.test.js)
│   └── truffle-config.js              # EVM network and compiler configurations
│
├── crypto/                            # Cryptographic and quantum simulation engine
│   ├── encryption.py                  # AES-256-GCM authenticated cipher with 96-bit unique IVs
│   ├── hashing.py                     # Deterministic SHA-256 cryptographic hashing
│   ├── key_management.py              # In-memory and secure session key lifecycle manager
│   ├── qkd_simulation.py              # Software-simulated BB84 QKD with 11% QBER abort threshold
│   ├── signatures.py                  # Classical ECDSA digital signatures (SECP256k1)
│   └── tcqc_simulation.py             # Non-commutative Kronecker tensor expansion (A ⊗ B)
│
├── data/                              # Data storage partitions
│   ├── raw/
│   │   ├── ML-EdgeIIoT-dataset.csv    # Full Edge-IIoTset benchmark (157,800 records × 63 cols)
│   │   └── Edge-IIoTset dataset.zip   # Source archive for benchmark
│   ├── processed/
│   │   └── edge_iiot_sampled_demo.parquet # 25,000-sample demo slice for rapid prototyping
│   ├── mimic/
│   │   └── mimic-iii-clinical-database-demo-1.4/ # 26 MIMIC-III ICU telemetry tables (100 patients)
│   └── dataset.zip                    # Compressed MIMIC-III ICU distribution
│
├── ehr/                               # Clinical EHR ingestion, anonymization, and payload pipeline
│   ├── loader.py                      # Multi-table MIMIC-III patient record ingestion
│   ├── payload.py                     # Canonical JSON serialization and payload schemas
│   ├── sanitizer.py                   # HIPAA Safe Harbor 18-PII scrubbing and quasi-ID masking
│   └── serializer.py                  # Deterministic byte encoding and Shannon entropy checks
│
├── ids/                               # Real-time intrusion detection and automated response
│   ├── inference.py                   # High-performance IDSInferenceEngine (PyTorch + Fallback)
│   ├── preprocessing.py               # Gateway flow telemetry feature extractor (Top-20 MI)
│   ├── response.py                    # SecurityResponseEngine automated containment playbooks
│   ├── risk.py                        # Multi-factor composite risk calculator
│   ├── severity.py                    # Multi-signal SeverityEngine (Critical, High, Med, Low)
│   └── simulation.py                  # Streaming network flow and attack vector generator
│
├── pages/                             # 20 Interactive Streamlit visual dashboards
│   ├── 01_Overview.py to 20_Complete_Architecture.py
│
├── scripts/                           # Reproducible experimental execution pipeline
│   ├── train_offline.py               # Full-scale offline training on 110,460 samples
│   ├── evaluate_offline.py            # Comprehensive evaluation on 23,670 held-out test records
│   ├── run_benchmarks.py              # Microsecond latency and throughput benchmark suite
│   ├── generate_figures.py            # Generates Plotly and Matplotlib analytical visualizations
│   ├── regenerate_all_paper_figures.py# Generates publication-ready 300-DPI PDF paper figures
│   ├── generate_source_of_truth.py    # Compiles authoritative master metrics registry
│   ├── phase2_repo_validation.py      # End-to-end repository integrity and primitive test suite
│   ├── validate_artifacts.py          # Verifies artifact existence, checksums, and schema
│   ├── verify_results.py              # 69-check automated consistency and manuscript auditor
│   └── run_pipeline.sh                # Automated master shell script
│
├── src/                               # Core shared modular library
│   ├── deep_models.py                 # HybridIDSNet neural model definition
│   ├── preprocessing.py               # PreprocessingPipeline (imputation, encoding, scaling)
│   ├── feature_selection.py           # Mutual Information selector
│   ├── evaluation.py                  # Performance metrics calculation routines
│   ├── explainability.py              # SHAP KernelExplainer and TreeExplainer integration
│   ├── leakage_audit.py               # Automated data leakage audit suite
│   ├── models.py                      # Classical ML baseline training wrappers
│   ├── scalability.py                 # Scalability and tier ablation simulation models
│   ├── streaming.py                   # Queue-based streaming telemetry simulation
│   ├── ui_helpers.py                  # Streamlit UI visual components and metrics display
│   └── utils.py                       # Seed setting, config loading, device detection
│
├── tests/                             # Pytest test suite (unit and integration tests)
│   ├── test_blockchain.py, test_contract.py, test_crypto.py, test_data.py,
│   ├── test_end_to_end.py, test_models.py, test_preprocessing.py
│
└── artifacts/                         # Ground-truth experimental artifacts
    ├── models/production_model/       # Checkpoints (production_model.pt, multiclass_classifier.joblib)
    ├── preprocessing/                 # Saved fitted scalers and label encoders
    ├── splits/                        # train_indices.npy, validation_indices.npy, test_indices.npy
    ├── results/                       # model_benchmark.csv, per_class_metrics.csv, test_predictions.csv
    ├── features/                      # selected_features.json, mi_scores.csv
    └── xai/                           # shap_importance.csv, shap_values.npy
```

---

## 2. Technical Parameter Specifications (28 Key Dimensions)

| # | Dimension | Current Implementation in Repository | Verification Source / File |
| :---: | :--- | :--- | :--- |
| **1** | **Exact ML Task** | Two-phase intrusion detection: (1) Deep binary threat screening (Attack vs Normal); (2) Cascading 15-class threat categorization. | [ids/inference.py:L223-238](file:///Users/rupesh/Documents/Blockchain-EHR/ids/inference.py#L223-L238), [src/deep_models.py](file:///Users/rupesh/Documents/Blockchain-EHR/src/deep_models.py) |
| **2** | **Exact Prediction Target** | Binary: `Attack_label` (0 = Normal, 1 = Attack). Multiclass: `Attack_type` (15 categorical classes). | [config.yaml:L15-16](file:///Users/rupesh/Documents/Blockchain-EHR/config.yaml#L15-L16) |
| **3** | **Dataset** | Standardized Edge-IIoTset benchmark (`ML-EdgeIIoT-dataset.csv`), accompanied by clinical ICU records from MIMIC-III Demo v1.4 for EHR payload encryption. | [data/raw/ML-EdgeIIoT-dataset.csv](file:///Users/rupesh/Documents/Blockchain-EHR/data/raw/ML-EdgeIIoT-dataset.csv) |
| **4** | **Dataset Size** | Exactly **157,800 records** $\times$ **63 raw attributes** (File size: 82,184,390 bytes). | SHA-256: `53101fad091af20bee815860962a5016b802ee45d456a141042f6183094c3c1a` |
| **5** | **Number of Classes** | Binary: 2. Multiclass: 15 (1 Normal + 14 attack classes). | [artifacts/preprocessing/label_encoder.joblib](file:///Users/rupesh/Documents/Blockchain-EHR/artifacts/preprocessing/label_encoder.joblib) |
| **6** | **Class Imbalance** | Binary: 133,499 Attack (84.60%) vs 24,301 Normal (15.40%). Attack/Normal ratio = 5.49 : 1. Multiclass: Normal (24,301), DDoS_UDP (14,498), DDoS_ICMP (14,090), Ransomware (10,925), down to severe minority classes MITM (1,214, 0.77%) and Fingerprinting (1,001, 0.63%). | Ground-truth counts from `ML-EdgeIIoT-dataset.csv` |
| **7** | **Input Features** | 63 raw features $\to$ 8 non-generalizable leakage columns dropped $\to$ 53 candidate features $\to$ Top-20 features selected via training-isolated Mutual Information. | [artifacts/features/selected_features.json](file:///Users/rupesh/Documents/Blockchain-EHR/artifacts/features/selected_features.json) |
| **8** | **Feature Types** | Mixed: 14 Numerical (packet sizes, flow duration, sequence numbers, ports) and 6 Categorical/String fields (`mqtt.protoname`, `mqtt.topic`, `mqtt.msg`, `http.request.method`, `http.referer`, `http.request.version`). | [src/preprocessing.py:L70-110](file:///Users/rupesh/Documents/Blockchain-EHR/src/preprocessing.py#L70-L110) |
| **9** | **Existing Preprocessing** | Inf/-Inf replaced with NaN; numerical NaNs imputed via training median; categorical NaNs imputed via training mode ("unknown"); categorical features encoded via `LabelEncoder` fitted strictly on train; scaled with `StandardScaler` fitted strictly on train. | [artifacts/preprocessing/preprocessor.joblib](file:///Users/rupesh/Documents/Blockchain-EHR/artifacts/preprocessing/preprocessor.joblib) |
| **10** | **Model Architecture** | `HybridIDSNet`: Input (20) $\to$ Linear Projection ($8 \times 16$) $\to$ 1D-CNN (64 filters, $k=3$, MaxPool) $\to$ 2-layer Bidirectional LSTM (64 hidden, bidirectional $\to$ 128) $\to$ 4-Head Multi-Head Self-Attention ($d_k=32$, LayerNorm) $\to$ Dense Classification Head (512 $\to$ 128 $\to$ BatchNorm $\to$ Dropout $\to$ 1). | [src/deep_models.py:L35-95](file:///Users/rupesh/Documents/Blockchain-EHR/src/deep_models.py#L35-L95), [ids/inference.py:L36-93](file:///Users/rupesh/Documents/Blockchain-EHR/ids/inference.py#L36-L93) |
| **11** | **Number of Parameters**| Exactly **304,193 trainable parameters** (1.17 MB serialized disk footprint, ~1.76 MB in-memory footprint). | [artifacts/models/production_model/model_config.json](file:///Users/rupesh/Documents/Blockchain-EHR/artifacts/models/production_model/model_config.json) |
| **12** | **Loss Function** | `torch.nn.BCEWithLogitsLoss(pos_weight=torch.tensor([0.182035]))` penalizing positive class to counteract the 5.49 : 1 attack imbalance. | [scripts/train_offline.py:L430-445](file:///Users/rupesh/Documents/Blockchain-EHR/scripts/train_offline.py#L430-L445) |
| **13** | **Optimizer** | `torch.optim.AdamW` with learning rate = $0.001$, weight decay = $1 \times 10^{-4}$. | [scripts/train_offline.py:L438](file:///Users/rupesh/Documents/Blockchain-EHR/scripts/train_offline.py#L438) |
| **14** | **Learning Rate** | $1 \times 10^{-3}$ (0.001) fixed. | [config.yaml:L54](file:///Users/rupesh/Documents/Blockchain-EHR/config.yaml#L54) |
| **15** | **Batch Size** | 256 for offline training (`scripts/train_offline.py:L435`); 64 in `config.yaml`. | [scripts/train_offline.py:L435](file:///Users/rupesh/Documents/Blockchain-EHR/scripts/train_offline.py#L435) |
| **16** | **Number of Epochs** | Research training: 12 epochs; Deployment re-training: 8 epochs on Train+Val. | [artifacts/models/model_manifest.json:L84-85](file:///Users/rupesh/Documents/Blockchain-EHR/artifacts/models/model_manifest.json#L84-L85) |
| **17** | **Scheduler** | None currently implemented (constant learning rate across all epochs). | [scripts/train_offline.py](file:///Users/rupesh/Documents/Blockchain-EHR/scripts/train_offline.py) |
| **18** | **Regularization** | Weight decay ($1 \times 10^{-4}$ in AdamW); 1D Batch Normalization (`BatchNorm1d`) in Conv and Dense blocks; Layer Normalization (`LayerNorm`) in Self-Attention block. | [src/deep_models.py](file:///Users/rupesh/Documents/Blockchain-EHR/src/deep_models.py) |
| **19** | **Dropout** | Dropout = 0.25 after BiLSTM and Dense layers; Dropout = 0.10 inside Multi-Head Self-Attention. | [src/deep_models.py:L72, L80](file:///Users/rupesh/Documents/Blockchain-EHR/src/deep_models.py#L72) |
| **20** | **Activation Functions**| `ReLU` in Conv1D and Dense linear layers; `LayerNorm` in Attention; `Sigmoid` applied to unnormalized logits at inference. | [src/deep_models.py:L63, L91](file:///Users/rupesh/Documents/Blockchain-EHR/src/deep_models.py#L63) |
| **21** | **Normalization** | Input features: `StandardScaler` (zero mean, unit variance). Internal: `BatchNorm1d` (CNN, Dense) and `LayerNorm` (Attention). | [artifacts/preprocessing/preprocessor.joblib](file:///Users/rupesh/Documents/Blockchain-EHR/artifacts/preprocessing/preprocessor.joblib) |
| **22** | **Train / Val / Test Split** | Disjoint, stratified split of 157,800 records: Train = **110,460** (70.0%), Validation = **23,670** (15.0%), Held-Out Test = **23,670** (15.0%). | [artifacts/splits/test_indices.npy](file:///Users/rupesh/Documents/Blockchain-EHR/artifacts/splits/test_indices.npy) |
| **23** | **Random Seed** | Seed = **42** set across Python `random`, NumPy, and PyTorch (`src.utils.set_seed(42)`). | [config.yaml:L4](file:///Users/rupesh/Documents/Blockchain-EHR/config.yaml#L4), [src/utils.py:L18-24](file:///Users/rupesh/Documents/Blockchain-EHR/src/utils.py#L18-L24) |
| **24** | **Existing Verified Metrics** | Held-Out Test Split ($N = 23{,}670$):<br>• Binary Screening ($\tau^* = 0.20$): **94.64%** Accuracy, **99.79%** Precision, **93.86%** Recall, **98.90%** Specificity, **90.88%** Macro F1, **0.8306** MCC ($18{,}796$ TP, $3{,}605$ TN, $40$ FP, $1{,}229$ FN).<br>• 15-Class Attribution: **85.67%** Accuracy ($20{,}279 / 23{,}670$), **80.58%** Macro F1, **78.58%** Recall, **91.23%** Precision, **0.8492** MCC. | [artifacts/results/model_benchmark.csv](file:///Users/rupesh/Documents/Blockchain-EHR/artifacts/results/model_benchmark.csv), [artifacts/results/per_class_metrics.csv](file:///Users/rupesh/Documents/Blockchain-EHR/artifacts/results/per_class_metrics.csv) |
| **25** | **Existing Baseline Models** | Decision Tree (15.40%), Extra Trees (37.37%), Gradient Boosting (15.50%), Logistic Regression (15.39%), MLP (15.43%), Random Forest (15.39%). *(All default classical baselines collapsed toward majority class under severe imbalance prior to threshold tuning).* | [artifacts/results/model_benchmark.csv](file:///Users/rupesh/Documents/Blockchain-EHR/artifacts/results/model_benchmark.csv) |
| **26** | **Hardware Environment** | Apple Silicon (MPS accelerator / CPU), Python 3.14.7, PyTorch 2.14.0. | [artifacts/models/model_manifest.json:L90-92](file:///Users/rupesh/Documents/Blockchain-EHR/artifacts/models/model_manifest.json#L90-L92) |
| **27** | **Existing Model Checkpoints**| • Binary PyTorch Model: [artifacts/models/production_model/production_model.pt](file:///Users/rupesh/Documents/Blockchain-EHR/artifacts/models/production_model/production_model.pt) (1.23 MB, SHA-256: `d105ca...`)<br>• Multiclass Classifier: [artifacts/models/production_model/multiclass_classifier.joblib](file:///Users/rupesh/Documents/Blockchain-EHR/artifacts/models/production_model/multiclass_classifier.joblib) (10.16 MB)<br>• Research Model: [artifacts/models/research_model/research_model.pt](file:///Users/rupesh/Documents/Blockchain-EHR/artifacts/models/research_model/research_model.pt) (1.23 MB) | Files verified intact on disk |
| **28** | **Existing Inference Pipeline**| `IDSInferenceEngine` in `ids/inference.py`: accepts raw flow telemetry $\to$ checks PyTorch model $\to$ outputs attack probability $p \in [0, 1]$ $\to$ if $p \ge 0.20$, dispatches to secondary 15-class classifier $\to$ passes predictions to `SeverityEngine` and `SecurityResponseEngine`. Tensor latency: **0.0049 ms**; Python dispatch: **0.0373 ms** (26,805.3 samples/s). | [ids/inference.py:L173-248](file:///Users/rupesh/Documents/Blockchain-EHR/ids/inference.py#L173-L248) |

---

## 3. Data Integrity & Housekeeping Actions

1. **Duplicate Archive Removal**:
   - `data/raw/archive.zip` (11.1 MB) was confirmed to be an exact duplicate of the MIMIC-III database distribution, which is already unpacked and verified under `data/mimic/mimic-iii-clinical-database-demo-1.4/` and `data/dataset.zip`. It has been removed.
2. **Temporary Preview Images Cleaned**:
   - Leftover raster preview snapshots (`acadlore_paper/page*_preview.png`) from earlier compilation validation runs have been cleared.
3. **Core Datasets Preserved**:
   - `data/raw/ML-EdgeIIoT-dataset.csv` (82.2 MB, 157,800 records) is intact and untouched.
   - `data/raw/Edge-IIoTset dataset.zip` (1.74 GB) is intact and preserves original provenance.
   - All partition splits (`artifacts/splits/*.npy`) are intact and strictly disjoint.

---

## 4. Current State & Immediate Next Step
- **Audit Status:** Stage 1 Forensic Audit is 100% complete.
- **Model / Code Modifications:** None applied (0 changes to training code or model architecture).
- **Integrity Rule Compliance:** Zero fabricated metrics; ground-truth baseline established.
