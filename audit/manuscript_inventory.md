# Comprehensive Manuscript Inventory

**Audit Date**: October 12, 2026  
**Auditor**: Independent Peer Review & Scientific Audit Taskforce  
**Repository**: `Blockchain-EHR`  
**Target Venue**: *Journal of Cyber Security and Mobility* / *Acadlore Journal Systems*  
**Manuscript Format**: LaTeX (`acadlore.cls`), compiled via `pdflatex` to PDF (`paper/revised_manuscript.pdf`, 30 pages)  
**Historical Formats Evaluated**: Original Microsoft Word document (`artifacts/word_manuscript_clean.txt`, `artifacts/extracted_word_doc.txt`) and working LaTeX sources (`acadlore_paper/main.tex`, `paper/final/main.tex`).

---

## 1. Document Metadata & Publishing Parameters

| Parameter | Current Specification | Source in Manuscript |
|---|---|---|
| **Manuscript Title** | *Tensor-Categorical Quantum Cryptography and Smart-Contract Orchestration for Scalable, Post-Quantum Electronic Health Record Exchange* | `acadlore_paper/main.tex` L18 |
| **Authors** | Harish Parshuram Bhabad (ORCID: 0000-0002-3620-3331), Anand Singh Rajawat (Corresponding Author, ORCID: 0000-0002-2342-8321) | `acadlore_paper/main.tex` L19 |
| **Affiliation** | School of Computer Science and Engineering, Sandip University, Nashik 422213, Maharashtra, India | `acadlore_paper/main.tex` L20-21 |
| **Document Class** | `acadlore.cls` (Option: `lineno`, 2-column, line-numbered) | `acadlore_paper/main.tex` L5 |
| **Citation Style** | Numerical format (`acadlore-number.bst`), BibTeX database `references.bib` (38 references) | `acadlore_paper/main.tex` L48 |
| **Page Budget** | Strict $\le 31$ pages limit; current verified output compiles to exactly **30 pages** | `acadlore_paper/main.pdf` |

---

## 2. Research Problem, Novelty, & Claimed Contributions

### 2.1 The Core Dilemma
The manuscript addresses the security dilemma in Internet of Medical Things (IoMT) and Electronic Health Record (EHR) exchanges:
- **Client-Side E2E Encryption** protects clinical privacy and HIPAA/GDPR regulatory compliance but leaves Network Intrusion Detection Systems (NIDS) blind at perimeter security middleboxes.
- **Payload Inspection / Decryption Middleboxes** restore network perimeter threat visibility but destroy clinical confidentiality and violate zero-trust isolation.

### 2.2 Proposed Solution & Architecture
A decoupled two-phase zero-trust architecture:
1. **Phase 1 (Off-Chain Payload & Identity Protection)**: Client-side data minimization, RFC 8785 canonical serialization, authenticated AES-256-GCM symmetric encryption, simulated Tensor-Categorical Quantum Cryptography (TC-QC) key generation, and simulated BB84 Quantum Key Distribution (QKD), with cryptographic SHA-256 state commitments anchored to Ethereum smart contracts for Attribute-Based / Role-Based Access Control (ABAC/RBAC).
2. **Phase 2 (Perimeter Telemetry Screening)**: Transport- and protocol-level flow telemetry monitoring post-encryption using `HybridIDSNet` (1D-CNN spatial feature extraction + Bidirectional LSTM temporal transitions + Multi-Head Self-Attention). Flow telemetry features are pruned from 53 to 20 via training-isolated Mutual Information ranking without examining encrypted payloads.

### 2.3 Novelty Claims Audited & Grounded
- **Decoupled Security Plane**: Mathematically proves and empirically demonstrates that network perimeter threat screening does not require clinical payload decryption.
- **Empirical Rigor**: Evaluation on the modern multi-protocol Edge-IIoTset benchmark (157,800 records) with strict train/val/test isolation (70/15/15), training-isolated feature selection, and calibrated threshold tuning ($\tau^*$).
- **Explainability**: Global SHAP explainability confirms that perimeter classifications rely on transport framing and protocol header dynamics rather than encrypted clinical text.

---

## 3. Structural Section Inventory

| Section | Title | Primary Content & Objectives |
|---|---|---|
| **01** | `01_introduction.tex` | Healthcare cybersecurity landscape, IoMT attack vectors, the encryption vs. visibility paradox, and 4 explicit contributions. |
| **02** | `02_related_work.tex` | Review of blockchain EHR systems, IoMT intrusion detection, post-quantum cryptography in healthcare, and comparative analysis matrix (Table 1). |
| **03** | `03_system_model.tex` | Architectural entities (Edge Medical Sensors, Edge Gateway, Off-chain IPFS/Database, Ethereum EVM, Hospital Management System), trust assumptions, threat model, and workflow sequence (Figure 1, Figure 2). |
| **04** | `04_mathematical_modelling.tex` | Formalization of payload encryption, TC-QC key expansion tensor algebra, BB84 simulation mechanics, smart-contract state machines, and `HybridIDSNet` neural equations. |
| **05** | `05_experimental_setup.tex` | Testbed hardware/software specifications, Edge-IIoTset benchmark provenance, 8 dropped leakage features, training-only Mutual Information selection (top-20), hyperparameter tables. |
| **06** | `06_results.tex` | Comprehensive empirical evaluation: cryptographic throughput, smart contract gas/latency, baseline vs. champion binary IDS performance, 15-class threat breakdown, confusion matrices, ablation study, and XAI validation. |
| **07** | `07_discussion.tex` | Scientific synthesis: resolving the encryption-visibility paradox, feasibility of blind network defense, security guarantees, and practical clinical deployment considerations. |
| **08** | `08_limitations.tex` | Explicit scientific boundaries: software simulation of quantum channels, local EVM testbed vs. mainnet gas, synthetic benchmark characteristics, and adversarial robustness limits. |
| **09** | `09_reproducibility.tex` | Hardware environments, deterministic random seeds, software dependency versions, data availability, and step-by-step verification commands. |
| **10** | `10_conclusion.tex` | Summary of validated findings, operational implications, and future research trajectories. |
| **11** | `11_backmatter.tex` | Author contributions, funding disclosures, data availability statements, conflict of interest statements, and acknowledgments. |
| **12** | `12_nomenclature.tex` | Glossary of abbreviations, acronyms, and mathematical symbols used across all equations. |

---

## 4. Tables Inventory

| Table ID | Label | Caption Summary | Verified Content Source |
|---|---|---|---|
| **Table 1** | `tab:related_work` | Comparative analysis with existing EHR and IoMT security frameworks | Literature taxonomy & architectural audit |
| **Table 2** | `tab:dataset_distribution` | Edge-IIoTset partition statistics across Train, Val, and Test splits (15 classes + Normal) | `artifacts/results/per_class_metrics.csv`, `BASELINE_RESULTS.json` |
| **Table 3** | `tab:binary_benchmark` | Binary intrusion detection benchmark on held-out test set ($N=23{,}670$): Baseline vs. Proposed Residual HybridIDSNet | `results/source_of_truth.json`, `FINAL_RESULTS.json`, `artifacts/results/model_benchmark.csv` |
| **Table 4** | `tab:multiclass_performance` | Multi-class attack classification breakdown (15 classes) with Precision, Recall, F1, Specificity, FPR, and FNR | `artifacts/results/per_class_metrics.csv`, `FINAL_RESULTS.json` |
| **Table 5** | `tab:crypto_performance` | Cryptographic benchmark: AES-256-GCM, TC-QC simulation, and BB84 QKD simulation metrics | `artifacts/benchmarks/crypto_benchmark.json`, `src/scalability.py` |
| **Table 6** | `tab:blockchain_performance` | Smart contract operational costs: function name, gas consumed, Ganache latency, Fallback latency | `artifacts/benchmarks/blockchain_benchmark.json`, `smart_contracts/` |
| **Table 7** | `tab:latency_budget` | End-to-end 10-stage processing latency budget: Ganache EVM vs. In-memory Fallback Ledger | `results/source_of_truth.json`, `scripts/evaluate_offline.py` |
| **Table 8** | `tab:ablation_results` | Ablation study: Component contribution across CNN, BiLSTM, and Multi-Head Attention, plus Tier-2 attribution | `artifacts/results/ablation_results.csv`, `FINAL_RESULTS.json` |
| **Table 9** | `tab:hyperparameters` | Hyperparameter configurations for `HybridIDSNet` training | `src/deep_models.py`, `artifacts/models/production_model/model_config.json` |
| **Table 10** | `tab:feature_ranking` | Top-20 features selected by Mutual Information on training partition with score and description | `artifacts/features/selected_features.json`, `src/preprocessing.py` |
| **Table 11** | `tab:confusion_breakdown` | Confusion matrix summary: True Positives, True Negatives, False Positives, False Negatives | `artifacts/results/binary_confusion_matrix.csv`, `FINAL_RESULTS.json` |
| **Table 12** | `tab:reproducibility_specs` | Hardware, software, library versions, and deterministic random seeds | `docs/reproducibility/REPRODUCIBILITY.md`, `artifacts/reports/hardware_report.json` |

---

## 5. Figures Inventory

| Figure ID | Label | Caption Summary | Rendered File | Status |
|---|---|---|---|---|
| **Figure 1** | `fig:architecture` | Decoupled Two-Phase Zero-Trust System Architecture | `figures/fig1_architecture.jpg` | Verified & Active |
| **Figure 2** | `fig:topology` | IoMT Network Deployment Topology and Trust Boundaries | `figures/fig2_topology.jpg` | Verified & Active |
| **Figure 3** | `fig:class_distribution` | Normal vs. Attack Class Distribution in Edge-IIoTset | `figures/fig3_class_distribution.pdf` | Regenerated & Verified |
| **Figure 4** | `fig:attack_distribution` | Frequency Breakdown Across 14 Attack Sub-Categories | `figures/fig4_attack_distribution.pdf` | Regenerated & Verified |
| **Figure 5** | `fig:crypto_performance` | Latency and Throughput Scaling for Cryptographic Primitives | `figures/fig5_crypto_performance.pdf` | Regenerated & Verified |
| **Figure 6** | `fig:roc_curve` | Receiver Operating Characteristic (ROC) Curve ($\text{AUC} \ge 0.9924$) | `figures/fig6_roc_curve.pdf` | Regenerated & Verified |
| **Figure 7** | `fig:pr_curve` | Precision-Recall Curve ($\text{PR-AUC} \ge 0.9986$) | `figures/fig7_pr_curve.pdf` | Regenerated & Verified |
| **Figure 8** | `fig:binary_confusion` | Normalized Confusion Matrix for Binary Intrusion Screening | `figures/fig8_binary_confusion.pdf` | Regenerated & Verified |
| **Figure 9** | `fig:learning_curves` | Training and Validation Loss and Accuracy Curves (50 Epochs) | `figures/fig9_learning_curves.pdf` | Regenerated & Verified |
| **Figure 10** | `fig:multiclass_confusion`| Normalized 15-Class Confusion Matrix for Threat Attribution | `figures/fig10_multiclass_confusion.pdf` | Regenerated & Verified |
| **Figure 11** | `fig:ablation_plot` | Performance Impact Across Architectural Ablations | `figures/fig11_ablation_plot.pdf` | Regenerated & Verified |
| **Figure 12** | `fig:mi_ranking` | Top-20 Feature Mutual Information Scores on Training Set | `figures/fig12_mi_ranking.pdf` | Regenerated & Verified |
| **Figure 13** | `fig:shap_importance` | Global SHAP Feature Attributions for `HybridIDSNet` | `figures/fig13_shap_importance.pdf` | Regenerated & Verified |

---

## 6. Mathematical Notation & Formal Models

1. **RFC 8785 Canonical JSON Formatting**: $M_{\text{canon}} = \mathcal{C}(M_{\text{raw}})$.
2. **AES-256-GCM Authenticated Encryption**: $(C, T_{\text{GCM}}) = \mathcal{E}_{\text{GCM}}(K_{\text{sess}}, IV, M_{\text{canon}}, AAD)$, where $AAD = \text{SenderID} \parallel \text{Timestamp} \parallel \text{RecordType}$.
3. **TC-QC Key Expansion**: State simulation via tensor products $\rho_{\text{tensor}} = \bigotimes_{i=1}^{k} |\psi_i\rangle \langle\psi_i|$, mapped into projective measurement basis yielding $K_{\text{sess}} \in \{0, 1\}^{256}$.
4. **BB84 QKD Simulation**: Sifting phase, error detection with Quantum Bit Error Rate $\text{QBER} = \frac{n_{\text{err}}}{n_{\text{sifted}}}$, abort threshold $\tau_{\text{abort}} = 11.0\%$.
5. **Smart Contract Verification**: Proof verification $\mathcal{V}(\sigma_{\text{digest}}, \text{Policy}_{\text{ABAC}}) \in \{0, 1\}$.
6. **Feature Mutual Information**: $I(X; Y) = \sum_{x \in X} \sum_{y \in Y} p(x,y) \log \frac{p(x,y)}{p(x)p(y)}$, computed exclusively on $\mathcal{D}_{\text{train}}$.
7. **Spatial Convolution**: $z_j^{(1)} = \text{ReLU}\left(\sum_{k=1}^{C_{\text{in}}} W_{j,k}^{(1)} * x_k + b_j^{(1)}\right)$.
8. **Bidirectional Temporal Transition**: $\overrightarrow{h}_t = \text{LSTM}(x_t, \overrightarrow{h}_{t-1})$, $\overleftarrow{h}_t = \text{LSTM}(x_t, \overleftarrow{h}_{t+1})$, $h_t = [\overrightarrow{h}_t \parallel \overleftarrow{h}_t]$.
9. **Multi-Head Self-Attention**: $\text{Attention}(Q, K, V) = \text{softmax}\left(\frac{QK^T}{\sqrt{d_k}}\right)V$.
10. **Binary Screening Decision**: $\hat{y} = \mathbb{I}(P(Y=1|X) \ge \tau^*)$, where $\tau^*$ is calibrated on validation data.

---

## 7. Audit Conclusion
The manuscript is comprehensively structured, with zero missing sections, fully aligned cross-references, rigorous mathematical formalism, and all 12 tables and 13 figures cleanly linked to empirical artifacts in the project.
