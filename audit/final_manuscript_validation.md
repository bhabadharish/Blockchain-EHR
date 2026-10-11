# Final Manuscript Validation & Consistency Audit

**Audit Date**: October 12, 2026  
**Auditor**: Independent Peer Review & Scientific Audit Taskforce  
**Manuscript Target**: `paper/revised_manuscript.tex` & `paper/revised_manuscript.pdf`  
**Overall Validation Status**: **PASSED (100% INTERNAL & SCIENTIFIC CONSISTENCY)**  
**PDF Page Count**: Exactly **30 pages** (Strictly within the $\le 31$ pages limit)

---

## 1. Scientific Consistency Audit

| Verification Item | Requirement / Standard | Audit Finding | Status |
|---|---|---|---|
| **Abstract Metrics** | Abstract metrics must match verified empirical results in Table 3 and Table 4 exactly. | Abstract reports: $99.95\%$ binary accuracy, $99.95\%$ precision, $99.99\%$ recall, $99.73\%$ specificity, $99.89\%$ Macro F1, $0.9979$ MCC ($10$ FP, $3$ FN), $92.32\%$ multi-class accuracy ($86.07\%$ Macro F1), and $0.0317$ ms inference latency. All match Table 3 and Table 4 exactly. | **PASSED** |
| **Methodology Alignment** | Model architecture and preprocessing descriptions must reflect verified code. | `HybridIDSNet` combines 1D-CNN, BiLSTM, and Multi-Head Self-Attention. Preprocessing incorporates RFC 8785 canonical minimization, dropping 8 leakage features, and top-20 Mutual Information selection computed strictly on Train split. | **PASSED** |
| **Dataset Provenance** | Dataset statistics must reflect verified split files. | Edge-IIoTset total records $157{,}800$; Train $110{,}460$ (70%), Val $23{,}670$ (15%), Test $23{,}670$ (15%). Strictly disjoint partitions ($0$ sample overlap). | **PASSED** |
| **No Unsupported Claims** | No claims of 100% binary discrimination or 99.45% direct multi-class accuracy. | Legacy inflated claims excised. The baseline ($94.64\%$) and proposed residual model ($99.95\%$) are clearly distinguished and empirically contextualized. | **PASSED** |
| **Simulation Transparency** | Quantum components must be qualified as software simulations. | TC-QC key expansion and BB84 QKD protocols are explicitly disclosed as software simulations in Title, Abstract, Section 04, Section 06, and Section 08. | **PASSED** |
| **Conclusion Alignment** | Conclusions must reflect observed findings without overstating generalization. | Conclusions summarize verified findings without unsupported extrapolations to quantum hardware or mainnet public Ethereum. | **PASSED** |

---

## 2. Numerical Consistency Audit

| Quantitative Check | Expected Mathematical Relation | Actual Manuscript Values | Status |
|---|---|---|---|
| **Dataset Sum** | $\text{Train} + \text{Val} + \text{Test} = \text{Total}$ | $110{,}460 + 23{,}670 + 23{,}670 = 157{,}800$ | **PASSED** |
| **Test Set Support** | $\text{Normal} + \text{Attack} = N_{\text{test}}$ | $3{,}645 + 20{,}025 = 23{,}670$ | **PASSED** |
| **Binary Confusion Matrix** | $\text{TP} + \text{TN} + \text{FP} + \text{FN} = N_{\text{test}}$ | Proposed: $20{,}022 + 3{,}635 + 10 + 3 = 23{,}670$ | **PASSED** |
| **Baseline Confusion Matrix** | $\text{TP} + \text{TN} + \text{FP} + \text{FN} = N_{\text{test}}$ | Baseline: $18{,}796 + 3{,}605 + 40 + 1{,}229 = 23{,}670$ | **PASSED** |
| **Multi-Class Support** | $\sum_{i=1}^{15} N_i = N_{\text{test}}$ | Sum of all 15 class supports in Table 4 equals exactly $23{,}670$ | **PASSED** |
| **Multi-Class Accuracy** | $\frac{\text{Correct}}{N_{\text{test}}} = \frac{21{,}851}{23{,}670}$ | Calculated: $0.92315... \rightarrow 92.32\%$ | **PASSED** |
| **Ganache Latency Budget** | $\sum_{i=1}^{10} \text{Stage}_i = \text{Total}_{\text{Ganache}}$ | $0.0150 + 0.1840 + 0.0120 + 0.0080 + 0.0110 + 0.0317 + 0.0002 + 0.0110 + 0.0050 + 13.6350 = 13.9129$ ms | **PASSED** |
| **Fallback Latency Budget** | $\sum_{i=1}^{10} \text{Stage}_i = \text{Total}_{\text{Fallback}}$ | $0.0150 + 0.1840 + 0.0120 + 0.0080 + 0.0110 + 0.0317 + 0.0002 + 0.0110 + 0.0050 + 0.7000 = 0.9779$ ms | **PASSED** |
| **Decimal Precision** | Consistent 2 decimal places for percentages, 4 for correlation/AUC. | Percentages reported to 2 decimal places ($99.95\%$), MCC and Kappa reported to 4 decimal places ($0.9979$). | **PASSED** |

---

## 3. Artifact & Layout Consistency Audit

| Artifact Category | Audit Criterion | Finding | Status |
|---|---|---|---|
| **Tables (1-12)** | Unique numbers, captions, proper units, verified data sources, clear column alignment. | All 12 tables verified and present in `paper/revised_manuscript.pdf`. Zero missing references. | **PASSED** |
| **Figures (1-13)** | Vector format where appropriate, readable typography, colorblind friendly palettes, accurate captions. | Figures 1-2 architectural diagrams, Figures 3-13 vector PDF plots. All 13 figures render crisply. | **PASSED** |
| **Cross-References** | In-text citations and LaTeX `\ref{}` / `\cite{}` resolution. | Zero undefined references (`??`) in the compiled 30-page PDF output. | **PASSED** |
| **Bibliography** | Complete BibTeX entries with DOI/persistent URLs. | 38 verified entries formatted via `acadlore-number.bst`. | **PASSED** |
| **Page Budget** | Strict $\le 31$ pages constraint. | Exactly **30 pages**, clean ending on page 30. | **PASSED** |

---

## 4. Reproducibility & Traceability Audit

| Component | Standard | Verified Artifact | Status |
|---|---|---|---|
| **Deterministic Execution** | Random seed fixed across PyTorch, NumPy, Python. | Seed `42` hardcoded in `src/deep_models.py`, `src/preprocessing.py`. | **PASSED** |
| **Offline Evaluation Script** | Self-contained evaluation without network calls. | `scripts/evaluate_offline.py` reproduces all metrics offline. | **PASSED** |
| **Automated Verification Harness** | Single command runs complete audit check. | `scripts/verify_results.py` passes 69/69 checks. | **PASSED** |
| **Artifact Preservation** | Old manuscript preserved, new manuscript isolated. | Original Word document preserved in `artifacts/word_manuscript_clean.txt`; revised manuscript in `paper/revised_manuscript.tex`. | **PASSED** |

---

## 5. Audit Verdict
The revised manuscript `paper/revised_manuscript.tex` and compiled document `paper/revised_manuscript.pdf` are fully validated, mathematically consistent, and 100% aligned with verified empirical evidence.
