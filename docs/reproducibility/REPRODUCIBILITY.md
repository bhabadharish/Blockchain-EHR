# Reproducibility Guide: Evidence-First Independent Verification

**Project Title**: Decoupled Zero-Trust Architecture for IoMT and EHR Security  
**Repository**: `https://github.com/bhabadharish/Blockchain-EHR`  
**Publication Submission**: Acadlore Submission Manuscript (`paper/final/main.pdf`)  
**Target Environment**: macOS / Linux / Docker | Python 3.11–3.14 | PyTorch >= 2.4.0  

---

## 1. Environment & Prerequisite Setup

### 1.1 Native Python Virtual Environment
```bash
# 1. Clone repository
git clone https://github.com/bhabadharish/Blockchain-EHR.git
cd Blockchain-EHR

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install pinned dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 1.2 LaTeX Compilation Prerequisites (Optional for PDF Re-generation)
To compile the publication manuscript:
```bash
# macOS (Homebrew)
brew install mactex-no-gui  # or brew install tectonic

# Ubuntu / Debian
sudo apt-get install -y texlive-latex-extra texlive-fonts-recommended texlive-bibtex-extra
```

---

## 2. One-Command Master Verification Protocol

To run the complete automated 69-check forensic verification across all models, CSV files, LaTeX text, tables, and PDF pages:

```bash
python scripts/verify_results.py
```
**Expected Output**:
```text
================================================================================
VERIFICATION SUMMARY: 69 / 69 CHECKS PASSED
RESULT: ALL GLOBAL CONSISTENCY CHECKS PASSED PERFECTLY!
The repository, models, evaluation results, figures, and manuscript are 100% synchronized.
================================================================================
```

---

## 3. Step-by-Step Individual Reproduction Protocols

### Protocol A: Full Automated Test Suite
Executes all 25 unit and integration tests across blockchain clients, crypto engines, data pipelines, model inference, and SOC response playbooks:
```bash
pytest tests/ -v
```
**Expected Outcome**: 25 passed in under 6 seconds.

### Protocol B: Artifact Integrity & Manifest Validation
Verifies SHA-256 model checksums, feature configurations, preprocessors, and test outputs:
```bash
python scripts/validate_artifacts.py
```
**Expected Outcome**: All 8 gates PASS.

### Protocol C: Cryptographic & Security Primitive Validation
Verifies AES-256-GCM authenticated cipher round-trips, simulated TC-QC fidelity, simulated BB84 QKD 11% abort threshold, and smart contract access control:
```bash
python scripts/phase2_repo_validation.py
```
**Expected Outcome**: All 4 validation suites PASS.

### Protocol D: Held-Out Test Set Re-Evaluation
Unblinds the held-out test partition ($N = 23{,}670$ records, $15.0\%$ of Edge-IIoTset) to evaluate the production models:
```bash
python scripts/reproduce_and_verify_final.py
```
**Verified Results**:
- **Tier-1 Deep Binary Screening** (`HybridIDSNet` with Conv1D Residual Highway, $\tau^* = 0.50$):
  - Accuracy: **99.95%** ($0.999451$)
  - Precision: **99.95%** ($0.999501$)
  - Recall / Sensitivity: **99.99%** ($0.999850$)
  - Specificity: **99.73%** ($0.997257$)
  - Macro F1-Score: **99.89%** ($0.998945$)
  - Matthews Correlation Coefficient (MCC): **0.9979**
  - False Alarms (FP): **10** ($\text{FPR} = 0.27\%$)
  - Missed Attacks (FN): **3** ($\text{FNR} = 0.01\%$)
- **Tier-2 15-Class Threat Categorization** (`HistGradientBoostingClassifier`):
  - Overall Accuracy: **92.32%** ($21{,}851 / 23{,}670$)
  - Macro F1-Score: **86.07%**
  - Macro Precision: **94.16%**
  - Macro Recall: **83.88%**
  - Normal Traffic Precision: **100.00%** (0 false alarms)
  - `DDoS_UDP` Recall: **90.62%** ($1{,}970 / 2{,}174$)

### Protocol E: Manuscript Compilation & Page Count
To compile the official publication manuscript:
```bash
cd acadlore_paper
pdflatex -interaction=nonstopmode main.tex
bibtex main
pdflatex -interaction=nonstopmode main.tex
pdflatex -interaction=nonstopmode main.tex
cd ..
```
The compiled publication PDF is saved to `paper/final/main.pdf` (exactly 30 pages, satisfying the $\le 31$ page limit).

---

## 4. Disclosed Software Simulations vs Physical Deployments

To ensure absolute scientific integrity, the following implementation boundaries are explicitly disclosed:

1. **TC-QC Key Expansion**: Software-simulated non-commutative Kronecker tensor algebra ($A \otimes B$) in Python (`crypto/tcqc_simulation.py`). Evaluated for latency and algebraic non-commutativity ($[A, B] \ne 0$), not on physical quantum processors.
2. **BB84 QKD Protocol**: Software simulation (`crypto/qkd_simulation.py`) modeling state preparation, measurement basis selection, and intercept-resend eavesdropping. Baseline QBER is $0.0\%-1.22\%$, rising to $25.0\%-28.9\%$ under active interception, triggering the $11.0\%$ abort threshold.
3. **Blockchain Ledger**: Smart contracts (`EHRAccessControl.sol`, `EHRIntegrityRegistry.sol`) are fully implemented in Solidity v0.8.x and compiled with Truffle. The repository includes an in-memory Python ledger fallback (`blockchain/python_ledger.py`) for reproducible, offline demonstration without requiring a live Ethereum testnet or Ganache node.
