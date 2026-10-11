# Intelligent Project Repository Cleanup Plan

**Audit Date**: October 12, 2026  
**Auditor**: Software Architect & Repository Maintenance Specialist  
**Repository**: `Blockchain-EHR`  
**Root Path**: `/Users/rupesh/Documents/Blockchain-EHR`

---

## 1. Executive Summary & Objective

The objective of this cleanup plan is to create a clean, organized, minimal, and fully functional research repository without sacrificing scientific evidence, model checkpoints, raw predictions, manuscript sources, figures, or reviewer reproducibility artifacts.

### Absolute Safety Guarantees
1. **Zero Evidence Deletion**: No CSV, JSON, Parquet, or raw dataset files will be deleted.
2. **Zero Checkpoint Deletion**: No `.pt`, `.joblib`, or preprocessor weights will be removed.
3. **Zero Manuscript Compromise**: All LaTeX files (`acadlore_paper/`, `paper/`), bibliography files (`references.bib`), and rendered PDFs remain intact.
4. **Zero Verification Disruption**: Test fixtures, pytest scripts, and verification harnesses remain untouched.
5. **Reversible & Staged**: Only disposable OS metadata (`.DS_Store`), python bytecode caches (`__pycache__`), and temporary ad-hoc test snippets are targeted for removal.

---

## 2. Inventory Breakdown by Classification

Based on [audit/file_inventory.csv](file:///Users/rupesh/Documents/Blockchain-EHR/audit/file_inventory.csv) (623 total files scanned outside `.git` and `.venv`):

| Classification Category | File Count | Approximate Storage | Primary Locations & Purpose |
|---|---|---|---|
| `KEEP_PROJECT` | ~160 files | ~15 MB | Core application code (`src/`, `ids/`, `crypto/`, `blockchain/`, `ehr/`, `pages/`), entry points (`app.py`), and test suites (`tests/`). |
| `KEEP_RESEARCH_PAPER` | ~115 files | ~25 MB | Manuscript sources, style files (`acadlore.cls`), figures, and compiled documents in `paper/` and `acadlore_paper/`. |
| `KEEP_EXPERIMENTAL_EVIDENCE` | ~275 files | ~95 MB | Checkpoints (`production_model.pt`, `multiclass_classifier.joblib`), predictions, ROC/PR data, splits, reports, and `scratch/` iteration weights. |
| `KEEP_DOCUMENTATION` | ~30 files | ~1.5 MB | `README.md`, `LICENSE`, `docs/` (`REPRODUCIBILITY.md`, `REVIEWER_GUIDE.md`, `DEPLOYMENT.md`), and `audit/` reports. |
| `KEEP_CONFIGURATION` | ~12 files | ~100 KB | Environment manifests (`requirements.txt`, `config.yaml`, `.gitignore`, `.env.example`, `run.sh`). |
| `KEEP_DEPLOYMENT` | ~4 files | ~50 KB | `Dockerfile`, `docker-compose.yml`, `.dockerignore`. |
| `SAFE_TO_REMOVE` | ~25 files | ~150 KB | `.DS_Store` metadata, `__pycache__/*.pyc` bytecode caches, ad-hoc `test_tw.tex`. |
| `DUPLICATE_CANDIDATE` | 1 file | ~5.8 MB | `acadlore_paper.zip` (backup archive of `acadlore_paper/`). Retained or quarantined pending author decision. |

---

## 3. Preservation Directives (What Remains Untouched)

### 3.1 Project Source Code & Execution Entry Points
- `app.py`: Streamlit SOC dashboard entry point.
- `src/`: Core implementation modules (`deep_models.py`, `preprocessing.py`, `scalability.py`, `crypto.py`, `smart_contract.py`, `streaming.py`).
- `ids/`: Production dual-tier inference engine (`inference.py`, `detector.py`).
- `crypto/` & `blockchain/`: Cryptographic primitives and local EVM interaction harnesses.
- `scripts/`: Reproducibility, evaluation, figure generation, and verification scripts.
- `tests/`: PyTest test suite (25 unit and integration tests).

### 3.2 Research Paper & Publication Assets
- `paper/revised_manuscript.tex` & `paper/revised_manuscript.pdf`: Primary revised publication document (30 pages).
- `paper/figures/`: High-resolution architectural graphics and vector PDFs (Figures 1–13).
- `paper/tables/`: Modular `.tex` table files (Tables 1–21).
- `acadlore_paper/`: Historical working directory preserving original compilation context.
- `Acadlore paper/`: Original vendor template and early JIDMIS submission PDF.

### 3.3 Experimental Evidence & Models
- `data/raw/ML-EdgeIIoT-dataset.csv`: Verified raw dataset.
- `artifacts/models/`: Trained model checkpoints (`production_model.pt`, `multiclass_classifier.joblib`, `model_manifest.json`).
- `artifacts/splits/`: Disjoint partition indices (`train_indices.npy`, `validation_indices.npy`, `test_indices.npy`).
- `artifacts/results/`: Ground-truth prediction logs, confusion matrices, ROC/PR coordinate arrays.
- `results/source_of_truth.json` & `results/verified_metrics.json`: Authoritative numerical registries.

---

## 4. Proposed Removals & Justifications

Only files meeting strict criteria for non-destructiveness are approved for removal:

1. **Mac OS Metadata (`.DS_Store`)**:
   - `/.DS_Store`
   - `/Acadlore paper/.DS_Store`
   - `/acadlore_paper/.DS_Store`
   - *Justification*: Operating system window position metadata; causes git clutter and carries zero project value.
2. **Python Bytecode Caches (`__pycache__` and `*.pyc`)**:
   - `/__pycache__/`
   - `/src/__pycache__/`
   - `/scripts/__pycache__/`
   - `/scratch/__pycache__/`
   - *Justification*: Auto-generated bytecode; fully regenerated on Python execution; safe to clear.
3. **Ad-Hoc Compiler Test Snippet**:
   - `acadlore_paper/test_tw.tex`
   - *Justification*: Temporary 6-line file created solely to test textwidth dimension; unreferenced by the manuscript.

---

## 5. Execution Safeguards
- All removals will be recorded in [audit/deletion_manifest.csv](file:///Users/rupesh/Documents/Blockchain-EHR/audit/deletion_manifest.csv).
- After cleanup, the full test suite (`pytest tests/`), artifact validation (`validate_artifacts.py`), global consistency audit (`verify_results.py`), and PDF compilation (`pdflatex revised_manuscript.tex`) will be re-executed to verify zero regression.
