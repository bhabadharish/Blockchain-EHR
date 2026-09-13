#!/usr/bin/env bash
# ==============================================================================
# Master Offline Research Training Pipeline Execution Script
# Part of PhD Research Platform: Edge-IIoT Quantum-Blockchain IDS
# ==============================================================================

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "========================================================================"
echo " STAGE 1: COMPLETE OFFLINE RESEARCH TRAINING & EVALUATION PIPELINE"
echo " Dataset: Edge-IIoTset (157,800 records, 100% participation)"
echo "========================================================================"

PYTHON_BIN="python3"
if [ -f ".venv/bin/python" ]; then
    PYTHON_BIN=".venv/bin/python"
fi

echo "Using Python binary: $PYTHON_BIN"

echo ""
echo "--- Step 1/5: Dataset Ingestion, Quality Audit & Stratified Partitioning ---"
$PYTHON_BIN scripts/prepare_dataset.py

echo ""
echo "--- Step 2/5: Full-Scale Preprocessing, MI Feature Selection & Model Training ---"
$PYTHON_BIN scripts/train_offline.py

echo ""
echo "--- Step 3/5: Held-Out Test Evaluation & Forensic Error Analytics ---"
$PYTHON_BIN scripts/evaluate_offline.py

echo ""
echo "--- Step 4/5: Offline Publication Figure & SHAP Explainability Generation ---"
$PYTHON_BIN scripts/generate_figures.py

echo ""
echo "--- Step 5/5: Comprehensive Artifact Integrity & Cryptographic Validation ---"
$PYTHON_BIN scripts/validate_artifacts.py

echo ""
echo "========================================================================"
echo " ✅ OFFLINE PIPELINE COMPLETE! All artifacts ready for Streamlit SOC."
echo " Launch the dashboard with: streamlit run app.py"
echo "========================================================================"
