#!/usr/bin/env bash
# ==============================================================================
# Edge-IIoT Quantum-Blockchain IDS Demonstration Platform Launcher
# ==============================================================================

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "========================================================================"
echo " Starting Edge-IIoT Post-Quantum Blockchain IDS Platform"
echo " PhD Research & Demonstration Suite (JIDMIS 2026 Framework)"
echo "========================================================================"

# Check virtual environment
if [ -d ".venv" ]; then
    echo " Activating Python virtual environment (.venv)..."
    source .venv/bin/activate
elif [ -n "$VIRTUAL_ENV" ]; then
    echo " Using active virtual environment: $VIRTUAL_ENV"
else
    echo " Virtual environment not found. Using system python3..."
fi

# Run fast verification test
echo " Verifying core modules..."
python3 -c "import torch, sklearn, web3, cryptography, streamlit; print(' Core modules operational.')"

# Launch Streamlit application
echo " Launching Streamlit SOC Dashboard on http://localhost:8501 ..."
streamlit run app.py --server.port 8501 --server.headless true
