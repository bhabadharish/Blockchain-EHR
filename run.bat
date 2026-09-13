@echo off
REM ==============================================================================
REM Edge-IIoT Quantum-Blockchain IDS Demonstration Platform Launcher (Windows)
REM ==============================================================================

echo ========================================================================
echo Starting Edge-IIoT Post-Quantum Blockchain IDS Platform
echo PhD Research ^& Demonstration Suite (JIDMIS 2026 Framework)
echo ========================================================================

IF EXIST .venv\Scripts\activate.bat (
    echo Activating Python virtual environment (.venv)...
    call .venv\Scripts\activate.bat
) ELSE (
    echo Virtual environment not found. Using system python...
)

echo Verifying core modules...
python -c "import torch, sklearn, web3, cryptography, streamlit; print('Core modules operational.')"

echo Launching Streamlit SOC Dashboard on http://localhost:8501 ...
streamlit run app.py --server.port 8501
