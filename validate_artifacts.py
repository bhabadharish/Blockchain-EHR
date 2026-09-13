#!/usr/bin/env python3
"""
CLI Entrypoint for Stage 1 - Step 5: Artifact Integrity & Validation Gate.
Delegates execution to scripts/validate_artifacts.py.
"""
import os
import sys
import runpy

if __name__ == "__main__":
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "validate_artifacts.py")
    runpy.run_path(script_path, run_name="__main__")
