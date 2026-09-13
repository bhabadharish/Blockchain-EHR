#!/usr/bin/env python3
"""
CLI Entrypoint for Stage 1 - Step 3: Offline Comprehensive Evaluation.
Delegates execution to scripts/evaluate_offline.py.
"""
import os
import sys
import runpy

if __name__ == "__main__":
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "evaluate_offline.py")
    runpy.run_path(script_path, run_name="__main__")
