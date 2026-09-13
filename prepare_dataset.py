#!/usr/bin/env python3
"""
CLI Entrypoint for Stage 1 - Step 1: Dataset Preparation.
Delegates execution to scripts/prepare_dataset.py.
"""
import os
import sys
import runpy

if __name__ == "__main__":
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "prepare_dataset.py")
    runpy.run_path(script_path, run_name="__main__")
