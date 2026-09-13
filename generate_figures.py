#!/usr/bin/env python3
"""
CLI Entrypoint for Stage 1 - Step 4: Figure & XAI Generation.
Delegates execution to scripts/generate_figures.py.
"""
import os
import sys
import runpy

if __name__ == "__main__":
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "generate_figures.py")
    runpy.run_path(script_path, run_name="__main__")
