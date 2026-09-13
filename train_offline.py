#!/usr/bin/env python3
"""
CLI Entrypoint for Stage 1 - Step 2: Offline Training Factory.
Delegates execution to scripts/train_offline.py.
"""
import os
import sys
import runpy

if __name__ == "__main__":
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "train_offline.py")
    runpy.run_path(script_path, run_name="__main__")
