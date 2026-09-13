"""
System Utilities, Hardware Profiler, Config Manager, and Reproducibility Helpers
Part of the PhD Research Platform for Edge-IIoT IDS with Blockchain & Quantum Security.
"""

import os
import random
import platform
import psutil
import yaml
import numpy as np
import torch


def load_config(config_path: str = "config.yaml") -> dict:
    """Load system configuration from YAML file."""
    if not os.path.isabs(config_path):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, config_path)
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found at: {config_path}")
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def set_seed(seed: int = 42):
    """Set global deterministic random seeds for full experimental reproducibility."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
    elif torch.backends.mps.is_available():
        torch.mps.manual_seed(seed)


def get_device(preferred: str = "auto") -> torch.device:
    """Detect and return the optimal compute device (Apple Silicon MPS, CUDA, or CPU)."""
    if preferred == "cuda" and torch.cuda.is_available():
        return torch.device("cuda")
    elif preferred == "mps" and torch.backends.mps.is_available():
        return torch.device("mps")
    elif preferred == "cpu":
        return torch.device("cpu")
    
    # Auto mode
    if torch.backends.mps.is_available():
        return torch.device("mps")
    elif torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


def get_hardware_info() -> dict:
    """Extract comprehensive system hardware and platform specifications."""
    mem = psutil.virtual_memory()
    device = get_device("auto")
    
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor() or "Apple Silicon / ARM64",
        "cpu_count_physical": psutil.cpu_count(logical=False),
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "ram_total_gb": round(mem.total / (1024 ** 3), 2),
        "ram_available_gb": round(mem.available / (1024 ** 3), 2),
        "ram_percent_used": mem.percent,
        "python_version": platform.python_version(),
        "torch_device": str(device),
        "mps_available": torch.backends.mps.is_available(),
        "cuda_available": torch.cuda.is_available(),
    }


def format_ms(seconds: float) -> str:
    """Format seconds into milliseconds string."""
    return f"{seconds * 1000:.3f} ms"


def format_tx_sec(count: int, seconds: float) -> str:
    """Calculate and format throughput in TX/sec."""
    if seconds <= 0:
        return "N/A"
    return f"{count / seconds:,.1f} TX/s"
