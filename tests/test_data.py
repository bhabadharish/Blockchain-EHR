"""
Unit tests for DataLoader, schema validation, and health scoring.
"""

import pytest
import os
import pandas as pd
from src.data_loader import DataLoader


def test_dataloader_extraction_and_discovery():
    loader = DataLoader()
    csv_path = loader.ensure_extracted()
    assert os.path.exists(csv_path), "Extracted CSV file does not exist"
    assert os.path.getsize(csv_path) > 1024 * 1024, "Extracted CSV file is too small"

    candidates = loader.discover_datasets(".")
    assert len(candidates) > 0, "No candidate datasets discovered"


def test_dataloader_sampling_and_health():
    loader = DataLoader()
    df = loader.load_raw_data(sample_mode="demo")
    assert len(df) <= 25001, "Demo dataframe exceeds sample limit"
    assert "Attack_label" in df.columns, "Attack_label missing from demo dataframe"
    assert "Attack_type" in df.columns, "Attack_type missing from demo dataframe"

    health = loader.inspect_health(df)
    assert health["health_score"] >= 70.0, f"Health score unexpectedly low: {health['health_score']}"
    assert len(health["multiclass_distribution"]) == 15, "Expected 15 classes in Edge-IIoTset"
    assert health["status"] in ["HEALTHY", "MODERATE"]
