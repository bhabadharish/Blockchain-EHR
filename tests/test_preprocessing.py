"""
Unit tests for preprocessing pipeline and data leakage audit.
"""

import pytest
import numpy as np
from src.data_loader import DataLoader
from src.preprocessing import PreprocessingPipeline
from src.leakage_audit import LeakageAuditor


@pytest.fixture(scope="module")
def raw_df():
    loader = DataLoader()
    return loader.load_raw_data(sample_mode="demo")


def test_preprocessing_and_leakage(raw_df):
    pipeline = PreprocessingPipeline()
    split = pipeline.prepare_train_test_split(raw_df, test_size=0.2)

    assert split["X_train"].shape[0] > 0
    assert split["X_test"].shape[0] > 0
    assert split["X_train"].shape[1] == split["X_test"].shape[1]
    assert len(split["classes"]) == 15

    # Run leakage audit
    auditor = LeakageAuditor()
    audit = auditor.audit_split_and_pipeline(
        split["X_train_df"],
        split["X_test_df"],
        split["feature_names"]
    )

    assert audit["overall_verdict"]["status"] == "PASS", f"Leakage audit failed: {audit['overall_verdict']}"
    assert audit["target_contamination"]["status"] == "PASS"
    assert audit["scaler_leakage"]["status"] == "PASS"


def test_single_record_transformation(raw_df):
    pipeline = PreprocessingPipeline()
    _ = pipeline.prepare_train_test_split(raw_df, test_size=0.2)
    sample_record = raw_df.iloc[0].to_dict()
    transformed = pipeline.transform_single_record(sample_record)

    assert transformed.shape == (1, len(pipeline.feature_names))
    assert not np.isnan(transformed).any()
