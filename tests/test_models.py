"""
Unit tests for classical ML models and the proposed Deep Hybrid IDS model.
"""

import pytest
import numpy as np
from src.data_loader import DataLoader
from src.preprocessing import PreprocessingPipeline
from src.feature_selection import FeatureSelector
from src.models import ModelBenchmarkSuite
from src.deep_models import DeepLearningTrainer


@pytest.fixture(scope="module")
def prepared_data():
    loader = DataLoader()
    df = loader.load_raw_data(sample_mode="demo")
    pipeline = PreprocessingPipeline()
    split = pipeline.prepare_train_test_split(df, test_size=0.2)
    selector = FeatureSelector()
    mi = selector.compute_mutual_information(
        split["X_train"], split["y_train_bin"], split["y_train_multi"], split["feature_names"]
    )
    X_train_top, names, _ = selector.select_top_k(split["X_train"], split["feature_names"], mi, top_k=15)
    X_test_top, _, _ = selector.select_top_k(split["X_test"], split["feature_names"], mi, top_k=15)
    return {
        "X_train": X_train_top[:2000],
        "y_train_bin": split["y_train_bin"][:2000],
        "X_test": X_test_top[:500],
        "y_test_bin": split["y_test_bin"][:500],
        "classes": split["classes"]
    }


def test_decision_tree_and_rf(prepared_data):
    suite = ModelBenchmarkSuite()
    dt_res = suite.train_and_eval_binary(
        "decision_tree",
        prepared_data["X_train"], prepared_data["y_train_bin"],
        prepared_data["X_test"], prepared_data["y_test_bin"]
    )
    assert dt_res["metrics"]["accuracy"] >= 0.90
    assert dt_res["metrics"]["f1"] >= 0.90


def test_proposed_hybrid_model(prepared_data):
    trainer = DeepLearningTrainer()
    res = trainer.train_proposed_model(
        prepared_data["X_train"], prepared_data["y_train_bin"],
        None, None,
        prepared_data["X_test"], prepared_data["y_test_bin"],
        is_binary=True, epochs=2, batch_size=64
    )
    assert res["metrics"]["accuracy"] >= 0.85
    assert "training_history" in res["metrics"]
    assert res["metrics"]["parameters"] > 0
