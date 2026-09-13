"""
Classical Machine Learning Benchmark Suite for Edge-IIoT Telemetry.
Part of the PhD Research Platform for Edge-IIoT IDS with Blockchain & Quantum Security.
Supports Binary & Multiclass models: Logistic Regression, Decision Tree, Random Forest,
Extra Trees, XGBoost, MLP Classifier.
"""

import time
import joblib
import os
import numpy as np
from typing import Dict, Any, List, Optional
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.neural_network import MLPClassifier
import xgboost as xgb
from src.evaluation import evaluate_binary, evaluate_multiclass
from src.utils import load_config, set_seed


class ModelBenchmarkSuite:
    """
    Manages training, evaluation, and serialization of classical ML models.
    """

    def __init__(self, config_path: str = "config.yaml"):
        self.config = load_config(config_path)
        self.seed = self.config["system"]["random_seed"]
        self.checkpoint_dir = self.config["models"]["checkpoint_dir"]
        os.makedirs(self.checkpoint_dir, exist_ok=True)

    def get_binary_model(self, model_name: str):
        """Instantiates deterministic scikit-learn or XGBoost binary classifier."""
        name = model_name.lower().replace(" ", "_")
        set_seed(self.seed)

        if name == "logistic_regression":
            return LogisticRegression(max_iter=300, random_state=self.seed)
        elif name == "decision_tree":
            return DecisionTreeClassifier(max_depth=15, random_state=self.seed)
        elif name == "random_forest":
            return RandomForestClassifier(n_estimators=100, max_depth=16, n_jobs=4, random_state=self.seed)
        elif name == "extra_trees":
            return ExtraTreesClassifier(n_estimators=100, max_depth=16, n_jobs=4, random_state=self.seed)
        elif name in ["xgboost", "gradient_boosting", "lightgbm"]:
            from sklearn.ensemble import HistGradientBoostingClassifier
            return HistGradientBoostingClassifier(max_iter=80, random_state=self.seed)
        elif name in ["mlp", "dnn"]:
            return MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=150, random_state=self.seed)
        elif name == "svm":
            from sklearn.svm import LinearSVC
            return LinearSVC(random_state=self.seed, max_iter=500)
        else:
            raise ValueError(f"Unsupported binary model: {model_name}")

    def get_multiclass_model(self, model_name: str):
        """Instantiates deterministic scikit-learn or XGBoost multiclass classifier."""
        name = model_name.lower().replace(" ", "_")
        set_seed(self.seed)

        if name == "decision_tree":
            return DecisionTreeClassifier(max_depth=16, random_state=self.seed)
        elif name == "random_forest":
            return RandomForestClassifier(n_estimators=100, max_depth=16, n_jobs=4, random_state=self.seed)
        elif name == "extra_trees":
            return ExtraTreesClassifier(n_estimators=100, max_depth=16, n_jobs=4, random_state=self.seed)
        elif name in ["xgboost", "gradient_boosting", "lightgbm"]:
            from sklearn.ensemble import HistGradientBoostingClassifier
            return HistGradientBoostingClassifier(max_iter=60, random_state=self.seed)
        elif name in ["mlp", "dnn"]:
            return MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=150, random_state=self.seed)
        else:
            raise ValueError(f"Unsupported multiclass model: {model_name}")

    def train_and_eval_binary(
        self,
        model_name: str,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray
    ) -> Dict[str, Any]:
        """Trains a binary classifier, records timing, and computes metrics."""
        model = self.get_binary_model(model_name)
        
        t0 = time.time()
        model.fit(X_train, y_train)
        train_time = time.time() - t0

        t1 = time.time()
        y_pred = model.predict(X_test)
        infer_time = time.time() - t1

        y_prob = None
        if hasattr(model, "predict_proba"):
            try:
                y_prob = model.predict_proba(X_test)
            except Exception:
                pass

        metrics = evaluate_binary(
            y_test, y_pred, y_prob=y_prob,
            inference_time_sec=infer_time, train_time_sec=train_time
        )
        metrics["model_name"] = model_name
        metrics["task"] = "binary"

        # Save model checkpoint
        save_path = os.path.join(self.checkpoint_dir, f"{model_name.lower().replace(' ', '_')}_binary.joblib")
        joblib.dump(model, save_path)
        metrics["saved_path"] = save_path
        metrics["model_size_kb"] = round(os.path.getsize(save_path) / 1024, 2)

        return {"metrics": metrics, "model": model}

    def train_and_eval_multiclass(
        self,
        model_name: str,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        classes: List[str]
    ) -> Dict[str, Any]:
        """Trains a multiclass classifier across all 15 classes, records timing, and computes metrics."""
        model = self.get_multiclass_model(model_name)

        t0 = time.time()
        model.fit(X_train, y_train)
        train_time = time.time() - t0

        t1 = time.time()
        y_pred = model.predict(X_test)
        infer_time = time.time() - t1

        y_prob = None
        if hasattr(model, "predict_proba"):
            try:
                y_prob = model.predict_proba(X_test)
            except Exception:
                pass

        metrics = evaluate_multiclass(
            y_test, y_pred, classes=classes, y_prob=y_prob,
            inference_time_sec=infer_time, train_time_sec=train_time
        )
        metrics["model_name"] = model_name
        metrics["task"] = "multiclass"

        save_path = os.path.join(self.checkpoint_dir, f"{model_name.lower().replace(' ', '_')}_multiclass.joblib")
        joblib.dump(model, save_path)
        metrics["saved_path"] = save_path
        metrics["model_size_kb"] = round(os.path.getsize(save_path) / 1024, 2)

        return {"metrics": metrics, "model": model}
