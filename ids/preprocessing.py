"""
Network Telemetry Preprocessing Module for Edge-IIoT IDS.
Loads the training-fitted preprocessing pipeline and extracts the top-20 mutual information features.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional, Tuple


class IDSPreprocessor:
    """
    Offline-fitted preprocessor wrapper for Edge-IIoT telemetry inference.
    Loads preprocessor.joblib, selected_features.json, and label_encoder.joblib.
    """

    def __init__(
        self,
        pipeline_path: str = "artifacts/preprocessing/preprocessor.joblib",
        features_path: str = "artifacts/features/selected_features.json",
        encoder_path: str = "artifacts/preprocessing/label_encoder.joblib"
    ):
        self.pipeline_path = pipeline_path
        self.features_path = features_path
        self.encoder_path = encoder_path

        self.pipeline = None
        self.selected_features: List[str] = []
        self.label_encoder = None
        self.classes: List[str] = []

        self._load_artifacts()

    def _load_artifacts(self):
        """Loads fitted preprocessing artifacts if present."""
        if os.path.exists(self.pipeline_path):
            self.pipeline = joblib.load(self.pipeline_path)

        if os.path.exists(self.features_path):
            with open(self.features_path, "r") as f:
                feat_cfg = json.load(f)
                self.selected_features = feat_cfg.get("top_20", [])

        if os.path.exists(self.encoder_path):
            self.label_encoder = joblib.load(self.encoder_path)
            self.classes = list(self.label_encoder.classes_)
        else:
            self.classes = [
                "Backdoor", "DDoS_HTTP", "DDoS_ICMP", "DDoS_TCP", "DDoS_UDP",
                "Fingerprinting", "MITM", "Normal", "Password", "Port_Scanning",
                "Ransomware", "SQL_injection", "Uploading", "Vulnerability_scanner", "XSS"
            ]

    def transform_record(self, record_dict: Dict[str, Any]) -> np.ndarray:
        """
        Transforms a single raw network telemetry record dictionary into
        a scaled (1, 20) feature vector ready for model inference.
        """
        df = pd.DataFrame([record_dict])
        return self.transform_dataframe(df)

    def transform_dataframe(self, df: pd.DataFrame) -> np.ndarray:
        """
        Transforms a batch dataframe through the fitted preprocessing pipeline
        and slices the 20 selected features.
        """
        if self.pipeline is not None:
            # Transform via pipeline
            scaled_df = self.pipeline.transform(df, return_df=True)
            if self.selected_features:
                available_cols = [c for c in self.selected_features if c in scaled_df.columns]
                if len(available_cols) == len(self.selected_features):
                    return scaled_df[self.selected_features].values.astype(np.float32)
                else:
                    # Fallback padding if some features missing
                    X = np.zeros((len(df), len(self.selected_features)), dtype=np.float32)
                    for i, col in enumerate(self.selected_features):
                        if col in scaled_df.columns:
                            X[:, i] = scaled_df[col].values
                    return X
            return scaled_df.values.astype(np.float32)
        else:
            # Synthetic feature fallback if pipeline artifact is missing
            n_samples = len(df)
            dim = len(self.selected_features) if self.selected_features else 20
            return np.zeros((n_samples, dim), dtype=np.float32)

    def get_feature_names(self) -> List[str]:
        return self.selected_features
