"""
Mutual Information Feature Selection & Ranking Engine.
Part of the PhD Research Platform for Edge-IIoT IDS with Blockchain & Quantum Security.
Computes MI(X_i, Y_binary) and MI(X_i, Y_multiclass) strictly on training data,
providing top-k selection, cumulative importance curves, and persistent caching.
"""

import os
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple
from sklearn.feature_selection import mutual_info_classif
from src.utils import load_config, set_seed


class FeatureSelector:
    """
    Mutual Information (MI) feature selection engine for Edge-IIoT telemetry.
    Computes entropy-based dependency measures strictly on training splits.
    """

    def __init__(self, config_path: str = "config.yaml"):
        self.config = load_config(config_path)
        self.seed = self.config["system"]["random_seed"]
        self.cache_file = self.config["feature_selection"]["cache_file"]
        self.default_top_k = self.config["feature_selection"]["default_top_k"]

    def compute_mutual_information(
        self,
        X_train: np.ndarray,
        y_train_bin: np.ndarray,
        y_train_multi: np.ndarray,
        feature_names: List[str],
        force_recompute: bool = False
    ) -> Dict[str, Any]:
        """
        Calculates Mutual Information for both binary and multiclass targets.
        Fitted EXCLUSIVELY on training data.
        Caches result to disk for instant retrieval.
        """
        if os.path.exists(self.cache_file) and not force_recompute:
            try:
                with open(self.cache_file, "r") as f:
                    cached_data = json.load(f)
                    if cached_data.get("feature_names") == feature_names:
                        return cached_data
            except Exception:
                pass

        set_seed(self.seed)

        # Scikit-learn mutual_info_classif
        # Binary target MI
        mi_bin = mutual_info_classif(
            X_train, y_train_bin, discrete_features=False, random_state=self.seed
        )

        # Multiclass target MI
        mi_multi = mutual_info_classif(
            X_train, y_train_multi, discrete_features=False, random_state=self.seed
        )

        # Build feature ranking table
        records = []
        for i, name in enumerate(feature_names):
            records.append({
                "feature": name,
                "mi_binary": float(mi_bin[i]),
                "mi_multiclass": float(mi_multi[i]),
                "composite_mi": float((mi_bin[i] + mi_multi[i]) / 2.0)
            })

        # Sort descending by composite MI
        records.sort(key=lambda x: -x["composite_mi"])
        
        # Calculate ranks and cumulative proportions
        total_mi = sum(r["composite_mi"] for r in records) or 1.0
        cum_sum = 0.0
        for rank, r in enumerate(records, start=1):
            r["rank"] = rank
            cum_sum += r["composite_mi"]
            r["cumulative_pct"] = round((cum_sum / total_mi) * 100, 2)
            r["composite_mi"] = round(r["composite_mi"], 4)
            r["mi_binary"] = round(r["mi_binary"], 4)
            r["mi_multiclass"] = round(r["mi_multiclass"], 4)

        result = {
            "feature_names": feature_names,
            "ranking": records,
            "total_features": len(feature_names),
            "top_features_ranked": [r["feature"] for r in records]
        }

        # Cache to artifacts
        os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
        with open(self.cache_file, "w") as f:
            json.dump(result, f, indent=2)

        return result

    def select_top_k(
        self,
        X: np.ndarray,
        feature_names: List[str],
        ranking_data: Dict[str, Any],
        top_k: Any = 20
    ) -> Tuple[np.ndarray, List[str], List[int]]:
        """
        Filters feature matrix to top_k features based on computed MI ranking.
        top_k can be integer (e.g. 5, 10, 15, 20, 30, 40) or 'all'.
        Returns (X_selected, selected_feature_names, selected_indices).
        """
        all_ranked = ranking_data["top_features_ranked"]
        
        if str(top_k).lower() == "all" or top_k >= len(all_ranked):
            selected_names = all_ranked
        else:
            selected_names = all_ranked[:int(top_k)]

        selected_indices = [feature_names.index(name) for name in selected_names if name in feature_names]
        X_selected = X[:, selected_indices]
        
        return X_selected, selected_names, selected_indices
