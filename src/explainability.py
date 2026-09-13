"""
Explainable AI (XAI) Engine for Edge-IIoT Telemetry Intrusion Detection.
Part of the PhD Research Platform for Edge-IIoT IDS with Blockchain & Quantum Security.
Provides global feature attributions, local perturbation explanations, and SHAP-aligned scoring.
"""

import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


class ExplainabilityEngine:
    """
    Computes global and local feature explanations for intrusion detection models.
    Supports Tree feature importances, local sample attributions, and SHAP.
    """

    def __init__(self, model: Any, feature_names: List[str]):
        self.model = model
        self.feature_names = feature_names
        self.shap_explainer = None

        if SHAP_AVAILABLE and hasattr(model, "predict_proba"):
            try:
                # Fast TreeExplainer for decision trees, RF, XGBoost
                self.shap_explainer = shap.TreeExplainer(model)
            except Exception:
                self.shap_explainer = None

    def get_global_importance(self, top_n: int = 15) -> List[Dict[str, Any]]:
        """
        Returns top_n global feature importances derived from model weights or tree splits.
        """
        importances = None
        if hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_
        elif hasattr(self.model, "coef_"):
            importances = np.abs(self.model.coef_).flatten()
            if len(importances) > len(self.feature_names):
                importances = np.mean(np.abs(self.model.coef_), axis=0)

        if importances is None or len(importances) != len(self.feature_names):
            importances = np.ones(len(self.feature_names)) / len(self.feature_names)

        # Normalize to 100%
        total = np.sum(importances) or 1.0
        norm_imp = (importances / total) * 100.0

        records = []
        for i, name in enumerate(self.feature_names):
            records.append({
                "feature": name,
                "importance_score": round(float(norm_imp[i]), 2),
                "raw_importance": float(importances[i])
            })

        records.sort(key=lambda x: -x["importance_score"])
        for rank, r in enumerate(records, start=1):
            r["rank"] = rank

        return records[:top_n]

    def explain_local_sample(
        self,
        sample_vector: np.ndarray,
        baseline_vector: Optional[np.ndarray] = None,
        top_n: int = 6
    ) -> Dict[str, Any]:
        """
        Computes local feature contribution to an individual prediction (sample_vector).
        Identifies top positive (pushing toward Attack) and negative (pushing toward Normal) features.
        """
        vec = sample_vector.flatten()
        
        # If SHAP is available, use SHAP values
        if self.shap_explainer is not None:
            try:
                shap_values = self.shap_explainer.shap_values(vec.reshape(1, -1))
                # For binary classification with probability of Attack:
                if isinstance(shap_values, list) and len(shap_values) > 1:
                    vals = shap_values[1][0]
                elif isinstance(shap_values, np.ndarray) and len(shap_values.shape) > 2:
                    vals = shap_values[0, :, 1]
                else:
                    vals = np.array(shap_values).flatten()

                contributions = []
                for i, name in enumerate(self.feature_names):
                    contributions.append({
                        "feature": name,
                        "value": round(float(vec[i]), 3),
                        "contribution": round(float(vals[i]), 4),
                        "direction": "Pushes to ATTACK" if vals[i] > 0 else "Pushes to NORMAL"
                    })
                contributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)
                return {
                    "method": "SHAP TreeExplainer",
                    "top_contributions": contributions[:top_n],
                    "all_contributions": contributions
                }
            except Exception:
                pass

        # Robust perturbation-based attribution fallback
        # Evaluates sensitivity of prediction to masking individual features
        base = baseline_vector.flatten() if baseline_vector is not None else np.zeros_like(vec)
        
        if hasattr(self.model, "predict_proba"):
            p_full = self.model.predict_proba(vec.reshape(1, -1))[0, 1]
        else:
            p_full = float(self.model.predict(vec.reshape(1, -1))[0])

        contributions = []
        for i, name in enumerate(self.feature_names):
            # Perturb single feature toward baseline
            perturbed = vec.copy()
            perturbed[i] = base[i]
            if hasattr(self.model, "predict_proba"):
                p_pert = self.model.predict_proba(perturbed.reshape(1, -1))[0, 1]
            else:
                p_pert = float(self.model.predict(perturbed.reshape(1, -1))[0])
            
            delta = float(p_full - p_pert)
            contributions.append({
                "feature": name,
                "value": round(float(vec[i]), 3),
                "contribution": round(delta, 4),
                "direction": "Pushes to ATTACK" if delta > 0 else "Pushes to NORMAL"
            })

        contributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)
        return {
            "method": "Sensitivity Perturbation Attribution",
            "top_contributions": contributions[:top_n],
            "all_contributions": contributions
        }
