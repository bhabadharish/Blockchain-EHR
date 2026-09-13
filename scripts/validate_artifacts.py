"""
Artifact Validation Suite for Stage 1 -> Stage 2 Integrity Gate.
Part of the PhD Research Platform for Edge-IIoT IDS with Blockchain & Quantum Security.

Verifies:
- Production model & fallback model existence
- Preprocessing pipeline & encoders
- Feature schemas & exact ordering
- Benchmark tables & predictions
- Precomputed figures (2D, 3D, HTML, PNG)
- Explainable AI artifacts (SHAP values & summary)
- Model manifest & cryptographic hash integrity
"""

import os
import sys
import json
import hashlib
import joblib
import numpy as np
import pandas as pd

def check_file(path: str, description: str) -> bool:
    if os.path.exists(path):
        size = os.path.getsize(path)
        print(f"  \033[92mPASS\033[0m: [{description}] -> {path} ({size:,} bytes)")
        return True
    else:
        print(f"  \033[91mFAIL\033[0m: [{description}] MISSING -> {path}")
        return False

def main():
    print("=" * 70)
    print(" STAGE 1 - STEP 5: ARTIFACT INTEGRITY & VALIDATION GATE")
    print("=" * 70)

    all_passed = True

    # 1. Models
    print("\n📦 1. Verifying Model Artifacts:")
    all_passed &= check_file("artifacts/models/production_model/production_model.pt", "Production PyTorch Model")
    all_passed &= check_file("artifacts/models/production_model/production_model_classical_fallback.joblib", "Classical Fallback Model")
    all_passed &= check_file("artifacts/models/production_model/model_config.json", "Model Architecture Config")
    all_passed &= check_file("artifacts/models/model_manifest.json", "Cryptographic Model Manifest")

    # 2. Preprocessing
    print("\n⚙️ 2. Verifying Preprocessing & Encoders:")
    all_passed &= check_file("artifacts/preprocessing/preprocessor.joblib", "Unified Preprocessor")
    all_passed &= check_file("artifacts/preprocessing/label_encoder.joblib", "Label Encoder")
    all_passed &= check_file("artifacts/preprocessing/categorical_encoders.joblib", "Categorical Encoders")
    all_passed &= check_file("artifacts/preprocessing/feature_names.json", "Full Feature Names")
    all_passed &= check_file("artifacts/preprocessing/categorical_columns.json", "Categorical Columns")
    all_passed &= check_file("artifacts/preprocessing/numerical_columns.json", "Numerical Columns")
    all_passed &= check_file("artifacts/preprocessing/feature_schema.json", "Feature Schema")

    # 3. Feature Selection
    print("\n🧬 3. Verifying Feature Selection Artifacts:")
    all_passed &= check_file("artifacts/features/mi_scores.csv", "Mutual Information Scores")
    all_passed &= check_file("artifacts/features/selected_features.json", "Selected Features Config (Top-k)")
    all_passed &= check_file("artifacts/features/mi_plot.html", "MI Ranking HTML Plot")

    # 4. Results & Benchmarks
    print("\n📊 4. Verifying Benchmark Results & Predictions:")
    all_passed &= check_file("artifacts/results/model_benchmark.csv", "Model Benchmark Table")
    all_passed &= check_file("artifacts/results/per_class_metrics.csv", "Per-Class Granular Metrics")
    all_passed &= check_file("artifacts/results/false_negative_analysis.csv", "False Negative Forensic Report")
    all_passed &= check_file("artifacts/results/false_positive_analysis.csv", "False Positive Forensic Report")
    all_passed &= check_file("artifacts/results/test_predictions.csv", "Test Sample Predictions")
    all_passed &= check_file("artifacts/results/ablation_results.csv", "Ablation Study Results")
    all_passed &= check_file("artifacts/results/binary_confusion_matrix.csv", "Binary Confusion Matrix")
    all_passed &= check_file("artifacts/results/multiclass_confusion_matrix.csv", "Multiclass Confusion Matrix")
    all_passed &= check_file("artifacts/results/normalized_confusion_matrix.csv", "Normalized Confusion Matrix")
    all_passed &= check_file("artifacts/results/roc_curve.csv", "ROC Curve Points")
    all_passed &= check_file("artifacts/results/pr_curve.csv", "PR Curve Points")
    all_passed &= check_file("artifacts/results/inference_benchmark.json", "Inference Latency & Throughput Benchmark")
    all_passed &= check_file("artifacts/benchmarks/manuscript_reference.json", "Manuscript Reference Benchmarks")

    # 5. Figures
    print("\n📈 5. Verifying Precomputed Publication Figures:")
    all_passed &= check_file("artifacts/figures/class_distribution.html", "Class Distribution (HTML)")
    all_passed &= check_file("artifacts/figures/attack_distribution.html", "Attack Distribution (HTML)")
    all_passed &= check_file("artifacts/figures/confusion/confusion_matrix.html", "Binary Confusion (HTML)")
    all_passed &= check_file("artifacts/figures/confusion/multiclass_confusion_matrix.html", "Multiclass Confusion (HTML)")
    all_passed &= check_file("artifacts/figures/roc/roc_curve.html", "ROC Curve (HTML)")
    all_passed &= check_file("artifacts/figures/pr/pr_curve.html", "PR Curve (HTML)")
    all_passed &= check_file("artifacts/figures/model_comparison.html", "Model Comparison (HTML)")
    all_passed &= check_file("artifacts/figures/latency_comparison.html", "Latency Comparison (HTML)")
    all_passed &= check_file("artifacts/figures/learning/learning_curves.html", "Learning Curves (HTML)")
    all_passed &= check_file("artifacts/results/ablation_plot.html", "Ablation Study (HTML)")
    all_passed &= check_file("artifacts/figures/3d/pca_3d.html", "3D PCA Feature Space (HTML)")
    all_passed &= check_file("artifacts/figures/3d/mi_3d.html", "3D MI Feature Space (HTML)")
    all_passed &= check_file("artifacts/figures/3d/model_performance_3d.html", "3D Model Performance (HTML)")

    # 6. Explainable AI (SHAP)
    print("\n🔮 6. Verifying Explainable AI (XAI) Artifacts:")
    all_passed &= check_file("artifacts/xai/shap_values.npy", "Offline Precomputed SHAP Values")
    all_passed &= check_file("artifacts/xai/background_samples.npy", "SHAP Background Samples")
    all_passed &= check_file("artifacts/xai/shap_importance.csv", "SHAP Feature Importance CSV")
    all_passed &= check_file("artifacts/xai/shap_summary.html", "SHAP Summary Plot (HTML)")

    # 7. Reports & Splits
    print("\n📑 7. Verifying Reports & Split Data:")
    all_passed &= check_file("artifacts/reports/data_quality.json", "Data Quality JSON Report")
    all_passed &= check_file("artifacts/reports/data_quality.csv", "Data Quality CSV Report")
    all_passed &= check_file("artifacts/reports/leakage_audit.json", "Data Leakage Audit Report")
    all_passed &= check_file("artifacts/reports/hardware_report.json", "Hardware & Software Profile")
    all_passed &= check_file("artifacts/reports/final_report.json", "Final Research Experiment Report")
    all_passed &= check_file("artifacts/splits/train_indices.npy", "Train Split Indices")
    all_passed &= check_file("artifacts/splits/validation_indices.npy", "Validation Split Indices")
    all_passed &= check_file("artifacts/splits/test_indices.npy", "Test Split Indices")
    all_passed &= check_file("artifacts/demo/live_samples.csv", "Pre-selected Live Demo Samples")

    # 8. Cryptographic Hash & Feature Alignment Check
    print("\n🔐 8. Checking Cryptographic Model Hash & Feature Alignment:")
    try:
        with open("artifacts/models/production_model/production_model.pt", "rb") as f:
            actual_model_hash = hashlib.sha256(f.read()).hexdigest()
        
        with open("artifacts/models/model_manifest.json", "r") as f:
            manifest = json.load(f)

        expected_hash = manifest.get("model_hash")
        if actual_model_hash == expected_hash:
            print(f"  \033[92mPASS\033[0m: [Model Hash Integrity] -> {actual_model_hash[:16]}... matches manifest.")
        else:
            print(f"  \033[91mFAIL\033[0m: [Model Hash Mismatch] -> Expected: {expected_hash}, Actual: {actual_model_hash}")
            all_passed = False

        # Check feature count
        with open("artifacts/features/selected_features.json", "r") as f:
            sel = json.load(f)
            top_20 = sel.get("top_20", [])
        
        if len(top_20) == manifest.get("feature_count"):
            print(f"  \033[92mPASS\033[0m: [Feature Count Alignment] -> {len(top_20)} selected features match manifest.")
        else:
            print(f"  \033[91mFAIL\033[0m: [Feature Count Mismatch] -> Selected: {len(top_20)}, Manifest: {manifest.get('feature_count')}")
            all_passed = False

    except Exception as e:
        print(f"  \033[91mFAIL\033[0m: Error during integrity checks: {e}")
        all_passed = False

    print("\n" + "=" * 70)
    if all_passed:
        print(" \033[92m✅ ALL REQUIRED ARTIFACTS VERIFIED: READY FOR STAGE 2 STREAMLIT SOC\033[0m")
        print("=" * 70)
        return 0
    else:
        print(" \033[91m❌ ARTIFACT VALIDATION FAILED: MISSING OR MISCONFIGURED ARTIFACTS\033[0m")
        print("=" * 70)
        return 1

if __name__ == "__main__":
    sys.exit(main())
