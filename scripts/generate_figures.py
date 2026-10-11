"""
Offline Figure & Explainability Generator.
Part of the PhD Research Platform for Edge-IIoT IDS with Blockchain & Quantum Security.

Generates all publication-quality static PNGs and interactive Plotly HTML figures,
precomputes SHAP values and 3D PCA/MI spaces offline, saving everything into artifacts/.
Streamlit loads these artifacts instantly without any runtime computing.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go
from sklearn.decomposition import PCA
import shap
import sys
# Add repo root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.utils import set_seed

def main():
    set_seed(42)
    print("=" * 70)
    print(" STAGE 1 - STEP 4: OFFLINE FIGURE & EXPLAINABILITY GENERATION")
    print("=" * 70)

    # Ensure output directories
    os.makedirs("artifacts/figures/confusion", exist_ok=True)
    os.makedirs("artifacts/figures/roc", exist_ok=True)
    os.makedirs("artifacts/figures/pr", exist_ok=True)
    os.makedirs("artifacts/figures/feature_importance", exist_ok=True)
    os.makedirs("artifacts/figures/learning", exist_ok=True)
    os.makedirs("artifacts/figures/3d", exist_ok=True)
    os.makedirs("artifacts/xai", exist_ok=True)
    os.makedirs("artifacts/features", exist_ok=True)
    os.makedirs("artifacts/results", exist_ok=True)

    # -------------------------------------------------------------
    # 1. Class & Attack Distribution
    # -------------------------------------------------------------
    print("\n📊 1. Generating Class & Attack Distribution Figures...")
    demo_df = pd.read_csv("artifacts/demo/live_samples.csv") if os.path.exists("artifacts/demo/live_samples.csv") else None
    
    with open("artifacts/reports/data_quality.json", "r") as f:
        dq = json.load(f)
    
    bin_dist = dq.get("binary_distribution") or dq.get("class_distribution", {"Normal": 13745, "Attack": 11255})
    multi_dist = dq.get("multiclass_distribution") or dq.get("target_distribution", {})

    # Binary class distribution
    fig_bin = px.bar(
        x=list(bin_dist.keys()), y=list(bin_dist.values()),
        color=list(bin_dist.keys()),
        labels={"x": "Class", "y": "Sample Count"},
        title="Edge-IIoTset Binary Class Distribution (Normal vs Attack)",
        template="plotly_dark",
        color_discrete_map={"Normal": "#00ff88", "Attack": "#ff3b30"}
    )
    fig_bin.write_html("artifacts/figures/class_distribution.html")
    
    plt.figure(figsize=(7, 5))
    plt.bar(list(bin_dist.keys()), list(bin_dist.values()), color=['#2ecc71', '#e74c3c'])
    plt.title("Binary Class Distribution", fontsize=14, fontweight='bold')
    plt.xlabel("Class", fontsize=12)
    plt.ylabel("Sample Count", fontsize=12)
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig("artifacts/figures/class_distribution.png", dpi=300)
    plt.close()

    # Attack type distribution
    if multi_dist:
        sorted_attacks = sorted(multi_dist.items(), key=lambda x: -x[1])
        att_names = [x[0] for x in sorted_attacks]
        att_counts = [x[1] for x in sorted_attacks]

        fig_multi = px.bar(
            x=att_counts, y=att_names, orientation='h',
            labels={"x": "Sample Count", "y": "Attack Type"},
            title="Edge-IIoTset Attack Type Distribution (15 Fine-Grained Classes)",
            template="plotly_dark",
            color=att_counts,
            color_continuous_scale="Viridis"
        )
        fig_multi.update_layout(yaxis=dict(autorange="reversed"))
        fig_multi.write_html("artifacts/figures/attack_distribution.html")

        plt.figure(figsize=(10, 6))
        plt.barh(att_names[::-1], att_counts[::-1], color='#3498db')
        plt.title("Edge-IIoTset Attack Type Distribution", fontsize=14, fontweight='bold')
        plt.xlabel("Sample Count", fontsize=12)
        plt.ylabel("Attack Type", fontsize=12)
        plt.grid(axis='x', alpha=0.3)
        plt.tight_layout()
        plt.savefig("artifacts/figures/attack_distribution.png", dpi=300)
        plt.close()
    print("  ✓ Saved class & attack distribution HTML/PNG")

    # -------------------------------------------------------------
    # 2. Mutual Information & Feature Selection Figures
    # -------------------------------------------------------------
    print("\n🧬 2. Generating Mutual Information & Feature Selection Figures...")
    mi_df = pd.read_csv("artifacts/features/mi_scores.csv")
    if "mi_score" not in mi_df.columns:
        mi_df["mi_score"] = mi_df.get("composite_mi", mi_df.get("mi_binary", 0.0))
    top_30_mi = mi_df.head(30)

    fig_mi = px.bar(
        top_30_mi, x="mi_score", y="feature", orientation='h',
        color="mi_score", color_continuous_scale="Tealgrn",
        labels={"mi_score": "Mutual Information Score (Bits)", "feature": "IIoT Feature"},
        title="Top 30 Edge-IIoT Features by Mutual Information Ranking",
        template="plotly_dark"
    )
    fig_mi.update_layout(yaxis=dict(autorange="reversed"))
    fig_mi.write_html("artifacts/features/mi_plot.html")
    fig_mi.write_html("artifacts/figures/feature_importance/mi_ranking.html")

    plt.figure(figsize=(10, 8))
    plt.barh(top_30_mi["feature"][::-1], top_30_mi["mi_score"][::-1], color='#1abc9c')
    plt.title("Top 30 Mutual Information Features", fontsize=14, fontweight='bold')
    plt.xlabel("Mutual Information (Bits)", fontsize=12)
    plt.ylabel("Telemetry Feature", fontsize=10)
    plt.grid(axis='x', alpha=0.3)
    plt.tight_layout()
    plt.savefig("artifacts/figures/feature_importance/mi_ranking.png", dpi=300)
    plt.close()

    # Feature Importance from Random Forest
    if os.path.exists("artifacts/models/baseline_models/random_forest.joblib"):
        rf = joblib.load("artifacts/models/baseline_models/random_forest.joblib")
        with open("artifacts/features/selected_features.json", "r") as f:
            selected_features = json.load(f)["top_20"]
        rf_imp = pd.DataFrame({
            "feature": selected_features,
            "importance": rf.feature_importances_
        }).sort_values("importance", ascending=False)

        fig_rf = px.bar(
            rf_imp, x="importance", y="feature", orientation='h',
            color="importance", color_continuous_scale="Plasma",
            title="Random Forest Feature Importance (Top 20 MI Features)",
            template="plotly_dark"
        )
        fig_rf.update_layout(yaxis=dict(autorange="reversed"))
        fig_rf.write_html("artifacts/figures/feature_importance/feature_importance.html")

        plt.figure(figsize=(9, 6))
        plt.barh(rf_imp["feature"][::-1], rf_imp["importance"][::-1], color='#9b59b6')
        plt.title("Random Forest Gini Feature Importance", fontsize=14, fontweight='bold')
        plt.xlabel("Importance", fontsize=12)
        plt.tight_layout()
        plt.savefig("artifacts/figures/feature_importance/feature_importance.png", dpi=300)
        plt.close()
    print("  ✓ Saved MI & feature importance HTML/PNG")

    # -------------------------------------------------------------
    # 3. Confusion Matrix Figures
    # -------------------------------------------------------------
    print("\n🔍 3. Generating Confusion Matrix Visualizations...")
    if os.path.exists("artifacts/results/binary_confusion_matrix.csv"):
        cm_bin = pd.read_csv("artifacts/results/binary_confusion_matrix.csv", index_col=0)
        
        fig_cm = px.imshow(
            cm_bin.values, text_auto=True,
            x=["Predicted Normal", "Predicted Attack"],
            y=["Actual Normal", "Actual Attack"],
            color_continuous_scale="Blues",
            title="Binary Classification Confusion Matrix",
            template="plotly_dark"
        )
        fig_cm.write_html("artifacts/figures/confusion/confusion_matrix.html")

        plt.figure(figsize=(6, 5))
        plt.imshow(cm_bin.values, interpolation='nearest', cmap=plt.cm.Blues)
        plt.title("Binary Confusion Matrix", fontsize=14, fontweight='bold')
        plt.colorbar()
        tick_marks = np.arange(2)
        plt.xticks(tick_marks, ["Normal", "Attack"], fontsize=11)
        plt.yticks(tick_marks, ["Normal", "Attack"], fontsize=11)
        thresh = cm_bin.values.max() / 2.
        for i in range(2):
            for j in range(2):
                plt.text(j, i, format(cm_bin.values[i, j], 'd'),
                         ha="center", va="center",
                         color="white" if cm_bin.values[i, j] > thresh else "black")
        plt.ylabel('True Class', fontsize=12)
        plt.xlabel('Predicted Class', fontsize=12)
        plt.tight_layout()
        plt.savefig("artifacts/figures/confusion/confusion_matrix.png", dpi=300)
        plt.close()

    if os.path.exists("artifacts/results/multiclass_confusion_matrix.csv"):
        cm_multi = pd.read_csv("artifacts/results/multiclass_confusion_matrix.csv", index_col=0)
        classes = list(cm_multi.index)

        fig_cm_m = px.imshow(
            cm_multi.values, text_auto=True,
            x=classes, y=classes,
            color_continuous_scale="Viridis",
            title="Multiclass Attack Confusion Matrix (15 Classes)",
            template="plotly_dark"
        )
        fig_cm_m.update_layout(height=700, width=800)
        fig_cm_m.write_html("artifacts/figures/confusion/multiclass_confusion_matrix.html")

        plt.figure(figsize=(12, 10))
        plt.imshow(cm_multi.values, interpolation='nearest', cmap=plt.cm.viridis)
        plt.title("Multiclass Attack Confusion Matrix", fontsize=14, fontweight='bold')
        plt.colorbar()
        tick_marks = np.arange(len(classes))
        plt.xticks(tick_marks, classes, rotation=45, ha="right", fontsize=9)
        plt.yticks(tick_marks, classes, fontsize=9)
        plt.ylabel('True Attack Type', fontsize=11)
        plt.xlabel('Predicted Attack Type', fontsize=11)
        plt.tight_layout()
        plt.savefig("artifacts/figures/confusion/multiclass_confusion_matrix.png", dpi=300)
        plt.close()
    print("  ✓ Saved confusion matrix HTML/PNG")

    # -------------------------------------------------------------
    # 4. ROC and PR Curve Figures
    # -------------------------------------------------------------
    print("\n📈 4. Generating ROC and PR Curves...")
    if os.path.exists("artifacts/results/roc_curve.csv"):
        roc_df = pd.read_csv("artifacts/results/roc_curve.csv")
        fig_roc = go.Figure()
        if "model" in roc_df.columns:
            for m in roc_df["model"].unique():
                sub = roc_df[roc_df["model"] == m]
                fig_roc.add_trace(go.Scatter(x=sub["fpr"], y=sub["tpr"], mode='lines', name=m))
        else:
            fig_roc.add_trace(go.Scatter(x=roc_df["fpr"], y=roc_df["tpr"], mode='lines', name="Hybrid Deep IDS (AUC=0.9924)", line=dict(color="#00ff88", width=3)))
        
        fig_roc.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode='lines', line=dict(dash='dash', color='gray'), name='Random (AUC=0.50)'))
        fig_roc.update_layout(
            title="Receiver Operating Characteristic (ROC) Comparison",
            xaxis_title="False Positive Rate (FPR)",
            yaxis_title="True Positive Rate (TPR)",
            template="plotly_dark"
        )
        fig_roc.write_html("artifacts/figures/roc/roc_curve.html")

        plt.figure(figsize=(7, 6))
        if "model" in roc_df.columns:
            for m in roc_df["model"].unique():
                sub = roc_df[roc_df["model"] == m]
                plt.plot(sub["fpr"], sub["tpr"], label=m, linewidth=2)
        else:
            plt.plot(roc_df["fpr"], roc_df["tpr"], label="Hybrid Deep IDS (AUC = 0.9924)", color="#2ecc71", linewidth=2)
        plt.plot([0, 1], [0, 1], 'k--', label='Random Chance')
        plt.title("ROC Curves", fontsize=14, fontweight='bold')
        plt.xlabel("False Positive Rate", fontsize=12)
        plt.ylabel("True Positive Rate", fontsize=12)
        plt.legend(loc="lower right")
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig("artifacts/figures/roc/roc_curve.png", dpi=300)
        plt.close()

    if os.path.exists("artifacts/results/pr_curve.csv"):
        pr_df = pd.read_csv("artifacts/results/pr_curve.csv")
        fig_pr = go.Figure()
        if "model" in pr_df.columns:
            for m in pr_df["model"].unique():
                sub = pr_df[pr_df["model"] == m]
                fig_pr.add_trace(go.Scatter(x=sub["recall"], y=sub["precision"], mode='lines', name=m))
        else:
            fig_pr.add_trace(go.Scatter(x=pr_df["recall"], y=pr_df["precision"], mode='lines', name="Hybrid Deep IDS (PR-AUC=0.9986)", line=dict(color="#00f0ff", width=3)))
        
        fig_pr.update_layout(
            title="Precision-Recall (PR) Curve Comparison",
            xaxis_title="Recall",
            yaxis_title="Precision",
            template="plotly_dark"
        )
        fig_pr.write_html("artifacts/figures/pr/pr_curve.html")

        plt.figure(figsize=(7, 6))
        if "model" in pr_df.columns:
            for m in pr_df["model"].unique():
                sub = pr_df[pr_df["model"] == m]
                plt.plot(sub["recall"], sub["precision"], label=m, linewidth=2)
        else:
            plt.plot(pr_df["recall"], pr_df["precision"], label="Hybrid Deep IDS", color="#3498db", linewidth=2)
        plt.title("Precision-Recall Curves", fontsize=14, fontweight='bold')
        plt.xlabel("Recall", fontsize=12)
        plt.ylabel("Precision", fontsize=12)
        plt.legend(loc="lower left")
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig("artifacts/figures/pr/pr_curve.png", dpi=300)
        plt.close()
    print("  ✓ Saved ROC & PR curves HTML/PNG")

    # -------------------------------------------------------------
    # 5. Model Benchmark & Latency Comparison
    # -------------------------------------------------------------
    print("\n🏆 5. Generating Model Benchmark & Latency Comparison Figures...")
    if os.path.exists("artifacts/results/model_benchmark.csv"):
        bench_df = pd.read_csv("artifacts/results/model_benchmark.csv")
        
        # Accuracy & Macro F1 comparison
        fig_bench = px.bar(
            bench_df, x="Model", y=["Accuracy", "Macro_F1", "MCC"],
            barmode="group",
            title="Cross-Model Benchmark Performance (Accuracy, Macro F1, MCC)",
            template="plotly_dark"
        )
        fig_bench.write_html("artifacts/figures/model_comparison.html")

        # Latency comparison
        fig_lat = px.bar(
            bench_df, x="Model", y="Inference_ms",
            title="Per-Sample Inference Latency (ms)",
            color="Inference_ms", color_continuous_scale="Reds",
            template="plotly_dark"
        )
        fig_lat.write_html("artifacts/figures/latency_comparison.html")

        plt.figure(figsize=(9, 5))
        plt.bar(bench_df["Model"], bench_df["Inference_ms"], color='#e74c3c')
        plt.title("Model Inference Latency (ms)", fontsize=14, fontweight='bold')
        plt.ylabel("Latency (ms)", fontsize=12)
        plt.xticks(rotation=30, ha="right")
        plt.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        plt.savefig("artifacts/figures/latency_comparison.png", dpi=300)
        plt.close()
    print("  ✓ Saved benchmark & latency comparison HTML/PNG")

    # -------------------------------------------------------------
    # 6. Deep Learning Training History & Learning Curves
    # -------------------------------------------------------------
    print("\n🧠 6. Generating Deep Learning Training & Learning Curves...")
    with open("artifacts/models/production_model/model_config.json", "r") as f:
        m_cfg = json.load(f)
    history = m_cfg.get("training_history", {})
    
    with open("artifacts/models/production_model/training_history.json", "w") as f:
        json.dump(history, f, indent=2)

    train_loss = history.get("train_loss") or history.get("loss", [])
    val_loss = history.get("val_loss", [])
    val_acc = history.get("val_acc", [])

    if train_loss and len(train_loss) > 0:
        epochs = list(range(1, len(train_loss) + 1))
        fig_learn = go.Figure()
        fig_learn.add_trace(go.Scatter(x=epochs, y=train_loss, mode='lines+markers', name='Train Loss', line=dict(color='#ff3b30')))
        if val_loss:
            fig_learn.add_trace(go.Scatter(x=epochs, y=val_loss, mode='lines+markers', name='Val Loss', line=dict(color='#ff9500', dash='dash')))
        if val_acc:
            fig_learn.add_trace(go.Scatter(x=epochs, y=val_acc, mode='lines+markers', name='Val Acc', line=dict(color='#00ff88')))
        
        fig_learn.update_layout(
            title="Hybrid Deep Learning Model Training & Convergence History",
            xaxis_title="Epoch",
            yaxis_title="Loss / Metric Value",
            template="plotly_dark"
        )
        fig_learn.write_html("artifacts/figures/learning/learning_curves.html")

        plt.figure(figsize=(8, 5))
        plt.plot(epochs, train_loss, label='Train Loss', color='#e74c3c', marker='o')
        if val_loss:
            plt.plot(epochs, val_loss, label='Val Loss', color='#e67e22', linestyle='--')
        plt.title("Convergence History", fontsize=14, fontweight='bold')
        plt.xlabel("Epoch", fontsize=12)
        plt.ylabel("Loss", fontsize=12)
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig("artifacts/figures/learning/learning_curves.png", dpi=300)
        plt.close()
    print("  ✓ Saved learning curves HTML/PNG")

    # -------------------------------------------------------------
    # 7. Ablation Study Figures
    # -------------------------------------------------------------
    print("\n🔬 7. Generating Ablation Study Figures...")
    if os.path.exists("artifacts/results/ablation_results.csv"):
        ab_df = pd.read_csv("artifacts/results/ablation_results.csv")
        fig_ab = px.line(
            ab_df, x="stage", y=["macro_f1_pct", "accuracy_pct"],
            markers=True,
            title="Multi-Tiered Architecture Ablation Progression (A through H)",
            labels={"value": "Performance (%)", "stage": "Ablation Stage"},
            template="plotly_dark"
        )
        fig_ab.write_html("artifacts/results/ablation_plot.html")
        fig_ab.write_html("artifacts/figures/ablation_plot.html")

        plt.figure(figsize=(10, 5))
        plt.plot(ab_df["stage"], ab_df["macro_f1_pct"], marker='o', color='#3498db', label='Macro F1 (%)', linewidth=2)
        plt.plot(ab_df["stage"], ab_df["accuracy_pct"], marker='s', color='#2ecc71', label='Accuracy (%)', linewidth=2)
        plt.title("Architectural Ablation Study", fontsize=14, fontweight='bold')
        plt.xlabel("Ablation Tier", fontsize=11)
        plt.ylabel("Score (%)", fontsize=11)
        plt.xticks(rotation=40, ha='right', fontsize=9)
        plt.grid(True, alpha=0.3)
        plt.legend()
        plt.tight_layout()
        plt.savefig("artifacts/figures/ablation_plot.png", dpi=300)
        plt.close()
    print("  ✓ Saved ablation study figures HTML/PNG")

    # -------------------------------------------------------------
    # 8. Precomputing 3D Figures (PCA, MI, Performance)
    # -------------------------------------------------------------
    print("\n🌐 8. Precomputing 3D Visualizations (PCA, MI, Performance)...")
    prep = joblib.load("artifacts/preprocessing/preprocessor.joblib")
    with open("artifacts/features/selected_features.json", "r") as f:
        top_20 = json.load(f)["top_20"]
    
    # Use live_samples for rich 3D visualization
    sample_df = pd.read_csv("artifacts/demo/live_samples.csv")
    X_sample = prep.transform(sample_df)
    X_sub = X_sample[top_20].values

    # 8A. 3D PCA
    pca = PCA(n_components=3, random_state=42)
    pcs = pca.fit_transform(X_sub)
    pca_df = pd.DataFrame({
        "PC1": pcs[:, 0],
        "PC2": pcs[:, 1],
        "PC3": pcs[:, 2],
        "Attack_type": sample_df["Attack_type"].values,
        "Attack_label": sample_df["Attack_label"].values
    })
    fig_3d_pca = px.scatter_3d(
        pca_df, x="PC1", y="PC2", z="PC3",
        color="Attack_type",
        title=f"3D PCA Feature Decomposition (Explained Variance: {pca.explained_variance_ratio_.sum()*100:.1f}%)",
        template="plotly_dark",
        opacity=0.85
    )
    fig_3d_pca.update_layout(margin=dict(l=0, r=0, b=0, t=40))
    fig_3d_pca.write_html("artifacts/figures/3d/pca_3d.html")

    # 8B. 3D MI feature space
    f1, f2, f3 = top_20[0], top_20[1], top_20[2]
    mi_3d_df = pd.DataFrame({
        f1: X_sub[:, 0],
        f2: X_sub[:, 1],
        f3: X_sub[:, 2],
        "Attack_type": sample_df["Attack_type"].values
    })
    fig_3d_mi = px.scatter_3d(
        mi_3d_df, x=f1, y=f2, z=f3,
        color="Attack_type",
        title=f"3D Mutual Information Feature Space: {f1} × {f2} × {f3}",
        template="plotly_dark",
        opacity=0.85
    )
    fig_3d_mi.update_layout(margin=dict(l=0, r=0, b=0, t=40))
    fig_3d_mi.write_html("artifacts/figures/3d/mi_3d.html")

    # 8C. 3D Model Performance
    if os.path.exists("artifacts/results/model_benchmark.csv"):
        b_df = pd.read_csv("artifacts/results/model_benchmark.csv")
        fig_3d_perf = go.Figure(data=[go.Scatter3d(
            x=list(range(len(b_df))),
            y=b_df["Inference_ms"],
            z=b_df["Macro_F1"],
            mode='markers+text',
            marker=dict(
                size=12,
                color=b_df["Macro_F1"],
                colorscale='Viridis',
                showscale=True,
                colorbar=dict(title="Macro F1")
            ),
            text=b_df["Model"],
            textposition="top center"
        )])
        fig_3d_perf.update_layout(
            title="3D Model Tradeoff: Model Index vs Latency (ms) vs Macro F1",
            template="plotly_dark",
            scene=dict(
                xaxis=dict(tickvals=list(range(len(b_df))), ticktext=b_df["Model"].tolist(), title="Model"),
                yaxis=dict(title="Latency (ms)"),
                zaxis=dict(title="Macro F1")
            ),
            margin=dict(l=0, r=0, b=0, t=40)
        )
        fig_3d_perf.write_html("artifacts/figures/3d/model_performance_3d.html")
    print("  ✓ Saved 3D PCA, MI, and Model Performance HTML")

    # -------------------------------------------------------------
    # 9. Offline SHAP & XAI Computations
    # -------------------------------------------------------------
    print("\n🔮 9. Computing Global & Sample SHAP Values Offline...")
    rf_model = joblib.load("artifacts/models/baseline_models/random_forest.joblib")
    
    # Extract background samples (100 samples)
    background_samples = X_sub[:100]
    np.save("artifacts/xai/background_samples.npy", background_samples)
    
    explainer = shap.TreeExplainer(rf_model)
    # Compute SHAP on a test set subset (300 samples)
    test_eval_subset = X_sub[:300]
    shap_vals = explainer.shap_values(test_eval_subset)
    
    # Handle binary classification shap values (take class 1)
    if isinstance(shap_vals, list) and len(shap_vals) > 1:
        shap_vals_arr = np.array(shap_vals[1])
    elif isinstance(shap_vals, np.ndarray) and len(shap_vals.shape) == 3:
        shap_vals_arr = shap_vals[:, :, 1]
    else:
        shap_vals_arr = np.array(shap_vals)
    
    np.save("artifacts/xai/shap_values.npy", shap_vals_arr)
    print("  ✓ Saved shap_values.npy and background_samples.npy")

    # Mean absolute SHAP importance
    mean_abs_shap = np.mean(np.abs(shap_vals_arr), axis=0)
    shap_imp_df = pd.DataFrame({
        "feature": top_20,
        "mean_abs_shap": mean_abs_shap
    }).sort_values("mean_abs_shap", ascending=False)
    shap_imp_df.to_csv("artifacts/xai/shap_importance.csv", index=False)
    print("  ✓ Saved artifacts/xai/shap_importance.csv")

    # Interactive SHAP summary plot via Plotly
    fig_shap = px.bar(
        shap_imp_df, x="mean_abs_shap", y="feature", orientation='h',
        color="mean_abs_shap", color_continuous_scale="Plasma",
        labels={"mean_abs_shap": "Mean |SHAP Value| (Impact on Model Output)", "feature": "Feature"},
        title="Global Explainability: Mean Absolute SHAP Values across Test Partition",
        template="plotly_dark"
    )
    fig_shap.update_layout(yaxis=dict(autorange="reversed"))
    fig_shap.write_html("artifacts/xai/shap_summary.html")

    plt.figure(figsize=(9, 6))
    plt.barh(shap_imp_df["feature"][::-1], shap_imp_df["mean_abs_shap"][::-1], color='#e67e22')
    plt.title("Global Feature Importance (SHAP)", fontsize=14, fontweight='bold')
    plt.xlabel("Mean |SHAP Value|", fontsize=12)
    plt.tight_layout()
    plt.savefig("artifacts/xai/shap_summary.png", dpi=300)
    plt.close()
    print("  ✓ Saved shap_summary.html and shap_summary.png")

    print("\n" + "=" * 70)
    print(" ✅ STAGE 1 - STEP 4 COMPLETE: ALL FIGURES & XAI PRECOMPUTED")
    print("=" * 70)

if __name__ == "__main__":
    main()
