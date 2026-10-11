import sys
sys.path.insert(0, ".")

import time
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    matthews_corrcoef, confusion_matrix, classification_report
)

print("=" * 70)
print("STAGE 9: Iteration 5 Controlled Benchmark — Multiclass De-biasing (H5)")
print("=" * 70)

# 1. Load data
df = pd.read_csv("data/raw/ML-EdgeIIoT-dataset.csv", low_memory=False)
train_idx = np.load("artifacts/splits/train_indices.npy")
val_idx = np.load("artifacts/splits/validation_indices.npy")

with open("artifacts/features/selected_features.json") as f:
    top_20 = json.load(f)["top_20"]

df_train = df.iloc[train_idx].copy().reset_index(drop=True)
df_val = df.iloc[val_idx].copy().reset_index(drop=True)

# 2. Champion Preprocessing Pipeline (Iterations 2-4)
# Clean tcp.srcport: convert to valid float port [0, 65535]
df_train["tcp.srcport"] = pd.to_numeric(df_train["tcp.srcport"], errors="coerce").fillna(0.0).clip(0, 65535)
df_val["tcp.srcport"] = pd.to_numeric(df_val["tcp.srcport"], errors="coerce").fillna(0.0).clip(0, 65535)

# Clean tcp.payload: map to byte length
df_train["tcp.payload"] = df_train["tcp.payload"].astype(str).map(lambda s: 0.0 if s in ["0", "0.0", "nan", ""] else float(len(s)))
df_val["tcp.payload"] = df_val["tcp.payload"].astype(str).map(lambda s: 0.0 if s in ["0", "0.0", "nan", ""] else float(len(s)))

# Clean tcp.options: map to RFC byte length
df_train["tcp.options"] = df_train["tcp.options"].astype(str).map(lambda s: 0.0 if s in ["0", "0.0", "nan", ""] else float(len(s) // 2))
df_val["tcp.options"] = df_val["tcp.options"].astype(str).map(lambda s: 0.0 if s in ["0", "0.0", "nan", ""] else float(len(s) // 2))

# Clean other numeric columns
for num_c in ["tcp.dstport", "tcp.flags", "tcp.flags.ack", "tcp.checksum"]:
    df_train[num_c] = pd.to_numeric(df_train[num_c], errors="coerce").fillna(0.0)
    df_val[num_c] = pd.to_numeric(df_val[num_c], errors="coerce").fillna(0.0)

# Harmonize '0' and '0.0' for nominal string columns
for c in ["dns.qry.name.len", "mqtt.conack.flags", "mqtt.protoname", "mqtt.topic", "mqtt.msg", "http.request.version", "http.request.method", "http.referer", "http.request.uri.query"]:
    s_tr = df_train[c].astype(str).replace({"0": "NULL_ZERO", "0.0": "NULL_ZERO", "0.00": "NULL_ZERO"})
    s_va = df_val[c].astype(str).replace({"0": "NULL_ZERO", "0.0": "NULL_ZERO", "0.00": "NULL_ZERO"})
    le = LabelEncoder()
    le.fit(s_tr)
    cls_set = set(le.classes_)
    df_train[c] = le.transform(s_tr)
    df_val[c] = le.transform(s_va.map(lambda x: x if x in cls_set else le.classes_[0]))

# Power-law log1p transform on skewed counters
skew_cols = ["tcp.len", "tcp.seq", "tcp.ack", "tcp.ack_raw", "tcp.payload", "tcp.options"]
for sc in skew_cols:
    df_train[sc] = np.log1p(np.maximum(0, pd.to_numeric(df_train[sc], errors="coerce").fillna(0.0).values))
    df_val[sc] = np.log1p(np.maximum(0, pd.to_numeric(df_val[sc], errors="coerce").fillna(0.0).values))

X_tr = df_train[top_20].values
X_va = df_val[top_20].values

y_tr_multi = df_train["Attack_type"].astype(str).values
y_va_multi = df_val["Attack_type"].astype(str).values

classes = sorted(list(np.unique(y_tr_multi)))
print(f"Total threat classes: {len(classes)}")

# 3. Train Balanced HistGradientBoostingClassifier
print("\nTraining Class-Balanced HistGradientBoostingClassifier...")
t0 = time.perf_counter()
hgb = HistGradientBoostingClassifier(
    class_weight="balanced",
    learning_rate=0.08,
    max_iter=120,
    max_leaf_nodes=64,
    random_state=42
)
hgb.fit(X_tr, y_tr_multi)
train_time = time.perf_counter() - t0
print(f"Training completed in {train_time:.2f} seconds.")

# 4. Latency Benchmark
warmup_x = X_va[:1000]
for _ in range(10):
    _ = hgb.predict(warmup_x)
t_start = time.perf_counter()
for _ in range(50):
    _ = hgb.predict(warmup_x)
latency_ms = ((time.perf_counter() - t_start) / (50 * 1000)) * 1000.0

# 5. Validation Evaluation
preds = hgb.predict(X_va)
acc = accuracy_score(y_va_multi, preds)
macro_f1 = f1_score(y_va_multi, preds, average="macro")
macro_prec = precision_score(y_va_multi, preds, average="macro", zero_division=0)
macro_rec = recall_score(y_va_multi, preds, average="macro", zero_division=0)

print(f"\nValidation Overall Accuracy: {acc*100:.2f}% (Baseline: 85.67%)")
print(f"Validation Macro F1:         {macro_f1*100:.2f}% (Baseline: 80.58%)")
print(f"Validation Macro Precision:  {macro_prec*100:.2f}%")
print(f"Validation Macro Recall:     {macro_rec*100:.2f}%")
print(f"Inference Latency:           {latency_ms:.4f} ms/sample")

# Per-class detailed breakdown
per_class_results = {}
for c in classes:
    y_true_c = (y_va_multi == c).astype(int)
    y_pred_c = (preds == c).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true_c, y_pred_c).ravel()
    prec_c = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec_c = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_c = 2 * prec_c * rec_c / (prec_c + rec_c) if (prec_c + rec_c) > 0 else 0.0
    spec_c = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    
    per_class_results[c] = {
        "support": int(np.sum(y_true_c)),
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        "precision": float(prec_c),
        "recall": float(rec_c),
        "f1": float(f1_c),
        "specificity": float(spec_c)
    }

print("\n--- Per-Class Metrics ---")
print(f"{'Class':<22} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'TP':<6} | {'FP':<6} | {'FN':<6}")
print("-" * 80)
for c in classes:
    m = per_class_results[c]
    print(f"{c:<22} | {m['precision']*100:<9.2f}% | {m['recall']*100:<9.2f}% | {m['f1']*100:<9.2f}% | {m['tp']:<6d} | {m['fp']:<6d} | {m['fn']:<6d}")

# Save artifacts
joblib.dump(hgb, "scratch/iteration5_hgb_model.joblib")

summary_results = {
    "accuracy": float(acc),
    "macro_f1": float(macro_f1),
    "macro_precision": float(macro_prec),
    "macro_recall": float(macro_rec),
    "latency_ms": float(latency_ms),
    "train_time_sec": float(train_time),
    "ddos_icmp_precision": per_class_results["DDoS_ICMP"]["precision"],
    "ddos_icmp_recall": per_class_results["DDoS_ICMP"]["recall"],
    "ddos_udp_precision": per_class_results["DDoS_UDP"]["precision"],
    "ddos_udp_recall": per_class_results["DDoS_UDP"]["recall"],
    "per_class": per_class_results
}

with open("scratch/iteration5_multiclass_results.json", "w") as f:
    json.dump(summary_results, f, indent=2)

print("\nSaved Iteration 5 model and benchmark results to scratch/")
