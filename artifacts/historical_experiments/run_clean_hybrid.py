import sys
sys.path.insert(0, ".")

import time
import json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, matthews_corrcoef, confusion_matrix

from src.utils import set_seed, get_device
from src.deep_models import HybridIDSNet

set_seed(42)
device = get_device()
print(f"Compute device: {device}")

# 1. Load data
df = pd.read_csv("data/raw/ML-EdgeIIoT-dataset.csv", low_memory=False)
train_idx = np.load("artifacts/splits/train_indices.npy")
val_idx = np.load("artifacts/splits/validation_indices.npy")

with open("artifacts/features/selected_features.json") as f:
    top_20 = json.load(f)["top_20"]

df_train = df.iloc[train_idx].copy().reset_index(drop=True)
df_val = df.iloc[val_idx].copy().reset_index(drop=True)

y_train = df_train["Attack_label"].astype(int).values
y_val = df_val["Attack_label"].astype(int).values

# 2. Controlled Feature Engineering for Iteration 2:
# Clean tcp.srcport: convert to valid float port [0, 65535]
df_train["tcp.srcport"] = pd.to_numeric(df_train["tcp.srcport"], errors="coerce").fillna(0.0).clip(0, 65535)
df_val["tcp.srcport"] = pd.to_numeric(df_val["tcp.srcport"], errors="coerce").fillna(0.0).clip(0, 65535)

# Clean tcp.payload: map to byte length (preventing 240-digit float32 overflow)
df_train["tcp.payload"] = df_train["tcp.payload"].astype(str).map(lambda s: 0.0 if s in ["0", "0.0", "nan", ""] else float(len(s)))
df_val["tcp.payload"] = df_val["tcp.payload"].astype(str).map(lambda s: 0.0 if s in ["0", "0.0", "nan", ""] else float(len(s)))

# Clean other numeric columns
for num_c in ["tcp.dstport", "tcp.flags", "tcp.flags.ack", "tcp.checksum"]:
    df_train[num_c] = pd.to_numeric(df_train[num_c], errors="coerce").fillna(0.0)
    df_val[num_c] = pd.to_numeric(df_val[num_c], errors="coerce").fillna(0.0)

# Power-law log1p transform on skewed counters
skew_cols = ["tcp.len", "tcp.seq", "tcp.ack", "tcp.ack_raw", "tcp.payload"]
for sc in skew_cols:
    df_train[sc] = np.log1p(np.maximum(0, pd.to_numeric(df_train[sc], errors="coerce").fillna(0.0).values))
    df_val[sc] = np.log1p(np.maximum(0, pd.to_numeric(df_val[sc], errors="coerce").fillna(0.0).values))

# Categoricals (excluding numeric/cleaned columns)
cat_cols = [c for c in top_20 if not pd.api.types.is_numeric_dtype(df_train[c])]
for c in cat_cols:
    le = LabelEncoder()
    le.fit(df_train[c].astype(str))
    cls_set = set(le.classes_)
    df_train[c] = le.transform(df_train[c].astype(str))
    df_val[c] = le.transform(df_val[c].astype(str).map(lambda x: x if x in cls_set else le.classes_[0]))

# Fit standard scaler on log-transformed data
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(df_train[top_20].values)
X_val_scaled = scaler.transform(df_val[top_20].values)

# 3. Model setup
train_dataset = TensorDataset(torch.tensor(X_train_scaled, dtype=torch.float32), torch.tensor(y_train, dtype=torch.float32).unsqueeze(1))
val_dataset = TensorDataset(torch.tensor(X_val_scaled, dtype=torch.float32), torch.tensor(y_val, dtype=torch.float32).unsqueeze(1))

train_loader = DataLoader(train_dataset, batch_size=256, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=256, shuffle=False)

model = HybridIDSNet(input_dim=len(top_20), num_classes=2).to(device)

n_pos = np.sum(y_train == 1)
n_neg = np.sum(y_train == 0)
pos_weight = torch.tensor([float(n_neg / max(1, n_pos))], device=device)
criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode="min", factor=0.5, patience=2)

epochs = 10
best_val_loss = float("inf")
best_weights = None
best_val_probs = None

print("\nStarting Controlled Training for Iteration 2 (Cleaned Ports + Payload Len + Log1p Scaling)...")
t0 = time.perf_counter()
for ep in range(1, epochs + 1):
    model.train()
    train_loss = 0.0
    for bx, by in train_loader:
        bx, by = bx.to(device), by.to(device)
        optimizer.zero_grad()
        out = model(bx)
        loss = criterion(out, by)
        loss.backward()
        optimizer.step()
        train_loss += loss.item() * len(bx)
    train_loss /= len(train_dataset)

    # Validation
    model.eval()
    val_loss = 0.0
    val_probs_ep = []
    with torch.no_grad():
        for bx, by in val_loader:
            bx, by = bx.to(device), by.to(device)
            out = model(bx)
            loss = criterion(out, by)
            val_loss += loss.item() * len(bx)
            p = torch.sigmoid(out.squeeze(-1)).cpu().numpy()
            val_probs_ep.extend(p)
    val_loss /= len(val_dataset)
    scheduler.step(val_loss)

    val_probs_ep = np.array(val_probs_ep)
    val_preds_ep = (val_probs_ep >= 0.20).astype(int)
    acc = accuracy_score(y_val, val_preds_ep)
    f1 = f1_score(y_val, val_preds_ep, average="macro", zero_division=0)

    if val_loss < best_val_loss:
        best_val_loss = val_loss
        best_weights = model.state_dict().copy()
        best_val_probs = val_probs_ep

    print(f"  Epoch {ep:02d}/{epochs:02d} | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f} | Val Acc: {acc*100:.2f}% | Val Macro F1: {f1*100:.2f}%")

train_time = time.perf_counter() - t0

# Evaluate best checkpoint across thresholds
thresholds = [0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
best_tau = 0.20
best_tau_f1 = 0.0
best_metrics = {}

for tau in thresholds:
    preds = (best_val_probs >= tau).astype(int)
    acc = accuracy_score(y_val, preds)
    prec = precision_score(y_val, preds, zero_division=0)
    rec = recall_score(y_val, preds, zero_division=0)
    f1 = f1_score(y_val, preds, average="macro", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_val, preds).ravel()
    spec = tn / (tn + fp)
    fpr = fp / (fp + tn)
    fnr = fn / (fn + tp)

    if f1 > best_tau_f1:
        best_tau_f1 = f1
        best_tau = tau
        best_metrics = {
            "optimal_threshold": tau,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "specificity": spec,
            "macro_f1": f1,
            "mcc": matthews_corrcoef(y_val, preds),
            "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
            "fpr": fpr, "fnr": fnr,
            "train_time_sec": train_time
        }

print("\n" + "="*60)
print(f"FINAL VALIDATION RESULTS FOR ITERATION 2 (tau*={best_tau:.2f}):")
print(f"  Accuracy:    {best_metrics['accuracy']*100:.2f}% ({best_metrics['accuracy']:.6f})")
print(f"  Precision:   {best_metrics['precision']*100:.2f}% ({best_metrics['precision']:.6f})")
print(f"  Recall:      {best_metrics['recall']*100:.2f}% ({best_metrics['recall']:.6f})")
print(f"  Specificity: {best_metrics['specificity']*100:.2f}% ({best_metrics['specificity']:.6f})")
print(f"  Macro F1:    {best_metrics['macro_f1']*100:.2f}% ({best_metrics['macro_f1']:.6f})")
print(f"  MCC:         {best_metrics['mcc']:.4f}")
print(f"  TP: {best_metrics['tp']}, TN: {best_metrics['tn']}, FP: {best_metrics['fp']}, FN: {best_metrics['fn']}")
print(f"  FPR: {best_metrics['fpr']*100:.2f}%, FNR: {best_metrics['fnr']*100:.2f}%")
print("="*60)

# Save best weights for Iteration 2
torch.save(best_weights, "scratch/iteration2_best_weights.pt")
with open("scratch/iteration2_results.json", "w") as f:
    json.dump(best_metrics, f, indent=2)
print("Saved iteration 2 weights and results to scratch/")
