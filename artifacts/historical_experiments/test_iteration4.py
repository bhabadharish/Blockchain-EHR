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
from src.deep_models import SelfAttentionBlock

set_seed(42)
device = get_device()
print(f"Compute device: {device}")

# Define HybridIDSNet with Residual Highway
class HybridIDSNetWithResidual(nn.Module):
    """
    Iteration 4 Architecture:
    Proposed HybridIDSNet with Conv1D -> Dense Residual Highway Connection (H4)
    Preserves Conv1D, BiLSTM, and MHA while establishing a direct gradient highway.
    """
    def __init__(
        self,
        input_dim: int,
        num_classes: int = 2,
        conv_filters: int = 64,
        conv_kernel_size: int = 3,
        lstm_hidden_dim: int = 64,
        lstm_layers: int = 2,
        attention_heads: int = 4,
        dense_dim: int = 128,
        dropout: float = 0.25,
        use_residual: bool = True
    ):
        super().__init__()
        self.input_dim = input_dim
        self.num_classes = num_classes
        self.use_residual = use_residual

        # 1. Feature projection into sequence space (Batch, Seq_len=8, Dim=16)
        self.seq_len = 8
        self.proj_dim = 16
        self.input_proj = nn.Linear(input_dim, self.seq_len * self.proj_dim)

        # 2. 1D Convolutional Block
        self.conv1 = nn.Conv1d(
            in_channels=self.proj_dim,
            out_channels=conv_filters,
            kernel_size=conv_kernel_size,
            padding=conv_kernel_size // 2
        )
        self.bn1 = nn.BatchNorm1d(conv_filters)
        self.relu = nn.ReLU()
        self.pool1 = nn.MaxPool1d(kernel_size=2)  # Output seq_len = 4

        # 3. Bidirectional LSTM Block
        self.bilstm = nn.LSTM(
            input_size=conv_filters,
            hidden_size=lstm_hidden_dim,
            num_layers=lstm_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if lstm_layers > 1 else 0.0
        )
        bilstm_out_dim = lstm_hidden_dim * 2

        # 4. Multi-Head Self-Attention Block
        self.attention = SelfAttentionBlock(embed_dim=bilstm_out_dim, num_heads=attention_heads, dropout=dropout)

        # 5. Dense Classification Head with Residual Highway
        self.fc1 = nn.Linear(bilstm_out_dim * 4, dense_dim)
        
        # Residual Highway connection from Conv1D output (conv_filters * 4 = 256)
        if self.use_residual:
            self.res_proj = nn.Linear(conv_filters * 4, dense_dim, bias=False)
        else:
            self.res_proj = None

        self.bn2 = nn.BatchNorm1d(dense_dim)
        self.dropout_layer = nn.Dropout(dropout)
        self.fc_out = nn.Linear(dense_dim, num_classes if num_classes > 2 else 1)

    def forward(self, x):
        b = x.size(0)
        proj = self.input_proj(x).view(b, self.seq_len, self.proj_dim)  # (B, 8, 16)
        
        conv_in = proj.transpose(1, 2)  # (B, 16, 8)
        c_out = self.pool1(self.relu(self.bn1(self.conv1(conv_in))))  # (B, conv_filters, 4)
        
        lstm_in = c_out.transpose(1, 2)  # (B, 4, conv_filters)
        lstm_out, _ = self.bilstm(lstm_in)  # (B, 4, bilstm_out_dim)
        
        attn_out = self.attention(lstm_out)  # (B, 4, bilstm_out_dim)
        
        flat_attn = attn_out.reshape(b, -1)  # (B, bilstm_out_dim * 4)
        h_attn = self.fc1(flat_attn)
        
        if self.use_residual and self.res_proj is not None:
            flat_conv = c_out.reshape(b, -1)  # (B, conv_filters * 4)
            h_res = self.res_proj(flat_conv)
            h_combined = h_attn + h_res
        else:
            h_combined = h_attn

        h = self.dropout_layer(self.relu(self.bn2(h_combined)))
        out = self.fc_out(h)
        return out


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

# 2. Iteration 3 Preprocessing (Champion state)
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

# Standard scale
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(df_train[top_20].values)
X_val_scaled = scaler.transform(df_val[top_20].values)

# Gradient Flow Verification Test
print("\n--- Diagnostic: Input Feature Gradient Flow Test ---")
sample_x = torch.tensor(X_train_scaled[:100], dtype=torch.float32, requires_grad=True, device=device)
sample_y = torch.tensor(y_train[:100], dtype=torch.float32, device=device).unsqueeze(1)

model_no_res = HybridIDSNetWithResidual(input_dim=len(top_20), num_classes=2, use_residual=False).to(device)
model_res = HybridIDSNetWithResidual(input_dim=len(top_20), num_classes=2, use_residual=True).to(device)

criterion = nn.BCEWithLogitsLoss()

# Gradient through baseline
out_no_res = model_no_res(sample_x)
loss_no_res = criterion(out_no_res, sample_y)
sample_x.grad = None
loss_no_res.backward(retain_graph=True)
grad_no_res = sample_x.grad.abs().mean(dim=0).cpu().numpy()

# Gradient through residual highway
sample_x.grad = None
out_res = model_res(sample_x)
loss_res = criterion(out_res, sample_y)
loss_res.backward()
grad_res = sample_x.grad.abs().mean(dim=0).cpu().numpy()

print(f"{'Feature':<25} | {'Base Grad Magnitude':<20} | {'Residual Grad Magnitude':<22} | {'Change'}")
print("-" * 80)
for feat_name, g_base, g_res in zip(top_20, grad_no_res, grad_res):
    ratio = (g_res / max(1e-9, g_base))
    print(f"{feat_name:<25} | {g_base:<20.6e} | {g_res:<22.6e} | {ratio:.2f}x")

# Check parameter count
param_count = sum(p.numel() for p in model_res.parameters() if p.requires_grad)
print(f"\nModel Parameter Count: {param_count:,} (Constraint: <= 350,000)")

# Training Iteration 4 Model
train_dataset = TensorDataset(torch.tensor(X_train_scaled, dtype=torch.float32), torch.tensor(y_train, dtype=torch.float32).unsqueeze(1))
val_dataset = TensorDataset(torch.tensor(X_val_scaled, dtype=torch.float32), torch.tensor(y_val, dtype=torch.float32).unsqueeze(1))

train_loader = DataLoader(train_dataset, batch_size=256, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=256, shuffle=False)

n_pos = np.sum(y_train == 1)
n_neg = np.sum(y_train == 0)
pos_weight = torch.tensor([float(n_neg / max(1, n_pos))], device=device)
criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
optimizer = torch.optim.AdamW(model_res.parameters(), lr=1e-3, weight_decay=1e-4)
scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode="min", factor=0.5, patience=2)

epochs = 10
best_val_loss = float("inf")
best_weights = None
best_val_probs = None

print("\nStarting Controlled Training for Iteration 4 (Residual Highway Network)...")
t0 = time.perf_counter()
for ep in range(1, epochs + 1):
    model_res.train()
    train_loss = 0.0
    for bx, by in train_loader:
        bx, by = bx.to(device), by.to(device)
        optimizer.zero_grad()
        out = model_res(bx)
        loss = criterion(out, by)
        loss.backward()
        optimizer.step()
        train_loss += loss.item() * len(bx)
    train_loss /= len(train_dataset)

    # Validation
    model_res.eval()
    val_loss = 0.0
    val_probs_ep = []
    with torch.no_grad():
        for bx, by in val_loader:
            bx, by = bx.to(device), by.to(device)
            out = model_res(bx)
            loss = criterion(out, by)
            val_loss += loss.item() * len(bx)
            p = torch.sigmoid(out.squeeze(-1)).cpu().numpy()
            val_probs_ep.extend(p)
    val_loss /= len(val_dataset)
    scheduler.step(val_loss)

    val_probs_ep = np.array(val_probs_ep)
    val_preds_ep = (val_probs_ep >= 0.10).astype(int)
    acc = accuracy_score(y_val, val_preds_ep)
    f1 = f1_score(y_val, val_preds_ep, average="macro", zero_division=0)

    if val_loss < best_val_loss:
        best_val_loss = val_loss
        best_weights = model_res.state_dict().copy()
        best_val_probs = val_probs_ep

    print(f"  Epoch {ep:02d}/{epochs:02d} | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f} | Val Acc: {acc*100:.2f}% | Val Macro F1: {f1*100:.2f}%")

train_time = time.perf_counter() - t0

# Latency Benchmark
model_res.load_state_dict(best_weights)
model_res.eval()
warmup_x = torch.tensor(X_val_scaled[:1000], dtype=torch.float32, device=device)
with torch.no_grad():
    for _ in range(10):
        _ = model_res(warmup_x)
    if device.type == "mps":
        torch.mps.synchronize()
    t_start = time.perf_counter()
    for _ in range(50):
        _ = model_res(warmup_x)
    if device.type == "mps":
        torch.mps.synchronize()
    latency_per_sample_ms = ((time.perf_counter() - t_start) / (50 * 1000)) * 1000.0

# Evaluate across thresholds
thresholds = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.50]
best_tau = 0.10
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
            "accuracy": float(acc),
            "precision": float(prec),
            "recall": float(rec),
            "specificity": float(spec),
            "macro_f1": float(f1),
            "mcc": float(matthews_corrcoef(y_val, preds)),
            "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
            "fpr": float(fpr), "fnr": float(fnr),
            "latency_ms": float(latency_per_sample_ms),
            "param_count": int(param_count),
            "train_time_sec": float(train_time)
        }

print("\n" + "="*60)
print(f"FINAL VALIDATION RESULTS FOR ITERATION 4 (tau*={best_tau:.2f}):")
print(f"  Accuracy:      {best_metrics['accuracy']*100:.2f}% ({best_metrics['accuracy']:.6f})")
print(f"  Precision:     {best_metrics['precision']*100:.2f}% ({best_metrics['precision']:.6f})")
print(f"  Recall:        {best_metrics['recall']*100:.2f}% ({best_metrics['recall']:.6f})")
print(f"  Specificity:   {best_metrics['specificity']*100:.2f}% ({best_metrics['specificity']:.6f})")
print(f"  Macro F1:      {best_metrics['macro_f1']*100:.2f}% ({best_metrics['macro_f1']:.6f})")
print(f"  MCC:           {best_metrics['mcc']:.4f}")
print(f"  TP: {best_metrics['tp']}, TN: {best_metrics['tn']}, FP: {best_metrics['fp']}, FN: {best_metrics['fn']}")
print(f"  FPR: {best_metrics['fpr']*100:.2f}%, FNR: {best_metrics['fnr']*100:.2f}%")
print(f"  Inference Latency: {best_metrics['latency_ms']:.4f} ms/sample")
print(f"  Parameters:    {best_metrics['param_count']:,}")
print("="*60)

# Save best weights and results
torch.save(best_weights, "scratch/iteration4_best_weights.pt")
with open("scratch/iteration4_results.json", "w") as f:
    json.dump(best_metrics, f, indent=2)
print("Saved iteration 4 weights and results to scratch/")
