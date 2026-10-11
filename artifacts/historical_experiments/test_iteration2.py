import sys
sys.path.insert(0, ".")

import time
import json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.preprocessing import StandardScaler, RobustScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, matthews_corrcoef, confusion_matrix

from src.utils import set_seed, get_device
from src.deep_models import HybridIDSNet

def prepare_pipeline(mode, df_train_raw, df_val_raw, top_20, leakage_cols):
    df_train = df_train_raw.copy()
    df_val = df_val_raw.copy()
    
    # 1. Clean tcp.srcport if mode != 'baseline'
    if mode != 'baseline':
        def clean_port(s):
            num = pd.to_numeric(s, errors='coerce')
            return num.fillna(0.0).values
        df_train['tcp.srcport'] = clean_port(df_train['tcp.srcport'])
        df_val['tcp.srcport'] = clean_port(df_val['tcp.srcport'])
        
    # 2. Identify numerical and categorical in top_20
    cat_cols = []
    num_cols = []
    for c in top_20:
        if pd.api.types.is_numeric_dtype(df_train[c]):
            num_cols.append(c)
        else:
            cat_cols.append(c)
            
    # 3. Apply log1p on extreme skews if mode == 'log_robust'
    if mode == 'log_robust':
        skew_cols = ['tcp.len', 'tcp.seq', 'tcp.ack', 'tcp.ack_raw']
        for sc in skew_cols:
            if sc in df_train.columns:
                df_train[sc] = np.log1p(np.maximum(0, df_train[sc].values))
                df_val[sc] = np.log1p(np.maximum(0, df_val[sc].values))
                
    # 4. Encode categoricals on train only
    X_train_df = df_train[top_20].copy()
    X_val_df = df_val[top_20].copy()
    
    for c in cat_cols:
        le = LabelEncoder()
        le.fit(X_train_df[c].astype(str))
        cls_set = set(le.classes_)
        X_train_df[c] = le.transform(X_train_df[c].astype(str))
        X_val_df[c] = le.transform(X_val_df[c].astype(str).map(lambda x: x if x in cls_set else le.classes_[0]))
        
    # 5. Fit scaler on train only
    if mode == 'baseline':
        scaler = StandardScaler()
    else:
        scaler = RobustScaler(quantile_range=(5.0, 95.0), unit_variance=True)
        
    X_train_scaled = scaler.fit_transform(X_train_df)
    X_val_scaled = scaler.transform(X_val_df)
    
    return X_train_scaled, X_val_scaled

def train_and_eval(name, mode, epochs=8, seed=42):
    set_seed(seed)
    device = get_device()
    
    df = pd.read_csv('data/raw/ML-EdgeIIoT-dataset.csv', low_memory=False)
    train_idx = np.load('artifacts/splits/train_indices.npy')
    val_idx = np.load('artifacts/splits/validation_indices.npy')
    
    with open('artifacts/features/selected_features.json') as f:
        top_20 = json.load(f)['top_20']
        
    leakage_cols = ['frame.time', 'ip.src_host', 'ip.dst_host', 'arp.src.proto_ipv4', 'arp.dst.proto_ipv4', 'http.file_data', 'http.request.full_uri', 'icmp.transmit_timestamp']
    
    df_train = df.iloc[train_idx].reset_index(drop=True)
    df_val = df.iloc[val_idx].reset_index(drop=True)
    
    y_train = df_train['Attack_label'].astype(int).values
    y_val = df_val['Attack_label'].astype(int).values
    
    X_train, X_val = prepare_pipeline(mode, df_train, df_val, top_20, leakage_cols)
    
    # Cost-sensitive weighting (champion pos_weight = 0.1820)
    n_pos = np.sum(y_train == 1)
    n_neg = np.sum(y_train == 0)
    pos_weight = torch.tensor([float(n_neg / max(1, n_pos))], device=device)
    
    train_dataset = TensorDataset(
        torch.tensor(X_train, dtype=torch.float32),
        torch.tensor(y_train, dtype=torch.float32).unsqueeze(1)
    )
    val_dataset = TensorDataset(
        torch.tensor(X_val, dtype=torch.float32),
        torch.tensor(y_val, dtype=torch.float32).unsqueeze(1)
    )
    
    train_loader = DataLoader(train_dataset, batch_size=256, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=256, shuffle=False)
    
    model = HybridIDSNet(input_dim=len(top_20), num_classes=2).to(device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=2)
    
    best_val_f1 = 0.0
    best_weights = None
    best_val_probs = None
    
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
        f1 = f1_score(y_val, val_preds_ep, average='macro', zero_division=0)
        
        if f1 > best_val_f1:
            best_val_f1 = f1
            best_weights = model.state_dict().copy()
            best_val_probs = val_probs_ep
            
        print(f"[{name}] Epoch {ep:02d}/{epochs:02d} | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f} | Val Acc: {acc*100:.2f}% | Val Macro F1: {f1*100:.2f}%")
        
    train_time = time.perf_counter() - t0
    
    # Threshold sweep on validation set
    thresholds = [0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
    best_tau = 0.20
    best_tau_f1 = 0.0
    best_metrics = {}
    
    for tau in thresholds:
        preds = (best_val_probs >= tau).astype(int)
        acc = accuracy_score(y_val, preds)
        prec = precision_score(y_val, preds, zero_division=0)
        rec = recall_score(y_val, preds, zero_division=0)
        f1 = f1_score(y_val, preds, average='macro', zero_division=0)
        tn, fp, fn, tp = confusion_matrix(y_val, preds).ravel()
        spec = tn / (tn + fp)
        fpr = fp / (fp + tn)
        fnr = fn / (fn + tp)
        
        if f1 > best_tau_f1:
            best_tau_f1 = f1
            best_tau = tau
            best_metrics = {
                "name": name,
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
            
    print(f"\nResults for {name} (tau*={best_tau:.2f}):")
    print(f"  Accuracy:  {best_metrics['accuracy']*100:.2f}% ({best_metrics['accuracy']:.6f})")
    print(f"  Precision: {best_metrics['precision']*100:.2f}% ({best_metrics['precision']:.6f})")
    print(f"  Recall:    {best_metrics['recall']*100:.2f}% ({best_metrics['recall']:.6f})")
    print(f"  Macro F1:  {best_metrics['macro_f1']*100:.2f}% ({best_metrics['macro_f1']:.6f})")
    print(f"  Spec:      {best_metrics['specificity']*100:.2f}% ({best_metrics['specificity']:.6f})")
    print(f"  FN: {best_metrics['fn']} ({best_metrics['fnr']*100:.2f}%) | FP: {best_metrics['fp']} ({best_metrics['fpr']*100:.2f}%)")
    return best_metrics, best_weights

if __name__ == '__main__':
    print('Testing Option 1: Cleaned Port + RobustScaler...')
    m_robust, w_robust = train_and_eval('CleanedPort_RobustScaler', mode='robust', epochs=8)
    
    print('\n' + '='*60 + '\n')
    print('Testing Option 2: Cleaned Port + Log1p + RobustScaler...')
    m_log, w_log = train_and_eval('CleanedPort_Log1p_RobustScaler', mode='log_robust', epochs=8)
