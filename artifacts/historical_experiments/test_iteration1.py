import time
import json
import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, matthews_corrcoef, confusion_matrix

from src.utils import set_seed, get_device
from src.deep_models import HybridIDSNet

class BinaryFocalLoss(nn.Module):
    def __init__(self, alpha: float = 0.5, gamma: float = 2.0, reduction: str = 'mean'):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.reduction = reduction

    def forward(self, logits, targets):
        bce_loss = nn.functional.binary_cross_entropy_with_logits(logits, targets, reduction='none')
        probs = torch.sigmoid(logits)
        p_t = targets * probs + (1 - targets) * (1 - probs)
        alpha_t = targets * self.alpha + (1 - targets) * (1 - self.alpha)
        focal_weight = alpha_t * torch.pow((1.0 - p_t), self.gamma)
        loss = focal_weight * bce_loss
        if self.reduction == 'mean':
            return loss.mean()
        elif self.reduction == 'sum':
            return loss.sum()
        return loss

def train_and_eval(loss_name, criterion_fn, epochs=8, seed=42):
    set_seed(seed)
    device = get_device()
    
    # Load dataset & indices
    df = pd.read_csv('data/raw/ML-EdgeIIoT-dataset.csv', low_memory=False)
    train_idx = np.load('artifacts/splits/train_indices.npy')
    val_idx = np.load('artifacts/splits/validation_indices.npy')
    
    with open('artifacts/features/selected_features.json') as f:
        top_20 = json.load(f)['top_20']
        
    prep = joblib.load('artifacts/preprocessing/preprocessor.joblib')
    
    df_train = df.iloc[train_idx].reset_index(drop=True)
    df_val = df.iloc[val_idx].reset_index(drop=True)
    
    y_train = df_train['Attack_label'].astype(int).values
    y_val = df_val['Attack_label'].astype(int).values
    
    X_train_20 = prep.transform(df_train, return_df=True)[top_20].values
    X_val_20 = prep.transform(df_val, return_df=True)[top_20].values
    
    train_dataset = TensorDataset(
        torch.tensor(X_train_20, dtype=torch.float32),
        torch.tensor(y_train, dtype=torch.float32).unsqueeze(1)
    )
    val_dataset = TensorDataset(
        torch.tensor(X_val_20, dtype=torch.float32),
        torch.tensor(y_val, dtype=torch.float32).unsqueeze(1)
    )
    
    train_loader = DataLoader(train_dataset, batch_size=256, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=256, shuffle=False)
    
    model = HybridIDSNet(input_dim=len(top_20), num_classes=2).to(device)
    criterion = criterion_fn(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=2)
    
    best_val_f1 = 0.0
    best_weights = None
    best_val_preds = None
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
        val_preds_ep = (val_probs_ep >= 0.50).astype(int)
        
        acc = accuracy_score(y_val, val_preds_ep)
        f1 = f1_score(y_val, val_preds_ep, average='macro', zero_division=0)
        
        if f1 > best_val_f1:
            best_val_f1 = f1
            best_weights = model.state_dict().copy()
            best_val_probs = val_probs_ep
            
        print(f"[{loss_name}] Epoch {ep:02d}/{epochs:02d} | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f} | Val Acc: {acc*100:.2f}% | Val Macro F1: {f1*100:.2f}%")
        
    train_time = time.perf_counter() - t0
    
    # Threshold sweep on validation set
    print(f"\nEvaluating threshold calibration on Validation Set for {loss_name}...")
    thresholds = [0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70]
    best_tau = 0.50
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
                "loss_name": loss_name,
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
            
    print(f"Optimal Threshold tau* for {loss_name}: {best_tau:.2f}")
    print(f"  Acc: {best_metrics['accuracy']*100:.2f}% | Prec: {best_metrics['precision']*100:.2f}% | Rec: {best_metrics['recall']*100:.2f}% | Macro F1: {best_metrics['macro_f1']*100:.2f}%")
    print(f"  FN: {best_metrics['fn']} (FNR: {best_metrics['fnr']*100:.2f}%) | FP: {best_metrics['fp']} (FPR: {best_metrics['fpr']*100:.2f}%)")
    return best_metrics, best_weights

if __name__ == '__main__':
    print('Testing Option A: Balanced BCE (pos_weight = 1.0)...')
    metrics_bce, weights_bce = train_and_eval('Balanced_BCE', lambda dev: nn.BCEWithLogitsLoss(), epochs=8)
    
    print('\n' + '='*60 + '\n')
    print('Testing Option B: Binary Focal Loss (gamma=2.0, alpha=0.5)...')
    metrics_focal, weights_focal = train_and_eval('Binary_Focal_Loss', lambda dev: BinaryFocalLoss(alpha=0.5, gamma=2.0), epochs=8)
    
    print('\n' + '='*60 + '\n')
    print('COMPARISON SUMMARY (VALIDATION PARTITION N=23,670):')
    print(f"Baseline (pos_weight=0.182): Acc: 94.67%, Macro F1: 90.92%, Rec: 93.93%, FN: 1216, FP: 46")
    print(f"Balanced BCE (pos_weight=1.0): Acc: {metrics_bce['accuracy']*100:.2f}%, Macro F1: {metrics_bce['macro_f1']*100:.2f}%, Rec: {metrics_bce['recall']*100:.2f}%, FN: {metrics_bce['fn']}, FP: {metrics_bce['fp']}")
    print(f"Focal Loss (gamma=2.0):       Acc: {metrics_focal['accuracy']*100:.2f}%, Macro F1: {metrics_focal['macro_f1']*100:.2f}%, Rec: {metrics_focal['recall']*100:.2f}%, FN: {metrics_focal['fn']}, FP: {metrics_focal['fp']}")
