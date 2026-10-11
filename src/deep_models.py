"""
Proposed Hybrid Deep Learning Architecture: MI-CNN-BiLSTM-Attention IDS.
Part of the PhD Research Platform for Edge-IIoT IDS with Blockchain & Quantum Security.
Combines 1D Convolutional feature extraction, Bidirectional LSTM temporal/sequential dependencies,
and Multi-Head Self-Attention for superior intrusion detection in Edge-IIoT networks.
"""

import time
import os
import math
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader
from typing import Dict, Any, List, Optional, Tuple
from src.utils import load_config, set_seed, get_device
from src.evaluation import evaluate_binary, evaluate_multiclass


class SelfAttentionBlock(nn.Module):
    """Multi-Head Self-Attention block with residual connection and LayerNorm."""
    def __init__(self, embed_dim: int, num_heads: int = 4, dropout: float = 0.1):
        super().__init__()
        self.mha = nn.MultiheadAttention(embed_dim, num_heads, dropout=dropout, batch_first=True)
        self.norm = nn.LayerNorm(embed_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        attn_out, _ = self.mha(x, x, x)
        return self.norm(x + self.dropout(attn_out))


class HybridIDSNet(nn.Module):
    """
    Proposed Deep Hybrid Architecture:
    Dense Projection -> 1D CNN -> BiLSTM -> Self-Attention -> Dense Head + Conv1D Residual Highway.
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

        # 1. Feature projection into sequence space (Batch, Seq_len, Dim)
        # We project input vector of length K into a (Seq_len=8, Dim=16) representation
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
        self.pool1 = nn.MaxPool1d(kernel_size=2) # Output seq_len = 4

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

        # 5. Dense Classification Head with Conv1D Residual Highway
        self.fc1 = nn.Linear(bilstm_out_dim * 4, dense_dim)
        if self.use_residual:
            self.res_proj = nn.Linear(conv_filters * 4, dense_dim, bias=False)
        else:
            self.res_proj = None

        self.bn2 = nn.BatchNorm1d(dense_dim)
        self.dropout_layer = nn.Dropout(dropout)
        self.fc_out = nn.Linear(dense_dim, num_classes if num_classes > 2 else 1)

    def forward(self, x):
        # x shape: (Batch, input_dim)
        b = x.size(0)
        proj = self.input_proj(x).view(b, self.seq_len, self.proj_dim) # (B, Seq, Dim)
        
        # Conv1d expects (Batch, Channels, Length)
        conv_in = proj.transpose(1, 2) # (B, Dim, Seq)
        c_out = self.pool1(self.relu(self.bn1(self.conv1(conv_in)))) # (B, conv_filters, 4)
        
        # LSTM expects (Batch, Seq_len, Features)
        lstm_in = c_out.transpose(1, 2) # (B, 4, conv_filters)
        lstm_out, _ = self.bilstm(lstm_in) # (B, 4, bilstm_out_dim)
        
        # Attention
        attn_out = self.attention(lstm_out) # (B, 4, bilstm_out_dim)
        
        # Flatten and combine with Conv1D Residual Highway
        flat_attn = attn_out.reshape(b, -1)
        h_attn = self.fc1(flat_attn)
        if self.use_residual and self.res_proj is not None:
            flat_conv = c_out.reshape(b, -1)
            h_combined = h_attn + self.res_proj(flat_conv)
        else:
            h_combined = h_attn

        h = self.dropout_layer(self.relu(self.bn2(h_combined)))
        out = self.fc_out(h)
        return out



class DeepLearningTrainer:
    """
    High-level manager for training, evaluating, and checkpointing the proposed model.
    """
    def __init__(self, config_path: str = "config.yaml"):
        self.config = load_config(config_path)
        self.seed = self.config["system"]["random_seed"]
        self.device = get_device(self.config["system"]["device"])
        self.checkpoint_dir = self.config["models"]["checkpoint_dir"]
        self.model_cfg = self.config["models"]["proposed_model"]

    def train_proposed_model(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray],
        y_val: Optional[np.ndarray],
        X_test: np.ndarray,
        y_test: np.ndarray,
        is_binary: bool = True,
        classes: Optional[List[str]] = None,
        epochs: Optional[int] = None,
        batch_size: Optional[int] = None,
        learning_rate: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Executes reproducible end-to-end training of the Proposed Model.
        """
        set_seed(self.seed)
        num_classes = 2 if is_binary else len(classes)
        input_dim = X_train.shape[1]
        
        n_epochs = epochs or self.model_cfg["epochs"]
        bs = batch_size or self.model_cfg["batch_size"]
        lr = learning_rate or self.model_cfg["learning_rate"]

        # Datasets
        train_ds = TensorDataset(
            torch.tensor(X_train, dtype=torch.float32),
            torch.tensor(y_train, dtype=torch.float32 if is_binary else torch.long)
        )
        test_ds = TensorDataset(
            torch.tensor(X_test, dtype=torch.float32),
            torch.tensor(y_test, dtype=torch.float32 if is_binary else torch.long)
        )

        train_loader = DataLoader(train_ds, batch_size=bs, shuffle=True)
        test_loader = DataLoader(test_ds, batch_size=bs * 2, shuffle=False)

        val_loader = None
        if X_val is not None and y_val is not None:
            val_ds = TensorDataset(
                torch.tensor(X_val, dtype=torch.float32),
                torch.tensor(y_val, dtype=torch.float32 if is_binary else torch.long)
            )
            val_loader = DataLoader(val_ds, batch_size=bs * 2, shuffle=False)

        # Instantiate Model
        model = HybridIDSNet(
            input_dim=input_dim,
            num_classes=num_classes,
            conv_filters=self.model_cfg["conv_filters"],
            conv_kernel_size=self.model_cfg["conv_kernel_size"],
            lstm_hidden_dim=self.model_cfg["lstm_hidden_dim"],
            lstm_layers=self.model_cfg["lstm_layers"],
            attention_heads=self.model_cfg["attention_heads"],
            dense_dim=self.model_cfg["dense_dim"],
            dropout=self.model_cfg["dropout"]
        ).to(self.device)

        criterion = nn.BCEWithLogitsLoss() if is_binary else nn.CrossEntropyLoss()
        optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=2)

        history = {"train_loss": [], "val_loss": [], "val_acc": []}
        t0 = time.time()

        for epoch in range(1, n_epochs + 1):
            model.train()
            total_train_loss = 0.0
            for bx, by in train_loader:
                bx = bx.to(self.device)
                by = by.to(self.device)

                optimizer.zero_grad()
                out = model(bx)
                loss = criterion(out.squeeze(-1) if is_binary else out, by)
                loss.backward()
                optimizer.step()
                total_train_loss += loss.item() * len(bx)

            avg_train_loss = total_train_loss / len(train_loader.dataset)
            history["train_loss"].append(round(avg_train_loss, 4))

            # Validation step
            if val_loader:
                model.eval()
                total_val_loss = 0.0
                correct = 0
                total = 0
                with torch.no_grad():
                    for bx, by in val_loader:
                        bx = bx.to(self.device)
                        by = by.to(self.device)
                        out = model(bx)
                        loss = criterion(out.squeeze(-1) if is_binary else out, by)
                        total_val_loss += loss.item() * len(bx)
                        
                        if is_binary:
                            preds = (torch.sigmoid(out.squeeze(-1)) >= 0.5).long()
                            correct += (preds == by.long()).sum().item()
                        else:
                            preds = torch.argmax(out, dim=1)
                            correct += (preds == by).sum().item()
                        total += len(by)

                avg_val_loss = total_val_loss / len(val_loader.dataset)
                val_acc = correct / max(1, total)
                history["val_loss"].append(round(avg_val_loss, 4))
                history["val_acc"].append(round(val_acc, 4))
                scheduler.step(avg_val_loss)

        train_duration = time.time() - t0

        # Final Evaluation on untouched Test Set
        model.eval()
        all_preds = []
        all_probs = []
        t1 = time.time()
        with torch.no_grad():
            for bx, _ in test_loader:
                bx = bx.to(self.device)
                out = model(bx)
                if is_binary:
                    prob = torch.sigmoid(out.squeeze(-1)).cpu().numpy()
                    pred = (prob >= 0.5).astype(int)
                    all_probs.extend(prob)
                    all_preds.extend(pred)
                else:
                    prob = torch.softmax(out, dim=1).cpu().numpy()
                    pred = np.argmax(prob, axis=1)
                    all_probs.extend(prob)
                    all_preds.extend(pred)
        infer_duration = time.time() - t1

        all_preds = np.array(all_preds)
        all_probs = np.array(all_probs)

        # Calculate metrics
        if is_binary:
            metrics = evaluate_binary(
                y_test, all_preds, y_prob=all_probs,
                inference_time_sec=infer_duration, train_time_sec=train_duration
            )
            metrics["model_name"] = "Proposed Hybrid IDS (MI+CNN+BiLSTM+Attn)"
            metrics["task"] = "binary"
            save_name = "proposed_hybrid_binary.pt"
        else:
            metrics = evaluate_multiclass(
                y_test, all_preds, classes=classes, y_prob=all_probs,
                inference_time_sec=infer_duration, train_time_sec=train_duration
            )
            metrics["model_name"] = "Proposed Hybrid IDS (MI+CNN+BiLSTM+Attn)"
            metrics["task"] = "multiclass"
            save_name = "proposed_hybrid_multiclass.pt"

        save_path = os.path.join(self.checkpoint_dir, save_name)
        torch.save(model.state_dict(), save_path)
        metrics["saved_path"] = save_path
        metrics["model_size_kb"] = round(os.path.getsize(save_path) / 1024, 2)
        metrics["epochs"] = n_epochs
        metrics["device"] = str(self.device)
        metrics["training_history"] = history

        # Parameter count
        param_count = sum(p.numel() for p in model.parameters() if p.requires_grad)
        metrics["parameters"] = param_count

        return {
            "metrics": metrics,
            "model": model,
            "history": history
        }
