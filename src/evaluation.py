"""
Comprehensive Metric Calculation and Security Evaluation Engine.
Part of the PhD Research Platform for Edge-IIoT IDS with Blockchain & Quantum Security.
Calculates academic binary, multiclass, and security-specific metrics.
"""

import time
import numpy as np
from typing import Dict, Any, List, Optional
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    matthews_corrcoef, cohen_kappa_score, roc_auc_score,
    average_precision_score, confusion_matrix, classification_report
)


def evaluate_binary(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: Optional[np.ndarray] = None,
    inference_time_sec: float = 0.0,
    train_time_sec: float = 0.0
) -> Dict[str, Any]:
    """
    Computes rigorous binary intrusion detection metrics.
    Normal = 0, Attack = 1.
    """
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    macro_prec = precision_score(y_true, y_pred, average="macro", zero_division=0)
    macro_rec = recall_score(y_true, y_pred, average="macro", zero_division=0)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    
    weighted_prec = precision_score(y_true, y_pred, average="weighted", zero_division=0)
    weighted_rec = recall_score(y_true, y_pred, average="weighted", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    
    mcc = matthews_corrcoef(y_true, y_pred)
    kappa = cohen_kappa_score(y_true, y_pred)

    # Confusion Matrix: TN, FP, FN, TP
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    
    sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    # Attack Detection Rate & False Alarm Rate
    attack_detection_rate = sensitivity
    false_alarm_rate = fpr

    # ROC-AUC and PR-AUC
    roc_auc = 0.5
    pr_auc = 0.0
    if y_prob is not None:
        try:
            # Handle 1D or 2D probabilities
            prob_positive = y_prob[:, 1] if len(y_prob.shape) > 1 and y_prob.shape[1] > 1 else y_prob.ravel()
            roc_auc = float(roc_auc_score(y_true, prob_positive))
            pr_auc = float(average_precision_score(y_true, prob_positive))
        except Exception:
            pass

    n_samples = len(y_true)
    latency_per_sample_ms = (inference_time_sec / max(1, n_samples)) * 1000.0
    throughput_eps = n_samples / max(0.0001, inference_time_sec)

    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "macro_precision": float(macro_prec),
        "macro_recall": float(macro_rec),
        "macro_f1": float(macro_f1),
        "weighted_precision": float(weighted_prec),
        "weighted_recall": float(weighted_rec),
        "weighted_f1": float(weighted_f1),
        "sensitivity": float(sensitivity),
        "specificity": float(specificity),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "mcc": float(mcc),
        "cohen_kappa": float(kappa),
        "roc_auc": float(roc_auc),
        "pr_auc": float(pr_auc),
        "attack_detection_rate": float(attack_detection_rate),
        "false_alarm_rate": float(false_alarm_rate),
        "confusion_matrix": cm.tolist(),
        "tp": int(tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "inference_latency_ms": round(latency_per_sample_ms, 4),
        "throughput_eps": round(throughput_eps, 1),
        "training_time_sec": round(train_time_sec, 3)
    }


def evaluate_multiclass(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    classes: List[str],
    y_prob: Optional[np.ndarray] = None,
    inference_time_sec: float = 0.0,
    train_time_sec: float = 0.0
) -> Dict[str, Any]:
    """
    Computes comprehensive multiclass metrics across all 15 Edge-IIoTset classes.
    """
    acc = accuracy_score(y_true, y_pred)
    macro_prec = precision_score(y_true, y_pred, average="macro", zero_division=0)
    macro_rec = recall_score(y_true, y_pred, average="macro", zero_division=0)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    
    weighted_prec = precision_score(y_true, y_pred, average="weighted", zero_division=0)
    weighted_rec = recall_score(y_true, y_pred, average="weighted", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    
    mcc = matthews_corrcoef(y_true, y_pred)
    kappa = cohen_kappa_score(y_true, y_pred)

    cm = confusion_matrix(y_true, y_pred, labels=list(range(len(classes))))
    norm_cm = cm.astype('float') / cm.sum(axis=1, keepdims=True)
    norm_cm = np.nan_to_num(norm_cm)

    # Per-class precision, recall, f1, support
    prec_per_class = precision_score(y_true, y_pred, average=None, zero_division=0)
    rec_per_class = recall_score(y_true, y_pred, average=None, zero_division=0)
    f1_per_class = f1_score(y_true, y_pred, average=None, zero_division=0)
    
    per_class_metrics = []
    for i, cls_name in enumerate(classes):
        support = int((y_true == i).sum())
        per_class_metrics.append({
            "class": cls_name,
            "precision": round(float(prec_per_class[i]), 4),
            "recall": round(float(rec_per_class[i]), 4),
            "f1": round(float(f1_per_class[i]), 4),
            "support": support
        })

    # Multiclass ROC-AUC OvR
    roc_auc_ovr = 0.5
    if y_prob is not None and y_prob.shape[1] == len(classes):
        try:
            roc_auc_ovr = float(roc_auc_score(y_true, y_prob, multi_class="ovr", average="macro"))
        except Exception:
            pass

    n_samples = len(y_true)
    latency_per_sample_ms = (inference_time_sec / max(1, n_samples)) * 1000.0
    throughput_eps = n_samples / max(0.0001, inference_time_sec)

    return {
        "accuracy": float(acc),
        "macro_precision": float(macro_prec),
        "macro_recall": float(macro_rec),
        "macro_f1": float(macro_f1),
        "weighted_precision": float(weighted_prec),
        "weighted_recall": float(weighted_rec),
        "weighted_f1": float(weighted_f1),
        "mcc": float(mcc),
        "cohen_kappa": float(kappa),
        "roc_auc_ovr": float(roc_auc_ovr),
        "per_class_metrics": per_class_metrics,
        "confusion_matrix": cm.tolist(),
        "normalized_confusion_matrix": norm_cm.tolist(),
        "classes": classes,
        "inference_latency_ms": round(latency_per_sample_ms, 4),
        "throughput_eps": round(throughput_eps, 1),
        "training_time_sec": round(train_time_sec, 3)
    }
