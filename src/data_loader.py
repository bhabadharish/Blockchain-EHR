"""
Dataset Discovery, Validation, Health Scoring, Extraction, and Sampling Engine.
Part of the PhD Research Platform for Edge-IIoT IDS with Blockchain & Quantum Security.
"""

import os
import glob
import zipfile
import hashlib
import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any, List, Optional
from src.utils import load_config, set_seed


class DataLoader:
    """
    Intelligent Data Loader for Edge-IIoTset datasets.
    Handles discovery, extraction from zip, schema validation, health scoring,
    sampling, and high-performance Parquet caching.
    """

    def __init__(self, config_path: str = "config.yaml"):
        self.config = load_config(config_path)
        self.raw_zip = self.config["dataset"]["raw_zip"]
        self.extracted_csv = self.config["dataset"]["extracted_csv"]
        self.cache_parquet = self.config["dataset"]["cache_parquet"]
        self.binary_target = self.config["dataset"]["target_col_binary"]
        self.multiclass_target = self.config["dataset"]["target_col_multiclass"]
        self.seed = self.config["system"]["random_seed"]

    def discover_datasets(self, root_dir: str = ".") -> List[Dict[str, Any]]:
        """
        Recursively discovers all candidate dataset files in the project.
        Evaluates size, format, and Edge-IIoTset schema markers.
        """
        candidates = []
        extensions = ["*.csv", "*.parquet", "*.zip"]
        for ext in extensions:
            for filepath in glob.glob(os.path.join(root_dir, "**", ext), recursive=True):
                # Ignore .venv, git, and cache dirs
                if any(x in filepath for x in [".venv", ".git", "__pycache__"]):
                    continue
                size_mb = os.path.getsize(filepath) / (1024 * 1024)
                fname = os.path.basename(filepath)
                is_edge_iiot = any(k in fname.lower() for k in ["edge", "iiot", "attack", "traffic"])
                candidates.append({
                    "path": filepath,
                    "filename": fname,
                    "size_mb": round(size_mb, 2),
                    "extension": ext.replace("*.", ""),
                    "is_edge_iiot_candidate": is_edge_iiot
                })
        return sorted(candidates, key=lambda x: -x["size_mb"])

    def ensure_extracted(self) -> str:
        """
        Ensures the benchmark CSV is extracted from the raw zip archive into data/raw/.
        Returns the absolute path to the ready CSV file.
        """
        if os.path.exists(self.extracted_csv):
            return self.extracted_csv
        
        os.makedirs(os.path.dirname(self.extracted_csv), exist_ok=True)
        zip_path = self.raw_zip
        if not os.path.exists(zip_path):
            # Check parent directories
            alt_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), zip_path)
            if os.path.exists(alt_path):
                zip_path = alt_path
            elif os.path.exists(self.cache_parquet.replace(".parquet", "_demo.parquet")):
                # Fallback to reconstructing extracted CSV from committed sampled parquet in CI/clean-clone environments
                df_demo = pd.read_parquet(self.cache_parquet.replace(".parquet", "_demo.parquet"))
                df_demo.to_csv(self.extracted_csv, index=False)
                return self.extracted_csv
            elif os.path.exists(self.cache_parquet):
                df_cache = pd.read_parquet(self.cache_parquet)
                df_cache.to_csv(self.extracted_csv, index=False)
                return self.extracted_csv
            elif os.path.exists("artifacts/demo/live_samples.csv"):
                df_live = pd.read_csv("artifacts/demo/live_samples.csv")
                df_live.to_csv(self.extracted_csv, index=False)
                return self.extracted_csv
            else:
                raise FileNotFoundError(f"Raw dataset zip not found at {self.raw_zip}")

        target_member = self.config["dataset"]["target_csv_in_zip"]
        with zipfile.ZipFile(zip_path, "r") as zf:
            # Locate target member or fallback to any ML-EdgeIIoT-dataset.csv
            found_member = None
            for name in zf.namelist():
                if "ML-EdgeIIoT-dataset.csv" in name:
                    found_member = name
                    break
            if not found_member:
                found_member = target_member
            
            with zf.open(found_member) as source, open(self.extracted_csv, "wb") as target:
                target.write(source.read())

        return self.extracted_csv

    def load_raw_data(self, sample_mode: Optional[str] = None) -> pd.DataFrame:
        """
        Loads dataset with sampling controls and caching:
        - 'demo': ~25,000 stratified samples (sub-second loading and rapid iteration)
        - 'research': ~100,000 stratified samples
        - 'full': entire dataset (157,800 rows)
        """
        mode = sample_mode or self.config["dataset"]["sample_mode"]
        cache_path = self.cache_parquet.replace(".parquet", f"_{mode}.parquet")

        if os.path.exists(cache_path):
            return pd.read_parquet(cache_path)

        csv_path = self.ensure_extracted()
        df = pd.read_csv(csv_path, low_memory=False)

        # Apply sampling if not full
        if mode == "demo":
            n_samples = min(self.config["dataset"]["demo_size"], len(df))
            df = self._stratified_sample(df, n_samples)
        elif mode == "research":
            n_samples = min(self.config["dataset"]["research_size"], len(df))
            df = self._stratified_sample(df, n_samples)

        # Cache to parquet for fast subsequent loads
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        df.to_parquet(cache_path, index=False)
        return df

    def _stratified_sample(self, df: pd.DataFrame, n: int) -> pd.DataFrame:
        """Helper to sample proportionally across multiclass Attack_type without column loss."""
        if self.multiclass_target not in df.columns or n >= len(df):
            return df.sample(n=min(n, len(df)), random_state=self.seed).reset_index(drop=True)
        
        from sklearn.model_selection import train_test_split
        sampled, _ = train_test_split(
            df, 
            train_size=n, 
            stratify=df[self.multiclass_target], 
            random_state=self.seed
        )
        return sampled.reset_index(drop=True)

    def calculate_dataset_hash(self, filepath: Optional[str] = None) -> str:
        """Computes SHA-256 integrity hash of the underlying raw dataset."""
        target = filepath or self.ensure_extracted()
        sha256 = hashlib.sha256()
        with open(target, "rb") as f:
            while chunk := f.read(1024 * 1024):
                sha256.update(chunk)
        return sha256.hexdigest()

    def inspect_health(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Computes the comprehensive Research Dataset Health Score and audit metrics.
        Returns health score (0-100), missing counts, duplicates, data types, and imbalance ratios.
        """
        total_rows = len(df)
        total_cols = len(df.columns)
        
        # Missing values
        missing_count = int(df.isnull().sum().sum())
        missing_pct = round((missing_count / (total_rows * total_cols)) * 100, 3)
        
        # Duplicate rows
        duplicate_count = int(df.duplicated().sum())
        duplicate_pct = round((duplicate_count / total_rows) * 100, 3)
        
        # Infinite values
        num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        inf_count = int(np.isinf(df[num_cols]).sum().sum()) if len(num_cols) > 0 else 0
        inf_pct = round((inf_count / (total_rows * max(1, len(num_cols)))) * 100, 3)
        
        # Constant features
        constant_cols = [col for col in df.columns if df[col].nunique() <= 1]
        
        # Categorical vs Numerical
        cat_cols = df.select_dtypes(exclude=[np.number]).columns.tolist()
        
        # Class Imbalance
        binary_counts = df[self.binary_target].value_counts().to_dict() if self.binary_target in df.columns else {}
        multiclass_counts = df[self.multiclass_target].value_counts().to_dict() if self.multiclass_target in df.columns else {}
        
        imbalance_ratio = 1.0
        if len(binary_counts) >= 2:
            vals = list(binary_counts.values())
            imbalance_ratio = round(max(vals) / max(1, min(vals)), 2)

        # Health Score deduction logic
        health_score = 100.0
        health_score -= min(30.0, missing_pct * 10)
        health_score -= min(20.0, duplicate_pct * 2)
        health_score -= min(20.0, inf_pct * 10)
        health_score -= min(15.0, len(constant_cols) * 2)
        health_score = max(0.0, round(health_score, 1))

        # Memory usage
        memory_mb = round(df.memory_usage(deep=True).sum() / (1024 * 1024), 2)

        return {
            "total_rows": total_rows,
            "total_columns": total_cols,
            "numerical_features_count": len(num_cols),
            "categorical_features_count": len(cat_cols),
            "missing_values_count": missing_count,
            "missing_pct": missing_pct,
            "duplicate_rows_count": duplicate_count,
            "duplicate_pct": duplicate_pct,
            "infinite_values_count": inf_count,
            "infinite_pct": inf_pct,
            "constant_features": constant_cols,
            "memory_footprint_mb": memory_mb,
            "binary_distribution": binary_counts,
            "multiclass_distribution": multiclass_counts,
            "binary_imbalance_ratio": imbalance_ratio,
            "health_score": health_score,
            "status": "HEALTHY" if health_score >= 80 else "MODERATE" if health_score >= 60 else "DEGRADED"
        }
