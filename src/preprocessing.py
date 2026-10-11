"""
Academic Preprocessing Pipeline for Edge-IIoT Telemetry.
Part of the PhD Research Platform for Edge-IIoT IDS with Blockchain & Quantum Security.
Ensures zero data leakage: all encoders and scalers are fitted EXCLUSIVELY on training data.
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any, List, Optional
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler, LabelEncoder
from src.utils import load_config, set_seed


class PreprocessingPipeline:
    """
    Reproducible preprocessing pipeline with strict leakage isolation.
    Handles cleaning, imputation, categorical encoding, scaling, and train/val/test splitting.
    """

    def __init__(self, config_path: str = "config.yaml"):
        self.config = load_config(config_path)
        self.seed = self.config["system"]["random_seed"]
        self.leakage_cols = self.config["dataset"]["leakage_cols_to_drop"]
        self.binary_target = self.config["dataset"]["target_col_binary"]
        self.multiclass_target = self.config["dataset"]["target_col_multiclass"]
        self.scaler_type = self.config["preprocessing"]["scaler"]
        
        # State containers
        self.scaler = None
        self.label_encoder = None
        self.categorical_encoders: Dict[str, LabelEncoder] = {}
        self.numerical_cols: List[str] = []
        self.categorical_cols: List[str] = []
        self.feature_names: List[str] = []
        self.multiclass_classes: List[str] = []

    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Cleans raw dataframe:
        - Drops exact duplicates
        - Replaces +/- Inf with NaN
        - Imputes numerical NaN with median and categorical with mode
        - Drops designated identifier/temporal leakage columns
        """
        df_clean = df.copy()

        # Remove duplicates
        df_clean = df_clean.drop_duplicates().reset_index(drop=True)

        # Drop identifier and timestamp columns that cause leakage
        cols_to_drop = [c for c in self.leakage_cols if c in df_clean.columns]
        if cols_to_drop:
            df_clean = df_clean.drop(columns=cols_to_drop)

        # Handle Inf / -Inf
        df_clean = df_clean.replace([np.inf, -np.inf], np.nan)

        # Handle NaN values
        for col in df_clean.columns:
            if col in [self.binary_target, self.multiclass_target]:
                continue
            if pd.api.types.is_numeric_dtype(df_clean[col]):
                median_val = df_clean[col].median()
                if pd.isna(median_val):
                    median_val = 0.0
                df_clean[col] = df_clean[col].fillna(median_val)
            else:
                mode_val = df_clean[col].mode()
                fill_val = mode_val[0] if len(mode_val) > 0 else "unknown"
                df_clean[col] = df_clean[col].fillna(fill_val)

        return df_clean

    def prepare_train_test_split(
        self,
        df: pd.DataFrame,
        test_size: float = 0.2,
        val_size: float = 0.1,
        scaler_choice: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Splits data into train, val, test and fits transformers EXCLUSIVELY on training data.
        Returns model-ready matrices: X_train, y_train_bin, y_train_multi, etc.
        """
        set_seed(self.seed)
        df_clean = self.clean_data(df)

        if self.binary_target not in df_clean.columns or self.multiclass_target not in df_clean.columns:
            raise ValueError(f"Targets {self.binary_target} and/or {self.multiclass_target} not found in dataframe.")

        # Separate features and targets
        y_bin = df_clean[self.binary_target].astype(int).values
        y_multi_raw = df_clean[self.multiclass_target].astype(str).values
        X_raw = df_clean.drop(columns=[self.binary_target, self.multiclass_target])

        # Encode multiclass labels
        self.label_encoder = LabelEncoder()
        y_multi = self.label_encoder.fit_transform(y_multi_raw)
        self.multiclass_classes = list(self.label_encoder.classes_)

        # Identify numerical and categorical columns
        self.numerical_cols = [c for c in X_raw.columns if pd.api.types.is_numeric_dtype(X_raw[c])]
        self.categorical_cols = [c for c in X_raw.columns if not pd.api.types.is_numeric_dtype(X_raw[c])]

        # First train / test split
        stratify_key = y_multi
        X_train_raw, X_test_raw, y_train_bin, y_test_bin, y_train_multi, y_test_multi = train_test_split(
            X_raw, y_bin, y_multi, test_size=test_size, random_state=self.seed, stratify=stratify_key
        )

        # Optional validation split
        if val_size > 0:
            val_ratio = val_size / (1.0 - test_size)
            X_train_raw, X_val_raw, y_train_bin, y_val_bin, y_train_multi, y_val_multi = train_test_split(
                X_train_raw, y_train_bin, y_train_multi, test_size=val_ratio, random_state=self.seed, stratify=y_train_multi
            )
        else:
            X_val_raw, y_val_bin, y_val_multi = None, None, None

        # Fit Categorical Encoders ONLY on train
        X_train_encoded = X_train_raw.copy()
        X_test_encoded = X_test_raw.copy()
        X_val_encoded = X_val_raw.copy() if X_val_raw is not None else None

        for cat_col in self.categorical_cols:
            le = LabelEncoder()
            train_vals = X_train_raw[cat_col].astype(str)
            le.fit(train_vals)
            self.categorical_encoders[cat_col] = le

            # Handle unseen labels in test/val by mapping to first class
            def transform_unseen(series: pd.Series, encoder: LabelEncoder) -> np.ndarray:
                classes = set(encoder.classes_)
                safe_series = series.astype(str).map(lambda s: s if s in classes else encoder.classes_[0])
                return encoder.transform(safe_series)

            X_train_encoded[cat_col] = le.transform(train_vals)
            X_test_encoded[cat_col] = transform_unseen(X_test_raw[cat_col], le)
            if X_val_encoded is not None:
                X_val_encoded[cat_col] = transform_unseen(X_val_raw[cat_col], le)

        # Select Scaler
        chosen_scaler = scaler_choice or self.scaler_type
        if chosen_scaler == "minmax":
            self.scaler = MinMaxScaler()
        elif chosen_scaler == "robust":
            self.scaler = RobustScaler()
        else:
            self.scaler = StandardScaler()

        # Fit Scaler ONLY on train
        self.feature_names = list(X_train_encoded.columns)
        X_train_scaled = self.scaler.fit_transform(X_train_encoded)
        X_test_scaled = self.scaler.transform(X_test_encoded)
        X_val_scaled = self.scaler.transform(X_val_encoded) if X_val_encoded is not None else None

        return {
            "X_train": X_train_scaled,
            "y_train_bin": y_train_bin,
            "y_train_multi": y_train_multi,
            "X_val": X_val_scaled,
            "y_val_bin": y_val_bin,
            "y_val_multi": y_val_multi,
            "X_test": X_test_scaled,
            "y_test_bin": y_test_bin,
            "y_test_multi": y_test_multi,
            "feature_names": self.feature_names,
            "classes": self.multiclass_classes,
            "scaler": self.scaler,
            "label_encoder": self.label_encoder,
            "X_train_df": X_train_encoded,
            "X_test_df": X_test_encoded
        }

    def transform(self, df: pd.DataFrame, return_df: bool = True):
        """
        Transforms an arbitrary raw dataframe:
        - Drops leakage and target columns if present
        - Handles NaNs/Infs
        - Encodes categorical columns with saved encoders
        - Aligns feature columns precisely with training order
        - Scales using the training-fitted scaler
        """
        if self.scaler is None:
            raise RuntimeError("Pipeline must be fitted prior to transforming telemetry data.")

        clean_df = df.copy()
        # Drop leakage and target columns
        cols_to_drop = [c for c in (self.leakage_cols + [self.binary_target, self.multiclass_target]) if c in clean_df.columns]
        if cols_to_drop:
            clean_df = clean_df.drop(columns=cols_to_drop)

        # Ensure all training feature names exist
        for col in self.feature_names:
            if col not in clean_df.columns:
                clean_df[col] = 0.0

        clean_df = clean_df[self.feature_names].copy()

        # Handle Infs & NaNs
        clean_df = clean_df.replace([np.inf, -np.inf], np.nan)
        for col in self.feature_names:
            if col in self.categorical_cols:
                clean_df[col] = clean_df[col].fillna("unknown")
            else:
                clean_df[col] = clean_df[col].fillna(0.0)

        # Sanitize numeric fields (RFC options abstraction, payload hex handling, port clipping, log1p)
        if "tcp.srcport" in clean_df.columns:
            clean_df["tcp.srcport"] = pd.to_numeric(clean_df["tcp.srcport"], errors="coerce").fillna(0.0).clip(0, 65535)
        if "tcp.payload" in clean_df.columns:
            clean_df["tcp.payload"] = clean_df["tcp.payload"].astype(str).map(
                lambda s: 0.0 if s in ["0", "0.0", "nan", "", "NULL_ZERO"] else float(len(s))
            )
        if "tcp.options" in clean_df.columns:
            clean_df["tcp.options"] = clean_df["tcp.options"].astype(str).map(
                lambda s: 0.0 if s in ["0", "0.0", "nan", "", "NULL_ZERO"] else float(len(s) // 2)
            )
        for num_c in ["tcp.dstport", "tcp.flags", "tcp.flags.ack", "tcp.checksum"]:
            if num_c in clean_df.columns:
                clean_df[num_c] = pd.to_numeric(clean_df[num_c], errors="coerce").fillna(0.0)
        skew_cols = ["tcp.len", "tcp.seq", "tcp.ack", "tcp.ack_raw", "tcp.payload", "tcp.options"]
        for sc in skew_cols:
            if sc in clean_df.columns:
                clean_df[sc] = np.log1p(np.maximum(0, pd.to_numeric(clean_df[sc], errors="coerce").fillna(0.0).values))

        # Encode categoricals
        for cat_col, encoder in self.categorical_encoders.items():
            if cat_col in clean_df.columns:
                cls_set = set(encoder.classes_)
                
                def _normalize_cat(v, enc=encoder, valid_classes=cls_set):
                    if pd.isna(v):
                        return enc.classes_[0]
                    try:
                        f = float(v)
                        if f.is_integer():
                            s_int = str(int(f))
                            if s_int in valid_classes:
                                return s_int
                    except (ValueError, TypeError):
                        pass
                    s = str(v)
                    if s in valid_classes:
                        return s
                    return enc.classes_[0]

                safe_s = clean_df[cat_col].apply(_normalize_cat)
                clean_df[cat_col] = encoder.transform(safe_s)

        # Scale
        scaled_vals = self.scaler.transform(clean_df)
        if return_df:
            return pd.DataFrame(scaled_vals, columns=self.feature_names)
        return scaled_vals

    def transform_single_record(self, record_dict: Dict[str, Any]) -> np.ndarray:
        """
        Transforms an incoming single live record into the model-ready feature vector.
        Used by the live streaming simulation engine.
        """
        row_df = pd.DataFrame([record_dict])
        return self.transform(row_df, return_df=False)

    def save(self, file_path: str = "artifacts/preprocessing/preprocessor.joblib"):
        """Saves entire pipeline object."""
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        joblib.dump(self, file_path)

    @classmethod
    def load(cls, file_path: str = "artifacts/preprocessing/preprocessor.joblib"):
        """Loads pipeline object."""
        return joblib.load(file_path)

