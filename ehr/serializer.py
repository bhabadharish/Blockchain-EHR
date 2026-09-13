"""
ehr/serializer.py
Canonical EHR Serialization & Information Entropy Estimation.
Provides deterministic serialization for cryptographic hashing and measures Shannon entropy.
"""

import json
import math
import collections
import pandas as pd
from typing import Dict, Any, Union


class EHRSerializer:
    """Handles deterministic serialization and analytical entropy measurement for EHR payloads."""

    @staticmethod
    def to_canonical_json(data: Union[Dict[str, Any], list]) -> str:
        """Serializes data into sorted, deterministic JSON format."""
        return json.dumps(data, sort_keys=True, separators=(',', ':'), default=str)

    @staticmethod
    def to_canonical_bytes(data: Union[Dict[str, Any], list, str, bytes, pd.DataFrame]) -> bytes:
        """Converts any structured EHR payload into canonical UTF-8 bytes."""
        if isinstance(data, bytes):
            return data
        elif isinstance(data, str):
            return data.encode("utf-8")
        elif isinstance(data, pd.DataFrame):
            return data.to_csv(index=False).encode("utf-8")
        else:
            return EHRSerializer.to_canonical_json(data).encode("utf-8")

    @staticmethod
    def calculate_shannon_entropy(data_bytes: bytes) -> float:
        """
        Calculates Shannon entropy in bits per byte:
        H = - sum(p * log2(p)).
        Theoretical range: 0.0 (constant byte) to 8.0 (ideal uniformly random ciphertext).
        """
        if not data_bytes:
            return 0.0

        length = len(data_bytes)
        counts = collections.Counter(data_bytes)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def to_canonical_json_bytes(data: Union[Dict[str, Any], list, str, bytes, pd.DataFrame]) -> bytes:
        """Alias for to_canonical_bytes."""
        return EHRSerializer.to_canonical_bytes(data)

    @staticmethod
    def compute_entropy(data_bytes: bytes) -> float:
        """Alias for calculate_shannon_entropy."""
        return EHRSerializer.calculate_shannon_entropy(data_bytes)
