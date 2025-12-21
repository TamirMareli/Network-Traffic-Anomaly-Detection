import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional


class FeatureExtractor:
    """
    Converts a raw sample (from simulator or live capture) into a single-row
    DataFrame matching the NSL-KDD raw feature schema expected by the preprocessor.
    """

    CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

    def __init__(self, expected_columns: Optional[List[str]] = None):
        self.expected_columns = expected_columns or [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
            'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
            'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
            'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
            'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
            'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
            'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate'
        ]

        self.numeric_cols = [c for c in self.expected_columns if c not in self.CATEGORICAL_COLS]

    def process_sample(self, raw_sample: Dict[str, Any], strict: bool = False) -> pd.DataFrame:
        """
        raw_sample: dict with raw feature values (may include extra keys).
        strict: if True, raises if any expected column is missing in raw_sample.
        """
        if not isinstance(raw_sample, dict):
            raise TypeError("raw_sample must be a dict")

        missing = [c for c in self.expected_columns if c not in raw_sample]
        extra = [k for k in raw_sample.keys() if k not in self.expected_columns]

        if strict and missing:
            raise ValueError(f"Missing expected keys: {missing}")

        if extra:
            # Not an error; just useful debug info
            # You can later route this to logger instead of print
            print(f"[i] Ignoring extra keys: {extra[:10]}" + ("..." if len(extra) > 10 else ""))

        df = pd.DataFrame([raw_sample])

        # Keep only expected columns, fill missing
        df = df.reindex(columns=self.expected_columns)

        # Fill missing categoricals with 'unknown' (safer than "0")
        for c in self.CATEGORICAL_COLS:
            df[c] = df[c].fillna("unknown").astype(str)

        # Convert numerics
        for c in self.numeric_cols:
            df[c] = pd.to_numeric(df[c], errors="coerce")

        # Fill NaNs in numerics with 0
        df[self.numeric_cols] = df[self.numeric_cols].fillna(0)

        # Normalize boolean-like columns to 0/1 if they exist
        boolish = ["land", "logged_in", "root_shell", "is_host_login", "is_guest_login"]
        for c in boolish:
            if c in df.columns:
                df[c] = df[c].apply(self._to_01)

        # Optional: clamp known rate features to [0,1] to avoid weird upstream bugs
        rate_cols = [c for c in df.columns if c.endswith("_rate")]
        df[rate_cols] = df[rate_cols].clip(lower=0, upper=1)

        return df

    @staticmethod
    def _to_01(x: Any) -> int:
        if isinstance(x, (int, np.integer)):
            return int(1 if x != 0 else 0)
        if isinstance(x, (float, np.floating)):
            return int(1 if x != 0.0 else 0)
        s = str(x).strip().lower()
        if s in {"1", "true", "yes", "y", "t"}:
            return 1
        if s in {"0", "false", "no", "n", "f", "", "none", "nan"}:
            return 0
        # fallback: treat unknown as 0
        return 0

    def _calculate_derived_features(self, packet_history: List[Any]):
        """
        Placeholder for live Scapy features (count, srv_count, etc.)
        """
        pass
