# pipeline_utils.py


import pandas as pd
import numpy as np


LOG_COLS_DEFAULT = ["src_bytes", "dst_bytes", "duration", "hot", "num_compromised"]

def safe_log1p(df: pd.DataFrame, log_cols=LOG_COLS_DEFAULT) -> pd.DataFrame:
    df_out = df.copy()
    for c in log_cols:
        if c in df_out.columns:
            df_out[c] = np.log1p(pd.to_numeric(df_out[c], errors="coerce").fillna(0).clip(lower=0))
    return df_out