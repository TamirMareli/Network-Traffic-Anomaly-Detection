import numpy as np

def safe_log1p(X):
    return np.log1p(np.clip(X, a_min=0, a_max=None))
