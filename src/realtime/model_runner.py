import sys
from pathlib import Path

# Always anchor paths to the file location (works on Windows + WSL)
PROJECT_ROOT = Path(__file__).resolve().parents[2]   # .../Network-Traffic-Anomaly-Detection
REALTIME_DIR = Path(__file__).resolve().parent       # .../src/realtime

for p in (PROJECT_ROOT, REALTIME_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import json
import joblib
import pandas as pd

from zeek_reader import read_conn_events
from feature_builder import build_model_input_row

def load_required_columns(models_dir: Path) -> list[str]:
    """
    We rely on model_metadata.json created in your training notebook.
    It should include a list of feature columns.
    If key differs in your project, adjust here once.
    """
    meta_path = models_dir / "model_metadata.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))

    # common options (בחרנו fallbackים בלי לשאול אותך)
    for key in ["feature_columns", "X_columns", "columns", "model_input_columns"]:
        if key in meta and isinstance(meta[key], list):
            return meta[key]

    raise KeyError("Could not find feature columns list in model_metadata.json")


def normalize_wsl_path(p: str) -> str:
    # Convert Windows path (C:\...) to WSL path (/mnt/c/...)
    if len(p) >= 3 and p[1] == ":":
        drive = p[0].lower()
        rest = p[2:].replace("\\", "/")
        return f"/mnt/{drive}{rest}"
    return p


def run_realtime(conn_log_path: str, project_root: str, threshold: float = 0.5):
    conn_log_path = normalize_wsl_path(conn_log_path)
    print("[✓] Normalized path:", conn_log_path)

    project_root = Path(project_root).resolve()
    models_dir = project_root / "results" / "models"
    out_dir = project_root / "results" / "realtime"
    out_dir.mkdir(parents=True, exist_ok=True)

    binary_model = joblib.load(models_dir / "binary_model.pkl")
    multi_model = joblib.load(models_dir / "multi_model.pkl")
    required_cols = load_required_columns(models_dir)

    alerts_path = out_dir / "alerts.jsonl"

    print("[✓] Loaded models.")
    print("[✓] Reading:", conn_log_path)
    print("[✓] Writing alerts to:", alerts_path)

    with alerts_path.open("a", encoding="utf-8") as f_out:
        for evt in read_conn_events(conn_log_path):
            x = build_model_input_row(evt, required_cols)

            # predict proba
            proba = float(binary_model.predict_proba(x)[:, 1][0])
            is_attack = proba >= threshold

            alert = {
                "ts": evt.get("ts"),
                "uid": evt.get("uid"),
                "orig_h": evt.get("id.orig_h"),
                "resp_h": evt.get("id.resp_h"),
                "resp_p": evt.get("id.resp_p"),
                "proto": evt.get("proto"),
                "conn_state": evt.get("conn_state"),
                "proba_attack": proba,
                "is_attack": int(is_attack),
            }

            if is_attack:
                # multiclass on the same row/pipeline (לפי איך שמימשתם)
                try:
                    mc = multi_model.predict(x)[0]
                    alert["attack_type"] = str(mc)
                except Exception:
                    alert["attack_type"] = "unknown"
                    
            alert["note"] = "attack" if is_attack else "normal"
            f_out.write(json.dumps(alert) + "\n")
            f_out.flush()

            if is_attack:
                print("[ALERT]", alert)

if __name__ == "__main__":
    PROJECT_ROOT = Path(__file__).resolve().parents[2]
    run_realtime(
        conn_log_path=r"C:\\Users\\elair\\zeek_logs\\conn.log",
        project_root=str(PROJECT_ROOT),
        threshold=0.5,
    )

