import time
from pathlib import Path
from typing import Dict, Iterator, Any

# Zeek conn.log standard column order (TSV)
ZEEK_CONN_FIELDS = [
    "ts", "uid",
    "id.orig_h", "id.orig_p",
    "id.resp_h", "id.resp_p",
    "proto", "service",
    "duration",
    "orig_bytes", "resp_bytes",
    "conn_state",
    "local_orig", "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts", "orig_ip_bytes",
    "resp_pkts", "resp_ip_bytes",
    "tunnel_parents",
    "orig_l2_addr"
]

def follow(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)  # tail -f behavior
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.05)
                continue
            yield line

def read_conn_events(conn_log_path: str) -> Iterator[Dict[str, Any]]:
    path = Path(conn_log_path)

    for raw in follow(path):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split("\t")
        if len(parts) < len(ZEEK_CONN_FIELDS):
            continue

        evt = dict(zip(ZEEK_CONN_FIELDS, parts))
        yield evt
