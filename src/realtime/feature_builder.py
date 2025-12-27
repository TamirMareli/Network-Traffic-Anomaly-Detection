from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Any
import pandas as pd

# Mapping Zeek conn_state -> NSL-KDD flag (ברוב המקרים אותו שם)
_ZEEK_TO_NSL_FLAG = {
    "SF": "SF", "S0": "S0", "REJ": "REJ", "S1": "S1", "S2": "S2", "S3": "S3",
    "RSTO": "RSTO", "RSTR": "RSTR", "SH": "SH", "OTH": "OTH",
    "RSTOS0": "RSTO", "RSTRH": "RSTR", "SHR": "SH",
}

# Minimal port->service mapping (אפשר להרחיב)
_PORT_TO_SERVICE = {
    80: "http",
    443: "http",     # בקירוב (NSL יש https לפעמים לא מופיע; נשאיר http)
    53: "domain",
    22: "ssh",
    21: "ftp",
    20: "ftp_data",
    25: "smtp",
    110: "pop_3",
    143: "imap4",
    23: "telnet",
}

@dataclass
class NslKddRow:
    duration: float
    protocol_type: str
    service: str
    flag: str
    src_bytes: float
    dst_bytes: float
    land: int

def _get(d: Dict[str, Any], key: str, default=None):
    # Zeek JSON keys like "id.orig_h" vs parsed TSV keys same
    return d.get(key, default)

def zeek_conn_to_nsl_basic(evt: Dict[str, Any]) -> NslKddRow:
    # duration
    duration = float(_get(evt, "duration", 0.0) or 0.0)

    # protocol
    proto = str(_get(evt, "proto", "tcp") or "tcp").lower()
    protocol_type = proto

    # bytes
    # Zeek JSON often: orig_bytes / resp_bytes (may be "-")
    def to_float(x):
        if x is None:
            return 0.0
        if isinstance(x, (int, float)):
            return float(x)
        x = str(x)
        return 0.0 if x in ("-", "", "nan", "NaN") else float(x)

    src_bytes = to_float(_get(evt, "orig_bytes", 0.0))
    dst_bytes = to_float(_get(evt, "resp_bytes", 0.0))

    # flag from conn_state
    conn_state = str(_get(evt, "conn_state", "OTH") or "OTH")
    flag = _ZEEK_TO_NSL_FLAG.get(conn_state, "OTH")

    # service: prefer Zeek's service, else map by dst port
    service = _get(evt, "service", None)
    if service in (None, "-", ""):
        resp_p = _get(evt, "id.resp_p", None)
        try:
            resp_p = int(resp_p) if resp_p not in (None, "-", "") else None
        except ValueError:
            resp_p = None
        service = _PORT_TO_SERVICE.get(resp_p, "other")
    service = str(service)

    # land
    orig_h = _get(evt, "id.orig_h", "")
    resp_h = _get(evt, "id.resp_h", "")
    orig_p = _get(evt, "id.orig_p", "")
    resp_p = _get(evt, "id.resp_p", "")
    land = int((str(orig_h) == str(resp_h)) and (str(orig_p) == str(resp_p)))

    return NslKddRow(
        duration=duration,
        protocol_type=protocol_type,
        service=service,
        flag=flag,
        src_bytes=src_bytes,
        dst_bytes=dst_bytes,
        land=land,
    )

def build_model_input_row(evt: Dict[str, Any], required_columns: list[str]) -> pd.DataFrame:
    """
    Creates a 1-row DataFrame with exactly the columns the model expects.
    Missing columns are filled with 0 / defaults.
    """
    basic = zeek_conn_to_nsl_basic(evt)

    row = {c: 0 for c in required_columns}  # default everything to 0
    # fill what we can
    for k, v in {
        "duration": basic.duration,
        "protocol_type": basic.protocol_type,
        "service": basic.service,
        "flag": basic.flag,
        "src_bytes": basic.src_bytes,
        "dst_bytes": basic.dst_bytes,
        "land": basic.land,
    }.items():
        if k in row:
            row[k] = v

    return pd.DataFrame([row], columns=required_columns)
