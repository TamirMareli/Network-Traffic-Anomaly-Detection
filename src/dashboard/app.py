from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import streamlit as st
import time, uuid

# Smooth auto-refresh without full-page meta refresh
from streamlit_autorefresh import st_autorefresh


# -----------------------------
# Paths
# -----------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ALERTS_PATH = PROJECT_ROOT / "results" / "realtime" / "alerts.jsonl"


# -----------------------------
# Styling (professional)
# -----------------------------
def inject_css() -> None:
    st.markdown(
        """
<style>
/* App background + typography */
.block-container { padding-top: 1.2rem; padding-bottom: 2.5rem; }
html, body, [class*="css"] { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; }

/* Header */
.header-wrap {
  display:flex; align-items:center; justify-content:space-between;
  gap: 1rem; margin-bottom: .6rem;
}
.brand {
  display:flex; align-items:center; gap:.7rem;
}
.badge {
  font-size: 0.8rem; padding: .2rem .55rem; border-radius: 999px;
  border: 1px solid rgba(255,255,255,.12);
  background: rgba(255,255,255,.04);
}
.subtle { color: rgba(255,255,255,.68); font-size: .9rem; }

/* Cards */
.kpi-grid { display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .8rem; margin-top: .4rem; }
.card {
  border-radius: 16px;
  padding: 14px 14px 12px 14px;
  background: rgba(255,255,255,.03);
  border: 1px solid rgba(255,255,255,.10);
  box-shadow: 0 8px 30px rgba(0,0,0,.18);
}
.card-title { font-size: .85rem; color: rgba(255,255,255,.62); margin-bottom: .25rem; }
.card-value { font-size: 1.55rem; font-weight: 700; line-height: 1.2; }
.card-foot { font-size: .8rem; color: rgba(255,255,255,.55); margin-top: .25rem; }

/* Section titles */
.section-title { font-size: 1.05rem; font-weight: 650; margin: .2rem 0 .4rem; }
.section-sub { color: rgba(255,255,255,.60); font-size: .88rem; margin-top: -0.1rem; }

/* Table container */
.table-wrap {
  border-radius: 16px;
  padding: 10px 10px 6px 10px;
  background: rgba(255,255,255,.02);
  border: 1px solid rgba(255,255,255,.10);
}

/* Small status pill */
.pill {
  display:inline-flex; align-items:center; gap:.35rem;
  font-size: .8rem;
  padding: .22rem .6rem;
  border-radius: 999px;
  border: 1px solid rgba(255,255,255,.12);
}
.dot { width:8px; height:8px; border-radius: 999px; display:inline-block; }
.dot-ok { background:#39d98a; }
.dot-warn { background:#ffcc00; }
.dot-bad { background:#ff5c5c; }

/* Sidebar */
[data-testid="stSidebar"] { border-right: 1px solid rgba(255,255,255,.08); }
hr { border-color: rgba(255,255,255,.08) !important; }

/* Plotly tweaks */
.js-plotly-plot .plotly .modebar { opacity: 0.2; }
.js-plotly-plot .plotly .modebar:hover { opacity: 1; }

/* Responsive KPI grid */
@media (max-width: 1100px) {
  .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
</style>
        """,
        unsafe_allow_html=True,
    )


# -----------------------------
# Efficient JSONL tail-reader
# -----------------------------
def tail_jsonl(path: Path, max_lines: int = 5000) -> List[Dict[str, Any]]:
    """
    Read last max_lines from a JSONL file efficiently.
    Works well for growing files.
    """
    if not path.exists():
        return []

    # Fast path: file not too big
    try:
        size = path.stat().st_size
    except OSError:
        return []

    # Read from the end in chunks until we have enough lines
    chunk_size = 64 * 1024
    data = b""
    with path.open("rb") as f:
        # Start near the end
        offset = max(size - chunk_size, 0)
        f.seek(offset)
        data = f.read()

        # If not enough newlines, expand backwards
        while data.count(b"\n") < max_lines + 5 and offset > 0:
            new_offset = max(offset - chunk_size, 0)
            f.seek(new_offset)
            data = f.read(offset - new_offset) + data
            offset = new_offset

    lines = data.splitlines()
    if max_lines and len(lines) > max_lines:
        lines = lines[-max_lines:]

    rows: List[Dict[str, Any]] = []
    for ln in lines:
        if not ln:
            continue
        try:
            rows.append(json.loads(ln.decode("utf-8", errors="ignore")))
        except Exception:
            continue
    return rows


def load_df(alerts_path: Path, max_lines: int) -> pd.DataFrame:
    rows = tail_jsonl(alerts_path, max_lines=max_lines)
    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)

    # Normalize columns
    if "ts" in df.columns:
        df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
        df["time"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")

    for col in ["proba_attack", "is_attack"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # Stringify some fields for consistent filtering
    for col in ["orig_h", "resp_h", "proto", "conn_state", "attack_type", "uid"]:
        if col in df.columns:
            df[col] = df[col].astype(str)

    return df


def render_header(file_ok: bool, file_size: int) -> None:
    status = "Live" if file_ok else "Waiting"
    dot_class = "dot-ok" if file_ok else "dot-warn"
    st.markdown(
        f"""
<div class="header-wrap">
  <div class="brand">
    <div style="font-size:1.6rem;">🚨</div>
    <div>
      <div style="font-size:1.55rem; font-weight:800; letter-spacing:-0.02em;">Realtime NIDS Dashboard</div>
      <div class="subtle">Zeek → Feature Builder → ML Inference → Alerts</div>
    </div>
  </div>

  <div style="display:flex; align-items:center; gap:.6rem;">
    <span class="pill"><span class="dot {dot_class}"></span>{status}</span>
    <span class="badge">alerts.jsonl: {file_size:,} bytes</span>
  </div>
</div>
        """,
        unsafe_allow_html=True,
    )


def kpi_cards(
    total: int,
    attacks: int,
    avg_p: float,
    last_uid: str,
    last_seen: str,
) -> None:
    st.markdown(
        f"""
<div class="kpi-grid">
  <div class="card">
    <div class="card-title">Events loaded</div>
    <div class="card-value">{total:,}</div>
    <div class="card-foot">Last window (tail)</div>
  </div>
  <div class="card">
    <div class="card-title">Attacks (flagged)</div>
    <div class="card-value">{attacks:,}</div>
    <div class="card-foot">Based on is_attack field</div>
  </div>
  <div class="card">
    <div class="card-title">Avg P(attack)</div>
    <div class="card-value">{avg_p:.3f}</div>
    <div class="card-foot">Mean probability</div>
  </div>
  <div class="card">
    <div class="card-title">Last event</div>
    <div class="card-value" style="font-size:1.05rem; font-weight:700;">{last_uid}</div>
    <div class="card-foot">{last_seen}</div>
  </div>
</div>
        """,
        unsafe_allow_html=True,
    )


def style_events_table(df: pd.DataFrame) -> pd.io.formats.style.Styler:
    def row_style(row: pd.Series) -> List[str]:
        is_attack = int(row.get("is_attack", 0) or 0)
        p = float(row.get("proba_attack", 0.0) or 0.0)
        if is_attack == 1:
            return ["background-color: rgba(255,92,92,.18)"] * len(row)
        if p >= 0.5:
            return ["background-color: rgba(255,204,0,.14)"] * len(row)
        return [""] * len(row)

    return df.style.apply(row_style, axis=1)


# -----------------------------
# App
# -----------------------------
def main() -> None:
    st.set_page_config(page_title="Realtime NIDS Dashboard", layout="wide")
    inject_css()

    # Sidebar controls
    with st.sidebar:
        st.markdown("## Controls")
        refresh_s = st.slider("Refresh interval (seconds)", 1, 10, 2)
        max_lines = st.number_input("Max events to load", 500, 50000, 5000, step=500)
        st.divider()

        st.markdown("## Filters")
        show_only_attacks = st.checkbox("Show only attacks", value=False)
        min_p = st.slider("Min P(attack)", 0.0, 1.0, 0.0, 0.01)

        st.divider()
        st.markdown("## Demo Mode")

        demo_attack_type = st.selectbox("Demo attack_type", ["dos", "probe", "r2l", "u2r", "unknown"], index=0)
        demo_severity = st.selectbox("Severity", ["low", "medium", "high", "critical"], index=2)
        demo_proba = st.slider("Demo P(attack)", 0.0, 1.0, 0.97, 0.01)

        if st.button("Inject demo alert", use_container_width=True):
            demo = {
                "ts": str(time.time()),
                "uid": f"DEMO_{uuid.uuid4().hex[:10].upper()}",
                "orig_h": "10.0.0.5",
                "resp_h": "10.0.0.1",
                "resp_p": "80",
                "proto": "tcp",
                "conn_state": "S0",
                "proba_attack": float(demo_proba),
                "is_attack": 1,
                "attack_type": demo_attack_type,
                "severity": demo_severity,
                "note": "demo_injected",
            }
            ALERTS_PATH.parent.mkdir(parents=True, exist_ok=True)
            with ALERTS_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(demo) + "\n")
            st.success(f"Injected: {demo['uid']}")
            if st.button("Clear alerts.jsonl", use_container_width=True):
                ALERTS_PATH.write_text("", encoding="utf-8")
                st.success("Cleared alerts.jsonl")

        st.divider()
        st.markdown("## Debug")
        st.caption("Data source")
        st.code(str(ALERTS_PATH), language="text")

    # Smooth refresh (reruns script without ugly full page reload)
    st_autorefresh(interval=int(refresh_s) * 1000, key="nids_refresh")

    file_ok = ALERTS_PATH.exists()
    file_size = ALERTS_PATH.stat().st_size if file_ok else 0

    render_header(file_ok=file_ok, file_size=file_size)

    if not file_ok or file_size == 0:
        st.warning("Waiting for alerts…")
        st.info("Make sure `model_runner.py` is running and writing to results/realtime/alerts.jsonl.")
        return

    df = load_df(ALERTS_PATH, int(max_lines))
    if df.empty:
        st.warning("alerts.jsonl exists but no valid JSON lines were parsed.")
        return

    # Apply filters
    if "proba_attack" in df.columns:
        df = df[df["proba_attack"].fillna(0.0) >= float(min_p)]
    if show_only_attacks and "is_attack" in df.columns:
        df = df[df["is_attack"].fillna(0).astype(int) == 1]

    # Dynamic filter options (only show when column exists)
    with st.sidebar:
        if "proto" in df.columns:
            protos = sorted(df["proto"].dropna().unique().tolist())
            proto_sel = st.multiselect("Protocol", protos, default=[])
        else:
            proto_sel = []

        if "conn_state" in df.columns:
            states = sorted(df["conn_state"].dropna().unique().tolist())
            state_sel = st.multiselect("Conn state", states, default=[])
        else:
            state_sel = []

        resp_port_sel = None
        if "resp_p" in df.columns:
            # sample top ports
            top_ports = (
                df["resp_p"].dropna().astype(str).value_counts().head(15).index.tolist()
            )
            resp_port_sel = st.multiselect("Resp port (top)", top_ports, default=[])

        ip_query = st.text_input("IP contains (orig/resp)", value="").strip()

    if proto_sel and "proto" in df.columns:
        df = df[df["proto"].isin(proto_sel)]
    if state_sel and "conn_state" in df.columns:
        df = df[df["conn_state"].isin(state_sel)]
    if resp_port_sel and "resp_p" in df.columns:
        df = df[df["resp_p"].astype(str).isin(resp_port_sel)]
    if ip_query:
        mask = False
        if "orig_h" in df.columns:
            mask = mask | df["orig_h"].str.contains(ip_query, na=False)
        if "resp_h" in df.columns:
            mask = mask | df["resp_h"].str.contains(ip_query, na=False)
        df = df[mask]

    # KPIs (after filtering)
    total = len(df)
    attacks = int(df["is_attack"].fillna(0).sum()) if "is_attack" in df.columns else 0
    avg_p = float(df["proba_attack"].mean()) if "proba_attack" in df.columns else 0.0

    last_uid = df["uid"].iloc[-1] if "uid" in df.columns and total else "-"
    last_seen = (
        str(df["time"].iloc[-1]) if "time" in df.columns and total else "—"
    )

    kpi_cards(total=total, attacks=attacks, avg_p=avg_p, last_uid=last_uid, last_seen=last_seen)

    st.divider()

    tabs = st.tabs(["Live Feed", "Analytics", "Attack Types"])

    # ---- Live Feed
    with tabs[0]:
        st.markdown('<div class="section-title">Recent events</div>', unsafe_allow_html=True)
        st.markdown('<div class="section-sub">Newest events at the bottom. Rows are highlighted when attack/high-probability.</div>', unsafe_allow_html=True)

        cols = [
            "time", "uid",
            "orig_h", "resp_h", "resp_p",
            "proto", "conn_state",
            "proba_attack", "is_attack", "attack_type",
        ]
        cols = [c for c in cols if c in df.columns]
        view = df[cols].tail(80).copy()

        st.markdown('<div class="table-wrap">', unsafe_allow_html=True)
        st.dataframe(style_events_table(view), use_container_width=True, height=520)
        st.markdown("</div>", unsafe_allow_html=True)

    # ---- Analytics
    with tabs[1]:
        left, right = st.columns([1, 1])

        with left:
            st.markdown('<div class="section-title">Attack probability (last 300 events)</div>', unsafe_allow_html=True)
            plot_df = df.tail(300).copy()
            if "time" in plot_df.columns and "proba_attack" in plot_df.columns:
                fig = px.line(plot_df, x="time", y="proba_attack")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Missing `time` or `proba_attack` columns.")

        with right:
            st.markdown('<div class="section-title">Probability distribution</div>', unsafe_allow_html=True)
            if "proba_attack" in df.columns:
                fig2 = px.histogram(df, x="proba_attack", nbins=30)
                st.plotly_chart(fig2, use_container_width=True)
            else:
                st.info("Missing `proba_attack` column.")

        st.markdown('<div class="section-title">Top talkers</div>', unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        if "orig_h" in df.columns:
            top_orig = df["orig_h"].value_counts().head(10).reset_index()
            top_orig.columns = ["orig_h", "count"]
            with c1:
                st.caption("Top orig_h")
                st.plotly_chart(px.bar(top_orig, x="orig_h", y="count"), use_container_width=True)
        if "resp_h" in df.columns:
            top_resp = df["resp_h"].value_counts().head(10).reset_index()
            top_resp.columns = ["resp_h", "count"]
            with c2:
                st.caption("Top resp_h")
                st.plotly_chart(px.bar(top_resp, x="resp_h", y="count"), use_container_width=True)

    # ---- Attack Types
    with tabs[2]:
        st.markdown('<div class="section-title">Attack type breakdown</div>', unsafe_allow_html=True)
        if "attack_type" in df.columns and df["attack_type"].notna().any():
            vc = df["attack_type"].fillna("unknown").value_counts().reset_index()
            vc.columns = ["attack_type", "count"]
            st.plotly_chart(px.bar(vc, x="attack_type", y="count"), use_container_width=True)
        else:
            st.info("No attack_type values yet (or everything is normal).")

    # Footer small info
    st.caption("Tip: Use filters on the left to slice traffic by protocol / state / ports / IP substring.")


if __name__ == "__main__":
    main()
