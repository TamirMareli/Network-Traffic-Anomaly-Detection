import streamlit as st
import pandas as pd
import joblib
import json
import plotly.express as px
from pathlib import Path
import numpy as np
import time
import datetime
from collections import deque
from scapy.all import sniff, IP, TCP, UDP, ICMP
import requests
import os

# ==========================================
# 1. PAGE CONFIGURATION
# ==========================================
st.set_page_config(
    page_title="SentinelAI | Advanced IDS",
    page_icon="🛡️",
    layout="wide"
)

# ==========================================
# 2. TELEGRAM CONFIG (ENV VARS)
# ==========================================
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

def send_telegram_alert(risk, proto, src_ip):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    msg = (
        f"🚨 *SECURITY ALERT*\n\n"
        f"Risk: {risk:.1%}\n"
        f"Protocol: {proto}\n"
        f"Source IP: {src_ip}"
    )
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    try:
        requests.get(url, params={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": msg,
            "parse_mode": "Markdown"
        }, timeout=3)
    except Exception:
        pass

# ==========================================
# SAFE TRANSFORMER (REQUIRED FOR MODEL LOAD)
# ==========================================
def safe_log1p(x):
    # Must exist for unpickling the trained model
    return np.log1p(np.abs(x))

# ==========================================
# 3. LOAD SYSTEM FILES
# ==========================================
def get_root():
    p = Path(__file__).resolve().parent
    for _ in range(6):
        if (p / "results").exists():
            return p
        p = p.parent
    return Path(__file__).resolve().parent

ROOT = get_root()

FILES = {
    "binary": ROOT / "results/models/binary_model.pkl",
    "schema": ROOT / "data/processed/realtime_schema.json"
}

@st.cache_resource
def load_system():
    sys = {}
    sys["model"] = joblib.load(FILES["binary"])
    with open(FILES["schema"], "r", encoding="utf-8") as f:
        sys["schema"] = json.load(f)
    return sys

system = load_system()
RAW_COLUMNS = system["schema"]["raw_feature_columns"]

# ==========================================
# 4. FLOW HELPERS
# ==========================================
def infer_service(dport, proto):
    if proto == "tcp":
        return {
            80: "http", 443: "https", 22: "ssh",
            21: "ftp", 25: "smtp", 110: "pop_3"
        }.get(int(dport), "private")
    if proto == "udp" and int(dport) == 53:
        return "domain_u"
    return "private"

def new_flow(t0, proto, service):
    return {
        "start": t0,
        "last": t0,
        "proto": proto,
        "service": service,
        "src_bytes": 0,
        "dst_bytes": 0,
        "syn": 0,
        "ack": 0,
        "rst": 0,
        "pkt_count": 0
    }


# ==========================================
# 5. PACKET ENGINE
# ==========================================
FLOW_TIMEOUT = 10.0
flows = {}
recent_conns = deque(maxlen=200)

def process_packet(pkt):
    if IP not in pkt:
        return None

    now = time.time()
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    proto, sport, dport = None, 0, 0
    if TCP in pkt:
        proto = "tcp"
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
    elif UDP in pkt:
        proto = "udp"
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
    elif ICMP in pkt:
        proto = "icmp"
    else:
        return None

    service = infer_service(dport, proto)
    key = (src_ip, dst_ip, sport, dport, proto)

    if key not in flows:
        flows[key] = new_flow(now, proto, service)
        recent_conns.append({"dst": dst_ip, "service": service})

    stf = flows[key]
    stf["last"] = now
    stf["src_bytes"] += len(pkt)
    stf["pkt_count"] += 1


    if proto == "tcp":
        flags = str(pkt[TCP].flags)
        stf["syn"] += int("S" in flags)
        stf["ack"] += int("A" in flags)
        stf["rst"] += int("R" in flags)


    duration = stf["last"] - stf["start"]

    dst_window = [c for c in recent_conns if c["dst"] == dst_ip]
    dst_count = len(dst_window)
    dst_srv_count = sum(1 for c in dst_window if c["service"] == service)
    same_srv_rate = dst_srv_count / dst_count if dst_count else 0.0
    dst_host_same_srv_rate = same_srv_rate
    dst_host_diff_srv_rate = 1.0 - same_srv_rate

    serror_rate = stf["syn"] / stf["pkt_count"] if stf["pkt_count"] else 0.0
    srv_serror_rate = serror_rate
    rerror_rate = stf["rst"] / stf["pkt_count"] if stf["pkt_count"] else 0.0

    src_bytes_rate = stf["src_bytes"] / duration if duration > 0 else 0.0
    connections_per_sec = dst_count / duration if duration > 0 else 0.0

    flag = "SF" if stf["ack"] > 0 else "S0"

    features = {
        "duration": float(duration),
        "protocol_type": proto,
        "service": service,
        "flag": flag,
        "src_bytes": float(stf["src_bytes"]),
        "dst_bytes": float(stf["dst_bytes"]),

        "count": float(dst_count),
        "srv_count": float(dst_srv_count),
        "same_srv_rate": float(same_srv_rate),

        "dst_host_count": float(dst_count),
        "dst_host_srv_count": float(dst_srv_count),
        "dst_host_same_srv_rate": float(dst_host_same_srv_rate),
        "dst_host_diff_srv_rate": float(dst_host_diff_srv_rate),

        "serror_rate": float(serror_rate),
        "srv_serror_rate": float(srv_serror_rate),
        "rerror_rate": float(rerror_rate),

        "src_bytes_rate": float(src_bytes_rate),
        "connections_per_sec": float(connections_per_sec),
    }


    expired = [k for k, v in flows.items() if now - v["last"] > FLOW_TIMEOUT]
    for k in expired:
        flows.pop(k, None)

    return features, src_ip

# ==========================================
# 6. STREAMLIT UI
# ==========================================
def main():
    # Persistent history & Telegram rate-limit state
    if "history" not in st.session_state:
        st.session_state.history = deque(maxlen=200)
    if "last_alert_ts" not in st.session_state:
        st.session_state.last_alert_ts = 0.0

    st.sidebar.title("🎛️ Control Panel")
    run = st.sidebar.toggle("Start Monitoring", value=False)
    threshold = st.sidebar.slider("Alert Threshold", 0.50, 0.99, 0.90, 0.01)
    telegram = st.sidebar.checkbox("Telegram Alerts", True)
    udp_filter = st.sidebar.checkbox("Smart UDP Filter", True)
    warmup_packets = st.sidebar.number_input("Warm-up packets", min_value=0, max_value=200, value=15, step=1)

    st.title("🛡️ SentinelAI – Real-Time IDS")

    k1, k2, k3 = st.columns(3)
    kpi_status = k1.empty()
    kpi_risk = k2.empty()
    kpi_proto = k3.empty()

    chart_ph = st.empty()
    log_ph = st.empty()

    if run:
        while True:
            packets = sniff(count=1, timeout=0.2)
            if not packets:
                time.sleep(0.01)
                continue

            res = process_packet(packets[0])
            if not res:
                continue

            feat, src_ip = res

            # Build row with all expected columns
            row = pd.DataFrame(0.0, index=[0], columns=RAW_COLUMNS)

            for k, v in feat.items():
                if k in row.columns:
                    row[k] = v

            # Predict
            try:
                prob = float(system["model"].predict_proba(row)[0][1])
            except Exception:
                prob = 0.0
            non_zero_features = int((row.values != 0).sum())
            st.metric("Active Features", f"{non_zero_features}/{len(row.columns)}")

            # Warm-up guard (before deciding attack)
            if len(recent_conns) < int(warmup_packets):
                prob = 0.0

            # Smart filter for UDP noise
            if udp_filter and feat["protocol_type"] == "udp" and prob < 0.95:
                prob = 0.1

            is_attack = prob > threshold

            # Telegram rate-limit: one alert per 10 seconds
            if is_attack and telegram:
                now_ts = time.time()
                if now_ts - st.session_state.last_alert_ts > 10:
                    send_telegram_alert(prob, feat["protocol_type"], src_ip)
                    st.session_state.last_alert_ts = now_ts

            # Append to history
            st.session_state.history.append({
                "Time": datetime.datetime.now().strftime("%H:%M:%S"),
                "Risk": prob,
                "Protocol": feat["protocol_type"],
                "Bytes": feat["src_bytes"],
                "Status": "ATTACK" if is_attack else "OK",
                "SrcIP": src_ip
            })

            # KPIs
            kpi_status.metric("Status", "🚨 ATTACK" if is_attack else "✅ OK")
            kpi_risk.metric("Attack Probability", f"{prob:.1%}")
            kpi_proto.metric("Protocol", feat["protocol_type"].upper())

            # Chart (guard empty)
            df = pd.DataFrame(st.session_state.history)
            if not df.empty:
                fig = px.area(df, x="Time", y="Risk")
                fig.update_layout(yaxis_range=[0, 1])
                chart_ph.plotly_chart(fig, use_container_width=True)
            else:
                chart_ph.info("Waiting for traffic data...")

            # Log table
            log_df = df[["Time", "Risk", "Protocol", "Bytes", "Status", "SrcIP"]].copy()
            log_ph.dataframe(log_df.sort_index(ascending=False).head(15), use_container_width=True)

            time.sleep(0.05)
    else:
        st.info("System standby. Turn on 'Start Monitoring' in the sidebar.")

if __name__ == "__main__":
    main()
