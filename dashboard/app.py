import streamlit as st
import pandas as pd
import joblib
import json
import plotly.graph_objects as go
import plotly.express as px
from pathlib import Path
import numpy as np
import time
from collections import deque, Counter
from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime

# ==========================================
# 1. CORE CONFIG & STYLING
# ==========================================
st.set_page_config(
    page_title="CyberSentinel PRO",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Professional Dark Mode
st.markdown("""
<style>
    /* Global Theme */
    .stApp { background-color: #0f1116; color: #e6e6e6; }
    
    /* Metrics Styling */
    div[data-testid="metric-container"] {
        background-color: #1e2130;
        border-left: 4px solid #4a90e2;
        padding: 10px 15px;
        border-radius: 6px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    
    /* Buttons */
    .stButton button { width: 100%; border-radius: 5px; font-weight: bold; }
    
    /* Status Indicators */
    .status-ok { color: #00ff41; font-weight: 800; }
    .status-danger { color: #ff0055; font-weight: 800; animation: blink 1s infinite; }
    
    @keyframes blink { 50% { opacity: 0.5; } }
</style>
""", unsafe_allow_html=True)

# ==========================================
# 2. LOGIC HELPERS
# ==========================================
def safe_log1p(x): return np.log1p(np.abs(x))

def get_project_root():
    current_path = Path(__file__).resolve().parent
    for _ in range(4):
        if (current_path / "results").exists(): return current_path
        current_path = current_path.parent
        if current_path == current_path.parent: break
    raise FileNotFoundError("Root not found")

# --- Initialize Session State ---
if 'monitoring' not in st.session_state: st.session_state.monitoring = False
if 'packet_count' not in st.session_state: st.session_state.packet_count = 0
if 'threat_count' not in st.session_state: st.session_state.threat_count = 0
if 'history_time' not in st.session_state: st.session_state.history_time = deque(maxlen=50)
if 'history_risk' not in st.session_state: st.session_state.history_risk = deque(maxlen=50)
if 'proto_counts' not in st.session_state: st.session_state.proto_counts = Counter()
if 'log_data' not in st.session_state: st.session_state.log_data = deque(maxlen=20)
if 'threat_log' not in st.session_state: st.session_state.threat_log = deque(maxlen=50) # Only attacks

# Packet time tracker for 'count' feature
if 'packet_times' not in st.session_state: st.session_state.packet_times = deque(maxlen=2000)

# ==========================================
# 3. LOAD MODELS
# ==========================================
try:
    ROOT = get_project_root()
    FILES = {
        "binary": ROOT / "results/models/binary_model.pkl",
        "multi": ROOT / "results/models/multi_model.pkl",
        "enc": ROOT / "results/models/multi_label_encoder.pkl",
        "meta": ROOT / "results/models/model_metadata.json",
        "schema": ROOT / "data/processed/realtime_schema.json"
    }
except:
    st.error("❌ Critical: File paths not found.")
    st.stop()

@st.cache_resource
def load_resources():
    sys = {}
    sys["bin"] = joblib.load(FILES["binary"])
    sys["mul"] = joblib.load(FILES["multi"])
    sys["enc"] = joblib.load(FILES["enc"])
    with open(FILES["meta"]) as f: sys["meta"] = json.load(f)
    with open(FILES["schema"]) as f: sys["schema"] = json.load(f)
    return sys

system = load_resources()

# ==========================================
# 4. PACKET PROCESSING
# ==========================================
def process_packet(pkt):
    feat = {}
    if TCP in pkt:
        feat['protocol_type'] = 'tcp'
        feat['service'] = 'http' if pkt[TCP].dport == 80 or pkt[TCP].sport == 80 else 'private'
        feat['flag'] = 'SF'
    elif UDP in pkt:
        feat['protocol_type'] = 'udp'
        feat['service'] = 'domain_u'
        feat['flag'] = 'SF'
    elif ICMP in pkt:
        feat['protocol_type'] = 'icmp'
        feat['service'] = 'ecr_i'
        feat['flag'] = 'SF'
    else: return None

    feat['src_bytes'] = len(pkt)
    feat['dst_bytes'] = 0
    
    # Calc Count (pkts in last 2 secs)
    now = time.time()
    st.session_state.packet_times.append(now)
    recent = [t for t in st.session_state.packet_times if now - t <= 2]
    feat['count'] = len(recent)
    
    # Defaults
    feat['srv_count'] = feat['count']
    feat['same_srv_rate'] = 1.0
    feat['diff_srv_rate'] = 0.0
    
    return feat

# ==========================================
# 5. UI LAYOUT & MAIN LOOP
# ==========================================
def main():
    # --- Sidebar ---
    with st.sidebar:
        st.title("🎛️ Control Center")
        
        # Start/Pause Button with dynamic label
        if st.session_state.monitoring:
            if st.button("⏸️ PAUSE MONITORING", type="primary"):
                st.session_state.monitoring = False
                st.rerun()
        else:
            if st.button("▶️ START MONITORING", type="primary"):
                st.session_state.monitoring = True
                st.rerun()
        
        st.divider()
        st.write("🔧 **Settings**")
        thresh = st.slider("Alert Threshold", 0.0, 1.0, system['meta'].get('binary_threshold', 0.5))
        
        if st.button("🗑️ Reset Statistics"):
            st.session_state.packet_count = 0
            st.session_state.threat_count = 0
            st.session_state.history_time.clear()
            st.session_state.history_risk.clear()
            st.session_state.proto_counts.clear()
            st.session_state.log_data.clear()
            st.session_state.threat_log.clear()
            st.rerun()

    # --- Main Screen ---
    st.title("🛡️ Network Security Operations (SOC)")
    
    # Top KPI Row
    k1, k2, k3, k4 = st.columns(4)
    status_ph = k1.empty()
    count_ph = k2.empty()
    threat_ph = k3.empty()
    proto_ph = k4.empty()

    # Middle Charts Row
    c1, c2, c3 = st.columns([1, 2, 1])
    gauge_ph = c1.empty()
    chart_ph = c2.empty()
    pie_ph = c3.empty()

    # Tabs for Logs
    st.divider()
    tab_all, tab_threats = st.tabs(["📜 Live Traffic Log", "🚨 Threat History"])
    log_all_ph = tab_all.empty()
    log_threat_ph = tab_threats.empty()

    # --- THE MONITORING LOOP ---
    
    # If paused, just show current static data
    if not st.session_state.monitoring:
        status_ph.metric("System Status", "PAUSED", delta_color="off")
        # Draw charts once so they don't disappear
        if st.session_state.log_data:
            df_hist = pd.DataFrame({'Time': list(st.session_state.history_time), 'Risk': list(st.session_state.history_risk)})
            chart_ph.plotly_chart(px.area(df_hist, x='Time', y='Risk', title="Risk Timeline"), use_container_width=True)
            log_all_ph.dataframe(pd.DataFrame(st.session_state.log_data), use_container_width=True, hide_index=True)
        return # Exit main(), waiting for user to click Start

    # While Running
    while st.session_state.monitoring:
        try:
            # 1. Sniff
            packets = sniff(count=1, timeout=0.1)
            
            # Logic: If no packet, just skip loop iteration but don't crash
            if not packets:
                time.sleep(0.05)
                continue
                
            pkt = packets[0]
            if IP not in pkt: continue
            
            # 2. Process
            feat = process_packet(pkt)
            if not feat: continue
            
            # 3. Predict
            df_in = pd.DataFrame([{col: feat.get(col, 0.0) for col in system["schema"]["raw_feature_columns"]}])
            df_in = df_in[system["schema"]["raw_feature_columns"]] # Ensure order
            
            prob = system["bin"].predict_proba(df_in)[0][1]
            if feat['protocol_type'] == 'udp':
                is_attack = prob > 0.8
            else:
                is_attack = prob > thresh
                        
            # 4. Update Stats
            st.session_state.packet_count += 1
            st.session_state.proto_counts[feat['protocol_type']] += 1
            now_str = datetime.datetime.now().strftime('%H:%M:%S')
            
            st.session_state.history_time.append(now_str)
            st.session_state.history_risk.append(prob)
            
            if is_attack:
                st.session_state.threat_count += 1
                att_idx = system["mul"].predict(df_in)[0]
                att_name = system["enc"].inverse_transform([att_idx])[0]
                
                # Add to Threat Log
                st.session_state.threat_log.appendleft({
                    "Time": now_str, "Type": att_name.upper(), 
                    "Src": pkt[IP].src, "Confidence": f"{prob:.1%}"
                })
            
            # Add to General Log
            st.session_state.log_data.appendleft({
                "Time": now_str, "Proto": feat['protocol_type'], 
                "Src": pkt[IP].src, "Bytes": feat['src_bytes'], 
                "Risk": f"{prob:.2f}", "Status": "🛑 ATTACK" if is_attack else "OK"
            })
            
            # 5. RENDER UI (Fast Updates)
            
            # KPIs
            status_ph.metric("Status", "ACTIVE MONITORING", delta="Scanning...")
            count_ph.metric("Packets Scanned", st.session_state.packet_count)
            threat_ph.metric("Threats Detected", st.session_state.threat_count, delta_color="inverse")
            proto_ph.metric("Current Proto", feat['protocol_type'].upper())
            
            # Gauge
            gauge_fig = go.Figure(go.Indicator(
                mode="gauge+number", value=prob*100, 
                title={'text': "Risk Level"},
                gauge={'axis': {'range': [None, 100]}, 
                       'bar': {'color': "#ff0055" if is_attack else "#00ff41"},
                       'threshold': {'line': {'color': "white", 'width': 2}, 'value': thresh*100}}
            ))
            gauge_fig.update_layout(height=250, margin=dict(l=20,r=20,t=50,b=20), paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"})
            gauge_ph.plotly_chart(gauge_fig, use_container_width=True)
            
            # Timeline Chart
            chart_df = pd.DataFrame({'Time': list(st.session_state.history_time), 'Risk': list(st.session_state.history_risk)})
            line_fig = px.area(chart_df, x='Time', y='Risk', template="plotly_dark", title="Real-Time Risk Analysis")
            line_fig.update_layout(height=250, margin=dict(l=20,r=20,t=40,b=20), yaxis_range=[0, 1.1])
            chart_ph.plotly_chart(line_fig, use_container_width=True)
            
            # Pie Chart
            pie_df = pd.DataFrame.from_dict(st.session_state.proto_counts, orient='index', columns=['count']).reset_index()
            pie_fig = px.pie(pie_df, values='count', names='index', template="plotly_dark", title="Protocol Distribution", hole=0.4)
            pie_fig.update_layout(height=250, margin=dict(l=20,r=20,t=40,b=20), showlegend=False)
            pie_ph.plotly_chart(pie_fig, use_container_width=True)
            
            # Logs
            log_all_ph.dataframe(pd.DataFrame(st.session_state.log_data), use_container_width=True, hide_index=True)
            if st.session_state.threat_log:
                log_threat_ph.dataframe(pd.DataFrame(st.session_state.threat_log), use_container_width=True, hide_index=True)
            else:
                log_threat_ph.info("No threats detected yet.")
                
            time.sleep(0.01) # Yield a tiny bit of CPU

        except Exception as e:
            # Silent fail for UI stability, print to console if needed
            print(e)
            time.sleep(1)

if __name__ == "__main__":
    main()