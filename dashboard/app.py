import streamlit as st
import pandas as pd
import joblib
import json
import plotly.graph_objects as go
import plotly.express as px
from pathlib import Path
import numpy as np
import time
from collections import deque
from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime

# ==========================================
# 1. PAGE CONFIGURATION & STYLING
# ==========================================
st.set_page_config(
    page_title="Sentinel AI | Advanced IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Dark Theme
st.markdown("""
<style>
    .stApp { background-color: #0E1117; color: #FAFAFA; }
    .stMetric { background-color: #262730; padding: 10px; border-radius: 5px; border-left: 5px solid #4CAF50; }
    /* Headers */
    h1, h2, h3 { font-family: 'Segoe UI', sans-serif; font-weight: 600; }
    /* Dataframes */
    div[data-testid="stDataFrame"] { border: 1px solid #333; border-radius: 5px; }
</style>
""", unsafe_allow_html=True)

# ==========================================
# 2. HELPER FUNCTIONS (תיקון קריטי: הפונקציה החסרה)
# ==========================================
# הפונקציה הזו חייבת להיות מוגדרת לפני טעינת המודל
def safe_log1p(x):
    return np.log1p(np.abs(x))

# ==========================================
# 3. LOAD SYSTEM RESOURCES
# ==========================================
def get_project_root():
    """
    Finds the project root directory to locate models and data.
    """
    current_path = Path(__file__).resolve().parent
    for _ in range(4):
        if (current_path / "results").exists(): return current_path
        current_path = current_path.parent
        if current_path == current_path.parent: break
    return current_path # Fallback

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
    st.error("Error: Could not locate project files. Please check directory structure.")
    st.stop()

@st.cache_resource
def load_system():
    """
    Loads trained models and schema metadata.
    """
    sys = {}
    try:
        # מוודאים שהפונקציה זמינה בזיכרון הגלובלי כדי ש-joblib ימצא אותה
        global safe_log1p
        
        sys["bin"] = joblib.load(FILES["binary"])
        sys["mul"] = joblib.load(FILES["multi"])
        sys["enc"] = joblib.load(FILES["enc"])
        with open(FILES["schema"]) as f: sys["schema"] = json.load(f)
    except Exception as e:
        st.error(f"Failed to load models: {e}")
        st.error("Tip: This usually happens if 'safe_log1p' is missing.")
    return sys

system = load_system()

# Initialize Session State
if 'history' not in st.session_state:
    st.session_state.history = deque(maxlen=60) # Keep last 60 packets
if 'packet_times' not in st.session_state:
    st.session_state.packet_times = deque(maxlen=2000) # Used for traffic intensity

# ==========================================
# 4. PACKET PROCESSING ENGINE
# ==========================================
def process_packet(pkt):
    """
    Extracts features from raw Scapy packets to match model input.
    """
    try:
        if IP not in pkt: return None
        
        feat = {}
        # Basic Protocol Extraction
        if TCP in pkt:
            feat['protocol_type'] = 'tcp'
            feat['service'] = 'http' if pkt[TCP].dport in [80, 443, 8080] else 'private'
            feat['flag'] = 'SF'
        elif UDP in pkt:
            feat['protocol_type'] = 'udp'
            feat['service'] = 'domain_u' # Common for DNS/Streaming
            feat['flag'] = 'SF'
        elif ICMP in pkt:
            feat['protocol_type'] = 'icmp'
            feat['service'] = 'ecr_i'
            feat['flag'] = 'SF'
        else:
            return None

        feat['src_bytes'] = len(pkt)
        feat['dst_bytes'] = 0
        
        # Calculate Traffic Intensity ('count' feature)
        now = time.time()
        st.session_state.packet_times.append(now)
        # How many packets arrived in the last 2 seconds?
        recent_count = len([t for t in st.session_state.packet_times if now - t <= 2.0])
        feat['count'] = recent_count
        
        # Default values for complex features not calculable in simple sniffing
        feat['srv_count'] = recent_count 
        feat['same_srv_rate'] = 1.0
        feat['diff_srv_rate'] = 0.0
        feat['dst_host_count'] = 1
        feat['dst_host_srv_count'] = 1
        
        return feat, pkt[IP].src, pkt[IP].dst
    except:
        return None

# ==========================================
# 5. MAIN DASHBOARD UI
# ==========================================
def main():
    # --- Sidebar Controls ---
    with st.sidebar:
        st.header("🎛️ Control Panel")
        run_sniffer = st.toggle("Start Monitoring (Live Sniffer)", value=False)
        
        st.divider()
        st.subheader("Model Calibration")
        
        # Sensitivity Slider
        threshold = st.slider("Alert Threshold", 0.0, 1.0, 0.75, 
                              help="Higher value = Fewer alerts. Lower value = More sensitive.")
        
        # Logic Inversion
        invert_logic = st.checkbox("Invert Model Logic", value=False, 
                                   help="Check this if the system flags safe traffic as attacks.")
        
        # Noise Filter
        smart_filter = st.checkbox("Smart Filter (Reduce Noise)", value=True, 
                                   help="Ignores standard UDP/DNS traffic unless risk is very high.")
        
        st.info("Tip: If you see too many False Positives, check 'Invert Model Logic' first.")

    st.title("🛡️ Network Traffic Inspector")
    
    # --- Layout Metrics ---
    # Top Metrics Row
    c1, c2, c3, c4 = st.columns(4)
    kpi_status = c1.empty()
    kpi_risk = c2.empty()
    kpi_proto = c3.empty()
    kpi_vol = c4.empty()
    
    st.divider()
    
    # Main Analysis Area
    col_main, col_details = st.columns([2, 1])
    
    with col_main:
        st.subheader("📊 Real-Time Risk Analysis")
        chart_ph = st.empty()
        
    with col_details:
        st.subheader("🔍 Last Packet Details")
        details_ph = st.empty()

    # Log Table
    st.subheader("📜 Traffic Log")
    log_ph = st.empty()

    # --- Sniffer Loop ---
    if run_sniffer:
        while True:
            # 1. Capture Packet
            packets = sniff(count=1, timeout=0.1)
            if not packets:
                time.sleep(0.01)
                continue
            
            # 2. Process Packet
            data = process_packet(packets[0])
            if not data: continue
            feat, src_ip, dst_ip = data
            
            # 3. Prepare Data for Model
            # Create a DataFrame with all columns initialized to 0.0
            input_df = pd.DataFrame(0.0, index=[0], columns=system["schema"]["raw_feature_columns"])
            # Update only extracted features
            for k, v in feat.items():
                if k in input_df.columns:
                    input_df[k] = v
            
            # 4. Prediction
            try:
                raw_prob = system["bin"].predict_proba(input_df)[0]
                
                # Handle Inverted Logic
                # Usually index [1] is 'Attack'. If model is inverted, index [0] is 'Attack'.
                if invert_logic:
                    prob_attack = raw_prob[0] 
                else:
                    prob_attack = raw_prob[1]
            except Exception as e:
                # Fallback if prediction fails
                prob_attack = 0.0
                
            # 5. Smart Filtering Logic
            is_alert = False
            
            if smart_filter:
                # If protocol is UDP (often noise) and probability isn't extreme -> Ignore
                if feat['protocol_type'] == 'udp' and prob_attack < 0.95:
                    is_alert = False
                    prob_attack = 0.1 # Artificially lower visual risk
                elif prob_attack > threshold:
                    is_alert = True
            else:
                if prob_attack > threshold:
                    is_alert = True

            # 6. Update History State
            now_str = datetime.datetime.now().strftime("%H:%M:%S")
            st.session_state.history.append({
                "Time": now_str, 
                "Risk": prob_attack, 
                "Bytes": feat['src_bytes'],
                "IsAttack": 1 if is_alert else 0
            })
            
            # --- Render UI Updates ---
            
            # KPIs
            if is_alert:
                kpi_status.metric("Status", "⚠️ ATTACK DETECTED", delta_color="inverse")
            else:
                kpi_status.metric("Status", "✅ SYSTEM SECURE", delta_color="normal")
            
            kpi_risk.metric("Attack Probability", f"{prob_attack:.1%}", delta=None)
            kpi_proto.metric("Protocol", feat['protocol_type'].upper())
            kpi_vol.metric("Packet Size", f"{feat['src_bytes']} bytes")
            
            # Chart
            df_hist = pd.DataFrame(st.session_state.history)
            fig = px.area(df_hist, x="Time", y="Risk", title="Risk Level Over Time", 
                          color_discrete_sequence=["#FF4B4B" if is_alert else "#00CC96"])
            fig.update_layout(yaxis_range=[0, 1.1], height=300, 
                              paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
            chart_ph.plotly_chart(fig, use_container_width=True)
            
            # Details Table (Explainability)
            details_df = pd.DataFrame([
                {"Feature": "Protocol", "Value": feat['protocol_type']},
                {"Feature": "Traffic Count (2s)", "Value": feat['count']},
                {"Feature": "Service", "Value": feat['service']},
                {"Feature": "Src Bytes", "Value": feat['src_bytes']}
            ])
            details_ph.dataframe(details_df, use_container_width=True, hide_index=True)
            
            # Log Table
            log_display = df_hist[['Time', 'Risk', 'Bytes']].copy()
            log_display['Status'] = df_hist['IsAttack'].apply(lambda x: "🚨 ATTACK" if x else "OK")
            # Show last 5 entries
            log_ph.dataframe(log_display.sort_index(ascending=False).head(5), use_container_width=True)
            
            time.sleep(0.05)
    else:
        st.info("System Standby. Click 'Start Monitoring' in the sidebar.")

if __name__ == "__main__":
    main()