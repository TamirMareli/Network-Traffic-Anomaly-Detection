#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZEEK_LOG_DIR="/mnt/c/Users/elair/zeek_logs"
IFACE="eth0"
ZEEK_BIN="/opt/zeek/bin/zeek"
MODEL_RUNNER="src/realtime/model_runner.py"
DASH_APP="src/dashboard/app.py"

PID_DIR="$PROJECT_ROOT/results/realtime"
LOG_DIR="$PROJECT_ROOT/results/logs"
mkdir -p "$PID_DIR" "$LOG_DIR" "$ZEEK_LOG_DIR"

echo "== NIDS START =="
echo "Project:   $PROJECT_ROOT"
echo "Zeek logs: $ZEEK_LOG_DIR"
echo "Iface:     $IFACE"
echo "Dashboard: http://localhost:8501"
echo ""

# 1) Ask sudo password ONCE (interactive, pretty)
echo "[*] Sudo auth (one-time)..."
sudo -v

# 2) Start dashboard in background
echo "[*] Starting Dashboard..."
(
  cd "$PROJECT_ROOT"
  streamlit run "$DASH_APP" --server.headless true --server.port 8501
) > "$LOG_DIR/dashboard.out.log" 2> "$LOG_DIR/dashboard.err.log" &
echo $! > "$PID_DIR/dashboard.pid"
echo "    [OK] Dashboard pid=$(cat "$PID_DIR/dashboard.pid")"

# 3) Start model runner in background
echo "[*] Starting Model runner..."
(
  cd "$PROJECT_ROOT"
  python3 "$MODEL_RUNNER"
) > "$LOG_DIR/runner.out.log" 2> "$LOG_DIR/runner.err.log" &
echo $! > "$PID_DIR/runner.pid"
echo "    [OK] Runner pid=$(cat "$PID_DIR/runner.pid")"

echo ""
echo "✅ Dashboard + Model runner started."
echo "Open: http://localhost:8501"
echo ""
echo "Now running Zeek in this terminal (CTRL+C stops Zeek)."
echo "Logs: $LOG_DIR"
echo ""

# 4) Run Zeek in FOREGROUND (needs sudo)
cd "$ZEEK_LOG_DIR"
sudo "$ZEEK_BIN" -C -i "$IFACE"
