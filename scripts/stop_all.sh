#!/usr/bin/env bash
set -u

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_DIR="$PROJECT_ROOT/results/realtime"

kill_pidfile() {
  local pidfile="$1"
  local name="$2"

  if [[ -f "$pidfile" ]]; then
    local pid
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      echo "[*] Stopping $name (pid=$pid)"
      kill "$pid" 2>/dev/null || true
      sleep 0.2
      kill -9 "$pid" 2>/dev/null || true
    else
      echo "[*] $name not running (pidfile existed)."
    fi
    rm -f "$pidfile"
  else
    echo "[*] No pidfile for $name"
  fi
}

echo "== NIDS STOP =="
kill_pidfile "$PID_DIR/dashboard.pid" "Dashboard"
kill_pidfile "$PID_DIR/runner.pid" "Model runner"
kill_pidfile "$PID_DIR/zeek.pid" "Zeek"
echo "✅ Stopped."
