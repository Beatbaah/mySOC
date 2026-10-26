#!/usr/bin/env bash
# Start/stop mySOC (API :8000, demo sensor, Vite console :5173) on a throwaway
# SQLite database so the developer's backend/mysoc-dev.db is never touched.
#   run.sh up | down | status | logs
set -euo pipefail
UNIT="$(cd "$(dirname "$0")/../../.." && pwd)"
TMP="${TMPDIR:-/tmp}"; STATE="${MYSOC_RUN_DIR:-${TMP%/}/mysoc-run}"
mkdir -p "$STATE"

# Env vars beat backend/.env (pydantic-settings), so these override the dev setup.
export MYSOC_DATABASE_URL="sqlite:///$STATE/mysoc.db"
export MYSOC_DEV_KEY_FILE="$STATE/vault.key"
export MYSOC_BOOTSTRAP_ADMIN_USERNAME=admin
export MYSOC_BOOTSTRAP_ADMIN_PASSWORD="${MYSOC_AGENT_PASSWORD:-Agent-Run-Passw0rd!x}"
export MYSOC_REQUIRE_MFA_FOR_ADMIN=false
export MYSOC_PUBLIC_ORIGIN=http://localhost:5173
export MYSOC_SENSOR_SOURCE=demo

start() { # name, workdir, command...
  local name=$1 dir=$2; shift 2
  (cd "$dir" && nohup "$@" >"$STATE/$name.log" 2>&1 & echo $! >"$STATE/$name.pid")
}
alive() { [ -f "$STATE/$1.pid" ] && kill -0 "$(cat "$STATE/$1.pid")" 2>/dev/null; }
wait_for() { # url, seconds
  for _ in $(seq "$2"); do curl -sf -o /dev/null "$1" && return 0; sleep 1; done
  echo "timed out waiting for $1" >&2; return 1
}

case "${1:-}" in
  up)
    for p in 8000 5173; do
      if lsof -iTCP:$p -sTCP:LISTEN >/dev/null 2>&1; then echo "port $p already in use (run.sh down, or stop your own dev server)" >&2; exit 1; fi
    done
    start api "$UNIT/backend" .venv/bin/uvicorn mysoc.main:app --port 8000
    wait_for http://127.0.0.1:8000/api/health 30
    # The API bootstraps tables + admin; start the sensor after so it doesn't race it.
    start sensor "$UNIT/backend" .venv/bin/python -m mysoc.sensor
    start vite "$UNIT/frontend" npx vite --port 5173 --strictPort
    wait_for http://localhost:5173/ 30
    for _ in $(seq 30); do grep -q "Sensor .* running" "$STATE/sensor.log" && break; sleep 1; done
    echo "mySOC up: http://localhost:5173  (admin / $MYSOC_BOOTSTRAP_ADMIN_PASSWORD)  state: $STATE"
    ;;
  down)
    for n in vite sensor api; do
      if alive $n; then pkill -P "$(cat "$STATE/$n.pid")" 2>/dev/null || true; kill "$(cat "$STATE/$n.pid")" 2>/dev/null || true; fi
      rm -f "$STATE/$n.pid"
    done
    # uvicorn takes a moment to release :8000; wait so an immediate `up` doesn't trip the port check.
    for _ in $(seq 15); do lsof -iTCP:8000 -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1 || break; sleep 1; done
    [ "${2:-}" = "--wipe" ] && rm -f "$STATE"/mysoc.db* "$STATE/vault.key"
    echo "stopped"
    ;;
  status) for n in api sensor vite; do alive $n && echo "$n: running" || echo "$n: stopped"; done ;;
  logs) tail -n "${2:-20}" "$STATE"/{api,sensor,vite}.log ;;
  *) echo "usage: run.sh up | down [--wipe] | status | logs [n]" >&2; exit 2 ;;
esac
