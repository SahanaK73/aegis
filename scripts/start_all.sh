#!/usr/bin/env bash
# Start backend + React dashboard (+ optionally a demo collector). Run from the repo root.
#   ./scripts/start_all.sh [scenario]      scenario: normal | payment_latency_spike | cpu_spike | ...
# Ctrl-C stops everything. DEVELOPMENT tokens only.
set -euo pipefail
cd "$(dirname "$0")/.."
SCENARIO="${1:-payment_latency_spike}"
export AEGIS_DB_PATH="${AEGIS_DB_PATH:-backend.db}"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

python -m uvicorn backend.main:app_factory --factory --port 8000 --log-level warning & pids+=($!)
(cd frontend && [ -d node_modules ] || npm install --no-audit --no-fund)
(cd frontend && npx vite --port 5173 --strictPort) & pids+=($!)
sleep 3
echo "Backend  http://localhost:8000/docs   Dashboard  http://localhost:5173  (Live API mode)"
echo "Starting collector, scenario=$SCENARIO (dev token for tenant-a)"
AEGIS_ENDPOINT=http://localhost:8000/api/v1/events AEGIS_COLLECTOR_TOKEN="${AEGIS_TOKEN_TENANT_A:-dev-token-tenant-a}" \
AEGIS_DB_PATH=collector.db AEGIS_TICK_SECONDS=1 AEGIS_HEARTBEAT_SECONDS=5 \
  python -m collector.main run --scenario "$SCENARIO"
