# Aegis: privacy-first AIOps observability (CICADA 2026 prototype)

One integrated pipeline: **local collector -> metadata-only egress -> FastAPI backend -> deterministic AIOps -> React dashboard.**
Telemetry here is **simulated** (`collector/simulator.py`); nothing is connected to real infrastructure. Security controls
are prototype-level, not production-grade, and "multi-region" is a per-tenant region check, not a multi-region deployment.

## Architecture

```
simulator / organizer stream (adapter slot)
  -> collector: redaction scan -> default-deny allow-list + strict validation -> SQLite outbox + audit hash chain
  -> POST /api/v1/events  (Bearer token, X-Content-SHA256 of the exact bytes)
  -> backend: token->tenant, size, SHA-256 over raw bytes, strict schema, region check, dedup, store exact bytes
  -> AIOps worker (background thread, never blocks ingest): rolling baselines + cold-start thresholds,
     sustained detection, dependency graph, correlation, ranked evidence-backed hypotheses (no LLM)
  -> incidents stored with stable ids  -> GET /api/v1/{incidents,events/recent,fleet,health}
  -> React dashboard (Live API mode; labelled Mock/Demo mode)
```
Raw log text, usernames, IPs and card/secret values stay in the collector's local SQLite and never leave.
The collector keeps working with the backend down (outbox + exponential backoff, same `event_id` and bytes on retry).

## Layout
`collector/` local agent | `backend/` FastAPI + SQLite + AIOps worker | `aiops/` deterministic engine | `frontend/` React (Vite)
`shared/event_schema.json` wire contract (generated from `backend/schemas.py`) | `tests/integration/` real-component tests | `scripts/` run helpers

## Prerequisites and install
Python 3.11+ and Node 18+.
```bash
pip install -r requirements.txt httpx          # add --break-system-packages if your OS requires it
(cd frontend && npm install)
```

## Environment variables (development defaults shown; tokens are DEV-ONLY placeholders)
| Variable | Default | Used by |
|---|---|---|
| AEGIS_ENDPOINT | http://localhost:8000/api/v1/events | collector |
| AEGIS_COLLECTOR_TOKEN | (empty) | collector; use `dev-token-tenant-a` locally |
| AEGIS_COLLECTOR_ID / AEGIS_REGION | collector-001 / ap-south | collector (region must match the tenant's) |
| AEGIS_DB_PATH | collector.db / backend.db | collector / backend |
| AEGIS_TICK_SECONDS, AEGIS_HEARTBEAT_SECONDS | 2 / 5 | collector |
| AEGIS_TOKEN_TENANT_A / _B | dev-token-tenant-a / b | backend (tenant-a: ap-south, tenant-b: eu-west) |
| AEGIS_AIOPS_KEY | dev-aiops-key | backend (external incident writes) |
| AEGIS_AIOPS_MODE | background | backend: background / sync / off |
| AEGIS_CORS_ORIGINS | http://localhost:5173,http://127.0.0.1:5173 | backend |
| VITE_API_BASE_URL, VITE_API_TOKEN, VITE_USE_MOCK, VITE_REFRESH_MS | see `frontend/.env.example` | frontend |

See `collector/README.md` and `backend/README.md` for the full variable lists and endpoint details.

## Run
One command (backend + dashboard + demo collector): `./scripts/start_all.sh payment_latency_spike`, then open http://localhost:5173.

Or separately, from the repo root:
```bash
python -m uvicorn backend.main:app_factory --factory --port 8000
(cd frontend && npm run dev)
AEGIS_COLLECTOR_TOKEN=dev-token-tenant-a python -m collector.main run --scenario payment_latency_spike
```
Scenarios: `normal`, `payment_latency_spike`, `cpu_spike`, `network_degradation`, `auth_attack`, `secret_injection`.
Heartbeats stop when you Ctrl-C the collector: the fleet shows it Poor after 45 s and AIOps raises a collector-offline anomaly.

## Tests
```bash
python -m pytest collector/tests backend/tests aiops/tests tests -q     # Python: unit + integration
(cd frontend && npm test && npm run build)                              # React: component tests + production build
python scripts/run_e2e.py                                               # live demo with real processes + dashboard tests vs the live API
```

## Live demo procedure
1. `./scripts/start_all.sh payment_latency_spike`; open http://localhost:5173 (header shows **LIVE API MODE**).
2. Overview: events flow in; after ~10 s the latency spike becomes an incident.
3. Incidents & RCA: ranked hypotheses with supporting and contradicting evidence; the database is not blamed.
4. Privacy / Egress: sender SHA-256 vs backend SHA-256, "hashes match", the exact bytes, acknowledgement.
5. Stop the backend, watch the collector backlog grow; restart it: events arrive once, in order, none lost.
6. Run the collector with `--scenario secret_injection`: the fake key, email and card never appear in the dashboard or backend DB.
7. Remediation tab: recommendations need simulated human approval; nothing is executed automatically.

## Known limitations
- Telemetry is simulated; the organizer-stream adapter is not built (the simulator is the only source).
- AIOps re-runs the batch pipeline over the last 3000 stored events per tenant (simple and deterministic, not incremental).
- Pending (not yet delivered) payloads exist only in the collector outbox; the dashboard shows the backlog from the last heartbeat.
- Dev tokens, no token rotation, rate limiting or TLS termination; the dashboard token lives in the browser.
- Dependency graph is hand-defined (api-gateway -> payment-service -> database, network-service -> payment-service).
- Remediation is simulated and human-approved only; the approval state is not persisted by the backend.
- Old `backend.db` files from before this version are not migrated; delete them.
