# Aegis Central Backend (Person 2)

FastAPI + SQLite. Receives metadata-only events from Person 1's collector, verifies and
stores them per tenant, and serves the dashboard APIs for Person 3.

## Run

```bash
pip install -r backend/requirements.txt
python -m uvicorn backend.main:app_factory --factory --port 8000   # from the folder containing backend/
python -m pytest backend/tests -q
```

Point the collector at it: `AEGIS_ENDPOINT=http://localhost:8000/api/v1/events AEGIS_COLLECTOR_TOKEN=dev-token-tenant-a`

## Dev configuration

| Env var | Default | Meaning |
|---|---|---|
| AEGIS_TOKEN_TENANT_A | dev-token-tenant-a | token for `tenant-a` (region `ap-south`) |
| AEGIS_TOKEN_TENANT_B | dev-token-tenant-b | token for `tenant-b` (region `eu-west`) |
| AEGIS_AIOPS_KEY | dev-aiops-key | key for `POST /api/v1/incidents` (AIOps only) |
| AEGIS_DB_PATH | backend.db | SQLite file (delete old files; schema changed) |
| AEGIS_AIOPS_MODE | background | `background` worker thread, `sync` (tests), `off` |
| AEGIS_CORS_ORIGINS | http://localhost:5173,http://127.0.0.1:5173 | allowed browser origins |

Thresholds (heartbeat, backlog, late events, etc.) are in `backend/config.py` (`Settings`).
These tokens are placeholders for the hackathon. Change them for anything real.

## Endpoints

All reads need `Authorization: Bearer <tenant token>` and return
`{"status":"ok","generated_at":...,"tenant_id":...,"data":...}`. Errors return
`{"status":"rejected","code":...}`. The tenant always comes from the token. Passing
`?tenant_id=<other>` returns **403**.

### POST /api/v1/events (collector -> backend)
Headers: `Authorization: Bearer <token>`, `X-Content-SHA256: <hex sha256 of the exact body>`.
Check order and status codes:

| Status | code | When |
|---|---|---|
| 401 | unauthorized | missing/unknown token |
| 413 | payload_too_large | body > 64 KB |
| 400 | hash_missing / hash_mismatch | header absent or SHA-256 of raw bytes differs |
| 422 | schema_invalid | unknown field, bad type/format/enum, bad timestamp (response lists field + error type only, never values) |
| 422 | timestamp_in_future | more than 300 s ahead |
| 403 | region_not_allowed | event region differs from the tenant's configured region |
| 200 | accepted / duplicate | stored, or already stored (no new row) |

Success example:
```json
{"status":"accepted","event_id":"evt-000001","hash_verified":true,
 "content_sha256":"<hex>","received_at":"2026-11-20T11:43:35Z","flags":[]}
```
`flags` can contain `late` (event older than 60 s on arrival) and `out_of_order`
(older than an event already stored for that collector).
Dedup key: `tenant_id + collector_id + event_id`. Event time (`timestamp_utc`) and
receipt time (`received_at`) are stored separately.

### GET /api/v1/events/recent
Query: `limit` (1-500, default 50), `collector_id`, `event_type`, `tenant_id` (403 if not your own).
`data` = `{events, egress_audit, egress_summary}`:
- `events`: approved events, oldest to newest, metric names normalised (`cpu_usage` -> `cpu_percent`; original kept in `original_metric_name`), plus `received_at` and `flags`.
- `egress_audit`: newest first. Per transfer: `sent_payload_exact` (the exact bytes received), `sender_sha256` (collector's header), `backend_sha256` (computed by the backend over those bytes), `hash_match`, `verification_status` (`verified` | `hash_mismatch` | `rejected`), `acknowledgement{status,http_status}`, `duplicate_deliveries`. Rejected attempts are listed with hashes only; their bodies are never stored.
- `egress_summary`: `verified`, `rejected`, `duplicate_deliveries`, `pending_in_collector_outbox` (backlog from the latest heartbeats).

### GET /api/v1/fleet
```json
{"data":{"collectors":[{"collector_id":"collector-001","tenant_id":"tenant-a","region":"ap-south",
  "collector_version":"0.1.0","last_heartbeat_at":"...","last_telemetry_at":"...",
  "cpu_percent":null,"memory_percent":null,"queue_backlog":6,"collector_reported_state":"excellent",
  "collector_health":{"state":"excellent","reasons":["..."],"heartbeat_age_seconds":0.8}}],
 "infrastructure":[{"service_id":"payment-api","state":"fair","reasons":["..."],"latest":[{"metric_name":"cpu_usage","value":87.0,"unit":"percent","severity":"high","timestamp_utc":"..."}]}]}}
```
Collector health and infrastructure health are separate lists.

### GET /api/v1/incidents
`data` = `{incidents, anomalies, dependency_graph, analysis}`. Incidents are produced by the built-in AIOps worker
(`backend/aiops_runner.py`) with stable ids (`INC-0001`...), each with ranked `root_cause_hypotheses` (supporting and
contradicting evidence, confidence), `timeline`, and a simulated human-approved `recommended_action`. `analysis` reports
`events_analyzed` and any AIOps `errors` (an AIOps failure never loses an accepted event).
The external write path `POST /api/v1/incidents` (header `X-Aegis-AIOps-Key`) still exists.

### GET /api/v1/health
Public liveness (`database`, `version`, `time`). With a token it adds the AIOps contract fields (`status` healthy|degraded,
`engine`, `graph_engine`, `active_incidents`, `healthy_collectors`, `unhealthy_collectors`, `anomaly_count`, `aiops_errors`)
and a `tenant` summary (events stored, collectors by state, worst states, ingest counters).

## Health states

Collector (worst of): heartbeat age >=10 s Good, >=20 s Fair, **>=45 s Poor**; backlog >10 Good, >100 Fair, >500 Poor;
telemetry stale >=60 s Good, >=120 s Fair. No heartbeat ever = Poor.
Infrastructure per service: worst severity among the latest metric of each name in the last 60 s
(info=Excellent, warning=Good, high=Fair, critical=Poor). Metrics with `health_scope=collector` are excluded.

## Contract notes and deviations

- `shared/event_schema.json` is generated from `backend/schemas.py`. Person 1 and Person 3 should confirm it.
- `service_id` is optional on `heartbeat` (the collector sends none); required on the other two.
- `window_seconds`, `health_scope`, `resource_id`, `dependency_id` are optional on `metric`; the collector currently fills `health_scope` and `window_seconds`.
- Timestamps must be UTC ISO 8601.
- The ack also returns `sender_sha256` and `backend_sha256`.
- Duplicates return 200 `duplicate` (the collector treats any 2xx as ack).

## Not implemented

- Dev tokens only (no token rotation, hashing, or admin API).
- No rate limiting, TLS termination (use a proxy), or pagination cursors.
- Reorder window: events are flagged out-of-order, not re-sequenced.
- Incident detection (Person 3). The backend only stores and serves incidents.
- `GET` endpoints use the tenant token; a separate dashboard login is not built.
