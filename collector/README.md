# Aegis Local Collector (Person 1)

Runs inside the customer environment. Produces metadata-only events, proves what
left, buffers when offline, and sends to the SaaS over HTTP(S) with a per-collector token.

## Run

```bash
pip install -r collector/requirements.txt
export AEGIS_ENDPOINT=http://localhost:8000/api/v1/events
export AEGIS_COLLECTOR_TOKEN=<token issued by the SaaS>
python -m collector.main run --scenario cpu_spike --ticks 30   # omit --ticks to run forever
python -m collector.main verify-audit                          # checks the audit hash chain
python -m pytest collector/tests -q                            # run from the folder that contains collector/
```

Scenarios: `normal`, `payment_latency_spike`, `cpu_spike`, `network_degradation`, `auth_attack`, `secret_injection`.
Simulated services use the AIOps graph ids (`api-gateway`, `payment-service`, `database`) and canonical metric names (`cpu_percent`, `latency_ms`, `packet_loss_percent`); legacy names still pass the allow-list and are normalised by the backend.

## Environment variables

| Variable | Default |
|---|---|
| AEGIS_ENDPOINT | http://localhost:8000/api/v1/events |
| AEGIS_COLLECTOR_TOKEN | (empty; required in real use) |
| AEGIS_COLLECTOR_ID | collector-001 |
| AEGIS_REGION | ap-south |
| AEGIS_SOURCE_TZ | Asia/Kolkata |
| AEGIS_POLICY_VERSION | v1 |
| AEGIS_DB_PATH | collector.db |
| AEGIS_TICK_SECONDS / AEGIS_HEARTBEAT_SECONDS | 2 / 5 |
| AEGIS_RAW_RETENTION_SECONDS | 3600 |
| AEGIS_REQUEST_TIMEOUT | 5 |
| AEGIS_BACKOFF_BASE / MAX / JITTER | 1 / 60 / 0.1 |
| AEGIS_BATCH_SIZE | 50 |
| AEGIS_AUTH_WINDOW_SECONDS / AEGIS_AUTH_THRESHOLD | 60 / 10 |

## Endpoint contract (for Person 2)

`POST /api/v1/events`, one event per request, body = deterministic JSON
(sorted keys, no whitespace, ASCII).

Headers:
- `Authorization: Bearer <token>`: the SaaS derives the tenant from this, never from the payload.
- `X-Collector-Id`
- `X-Content-SHA256`: hex SHA-256 of the **exact raw request body**.
- `Content-Type: application/json`

Response handling by the collector: any 2xx = ack, and the event is deleted from the outbox. **409 = duplicate event_id, also treated as ack.** Anything else (4xx/5xx, timeout, connection error) keeps the event and retries with exponential backoff, same `event_id`, same bytes.

Server must: hash the raw body it received (do not re-serialize) and compare to the header; dedupe on `(tenant_id from token, collector_id, event_id)`; order by `timestamp_utc`.

Event types and fields: see `collector/policy.py` (`SCHEMAS`, `FIELD_RULES`). Samples in `collector/fixtures/`.
**Person 2 must freeze one schema.** If it differs, edit only `policy.py` (and `pipeline.py` where candidates are built).

## Hashing rule

The hash is never inside the bytes being hashed. Serialize once, hash those bytes, send those same bytes, send the hash in the header. The audit table stores the hash, size and a chained record hash.

## Safety model

- Default-deny allow-list per event type (`enforce_allowlist`), then strict validation (`validate_outbound`): unknown fields rejected, string fields must be enums or strict identifiers, final regex secret scan.
- Raw log lines and raw auth records go to the local `raw_logs` table only (expire after `AEGIS_RAW_RETENTION_SECONDS`). Failed logins leave only as `auth_failure_summary` (early summary at threshold, final at window close).
- Violations are logged by field name or category only, never the value.
- Outbox is written before send and deleted only on ack. Audit chain detects edits or deletions.

## Deviations / assumptions

- Followed the Person-1 prompt's event types (`metric`, `heartbeat`, `auth_failure_summary`), not the earlier spec's `metric_anomaly` / `tenant_id` / `redaction_summary`. The collector sends no `tenant_id`.
- Heartbeat health states are computed from backlog and consecutive send failures (thresholds in `Collector.collector_health`).
- Collector-Poor-at-45s is a server-side rule (heartbeat staleness); the collector only sends heartbeats.

## Not implemented

- Organizer-stream adapter (the simulator is the only source; add an adapter that yields the same record dicts).
- TLS client config / cert pinning (use an https endpoint; `requests` verifies certs by default).
- Dead-letter handling for permanently rejected events (4xx keeps retrying).
- Batch POST; reorder window is server-side.
- Real log tailing, metrics scraping, or DB-backed `raw_logs` encryption.
