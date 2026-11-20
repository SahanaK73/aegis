"""Aegis central backend (FastAPI).

Pipeline for POST /api/v1/events:
  token -> tenant (401) -> size (413) -> SHA-256 over the raw bytes (400) -> strict schema (422)
  -> timestamp not in future (422) -> region matches tenant (403) -> store + dedup -> ack
  -> hand to the AIOps worker (never blocks, never fails the request).
Tenant identity ALWAYS comes from the token. The payload has no tenant field and an
unknown field is rejected.

Every response from the dashboard endpoints uses one envelope:
  {"status":"ok","generated_at":...,"tenant_id":...,"data":{...}}
"""

from __future__ import annotations

import hashlib
import hmac
from contextlib import asynccontextmanager
import json
import time
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import FastAPI, Header, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from aiops.adapter import normalize_event
from aiops.dependency_graph import ServiceDependencyGraph

from .aiops_runner import AIOpsRunner
from .config import Settings, Tenant
from .db import DB
from .health import collector_health, infrastructure_health, worst
from .schemas import EVENT_ADAPTER, IncidentIn, safe_errors


def iso(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def reject(status: int, code: str, **extra: Any) -> JSONResponse:
    return JSONResponse(status_code=status, content={"status": "rejected", "code": code, **extra})


def create_app(settings: Settings | None = None, clock: Callable[[], float] = time.time) -> FastAPI:
    cfg = settings or Settings()
    db = DB(cfg.db_path)
    runner = AIOpsRunner(db, cfg, clock)
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        runner.stop()

    app = FastAPI(title="Aegis Central Backend", version="0.2.0", lifespan=lifespan)
    app.state.db, app.state.cfg, app.state.clock, app.state.aiops = db, cfg, clock, runner
    app.add_middleware(
        CORSMiddleware, allow_origins=list(cfg.cors_origins), allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Content-SHA256", "X-Collector-Id"],
    )
    stats: dict[str, dict[str, int]] = {}

    def bump(tenant_id: str, key: str) -> None:
        s = stats.setdefault(tenant_id, {})
        s[key] = s.get(key, 0) + 1

    def tenant_from(authorization: str | None) -> Tenant | None:
        if not authorization or not authorization.lower().startswith("bearer "):
            return None
        token = authorization[7:].strip()
        for known, tenant in cfg.tokens.items():
            if hmac.compare_digest(known.encode(), token.encode()):
                return tenant
        return None

    def envelope(tenant: Tenant | None, data: Any) -> dict[str, Any]:
        return {"status": "ok", "generated_at": iso(clock()),
                "tenant_id": tenant.tenant_id if tenant else None, "data": data}

    def scoped(authorization: str | None, tenant_id: str | None):
        tenant = tenant_from(authorization)
        if tenant is None:
            return None, reject(401, "unauthorized")
        if tenant_id is not None and tenant_id != tenant.tenant_id:
            return None, reject(403, "cross_tenant_access_denied")
        return tenant, None

    # ---- ingestion --------------------------------------------------------
    @app.post("/api/v1/events")
    async def ingest(request: Request, authorization: str | None = Header(default=None),
                     x_content_sha256: str | None = Header(default=None)):
        tenant = tenant_from(authorization)
        if tenant is None:
            return reject(401, "unauthorized")
        raw = await request.body()
        now = clock()
        computed = hashlib.sha256(raw).hexdigest()
        claimed = x_content_sha256.strip().lower() if x_content_sha256 else None

        def refuse(status: int, code: str, counter: str, detail: str = "", **extra: Any):
            bump(tenant.tenant_id, counter)
            db.record_rejection(tenant_id=tenant.tenant_id, now=now, http_status=status, code=code,
                                sender_sha=claimed, backend_sha=computed, size=len(raw), detail=detail)
            return reject(status, code, backend_sha256=computed, **extra)

        if len(raw) > cfg.max_body_bytes:
            return refuse(413, "payload_too_large", "rejected_too_large")
        if not claimed or not hmac.compare_digest(computed, claimed):
            return refuse(400, "hash_mismatch" if claimed else "hash_missing", "rejected_hash_mismatch")

        try:
            ev = EVENT_ADAPTER.validate_json(raw, strict=True)
            text = raw.decode("utf-8")
        except ValidationError as exc:
            errs = safe_errors(exc)
            return refuse(422, "schema_invalid", "rejected_schema",
                          detail=",".join(f"{e['field']}:{e['type']}" for e in errs[:8]), errors=errs)
        except UnicodeDecodeError:
            return refuse(422, "schema_invalid", "rejected_schema", detail="not utf-8")

        if ev.ts_epoch - now > cfg.max_future_skew_seconds:
            return refuse(422, "timestamp_in_future", "rejected_timestamp")
        if ev.region != tenant.region:
            return refuse(403, "region_not_allowed", "rejected_region", detail="region mismatch")

        body = json.dumps(ev.model_dump(exclude_none=True), sort_keys=True, separators=(",", ":"))
        outcome, flags = db.store_event(tenant_id=tenant.tenant_id, ev=ev, sha=computed, sender_sha=claimed,
                                        raw_body=text, body=body, now=now, late_after=cfg.late_after_seconds)
        bump(tenant.tenant_id, outcome)
        if outcome == "accepted":
            runner.notify(tenant.tenant_id)  # non-blocking in background mode; errors are recorded, not raised
        return {"status": outcome, "event_id": ev.event_id, "hash_verified": True,
                "sender_sha256": claimed, "backend_sha256": computed, "content_sha256": computed,
                "received_at": iso(now), "flags": flags}

    # ---- dashboard APIs ---------------------------------------------------
    def egress_records(tenant_id: str, rows: list[dict], rejections: list[dict]) -> list[dict]:
        out: list[dict] = []
        for r in rows:
            out.append({
                "event_id": r["event_id"], "event_type": r["event_type"], "service_id": r["service_id"] or "n/a",
                "collector_id": r["collector_id"], "timestamp_utc": r["timestamp_utc"],
                "policy_version": json.loads(r["body"])["policy_version"],
                "approved_payload": json.loads(r["raw_body"]),     # exactly what was sent
                "sent_payload_exact": r["raw_body"],
                "sender_sha256": r["sender_sha256"], "backend_sha256": r["content_sha256"],
                "sha256_hash": r["content_sha256"],
                "hash_match": r["sender_sha256"] == r["content_sha256"],
                "verification_status": "verified",
                "acknowledgement": {"status": "accepted", "http_status": 200, "event_id": r["event_id"],
                                    "hash_verified": True, "received_at": iso(r["received_at"])},
                "duplicate_deliveries": r["duplicate_deliveries"],
                "flags": [f for f in r["flags"].split(",") if f],
                "received_at": iso(r["received_at"]), "_sort": r["received_at"],
            })
        for j in rejections:
            out.append({
                "event_id": f"attempt-{j['id']}", "event_type": "rejected", "service_id": "n/a",
                "collector_id": "n/a", "timestamp_utc": iso(j["received_at"]), "policy_version": "n/a",
                "approved_payload": {"note": "body not stored: rejected payloads are never retained",
                                     "bytes_received": j["size"], "detail": j["detail"]},
                "sent_payload_exact": None,
                "sender_sha256": j["sender_sha256"], "backend_sha256": j["backend_sha256"],
                "sha256_hash": j["backend_sha256"],
                "hash_match": j["sender_sha256"] == j["backend_sha256"],
                "verification_status": "hash_mismatch" if j["code"].startswith("hash_") else "rejected",
                "acknowledgement": {"status": "rejected", "http_status": j["http_status"], "code": j["code"],
                                    "hash_verified": j["sender_sha256"] == j["backend_sha256"],
                                    "received_at": iso(j["received_at"])},
                "duplicate_deliveries": 0, "flags": [], "received_at": iso(j["received_at"]),
                "_sort": j["received_at"],
            })
        out.sort(key=lambda x: x["_sort"], reverse=True)
        for x in out:
            del x["_sort"]
        return out

    @app.get("/api/v1/events/recent")
    def events_recent(authorization: str | None = Header(default=None),
                      limit: int = Query(50, ge=1, le=500), tenant_id: str | None = None,
                      collector_id: str | None = None, event_type: str | None = None):
        tenant, err = scoped(authorization, tenant_id)
        if err:
            return err
        rows = db.recent_events(tenant.tenant_id, limit, collector_id, event_type)  # newest first
        events = []
        # Event-time order (oldest -> newest), not arrival order: late / out-of-order deliveries
        # must not draw charts backwards. pk is the tie-break so the order is deterministic.
        for r in sorted(rows, key=lambda x: (x["event_ts"], x["pk"])):
            ev = normalize_event(json.loads(r["body"]))
            ev["received_at"] = iso(r["received_at"])
            ev["flags"] = [f for f in r["flags"].split(",") if f]
            events.append(ev)
        beats = [c.get("queue_backlog") or 0 for c in db.collectors(tenant.tenant_id)]
        rejections = db.recent_rejections(tenant.tenant_id, min(limit, 50))
        egress = egress_records(tenant.tenant_id, rows, rejections)
        return envelope(tenant, {
            "events": events,
            "egress_audit": egress,
            "egress_summary": {
                "verified": db.count_events(tenant.tenant_id),
                "rejected": db.count_rejections(tenant.tenant_id),
                "duplicate_deliveries": db.duplicate_total(tenant.tenant_id),
                "pending_in_collector_outbox": sum(beats),
                "note": "Pending payloads live only in the collector's local outbox; this is the backlog "
                        "count from the latest collector heartbeats.",
            },
        })

    @app.get("/api/v1/fleet")
    def fleet(authorization: str | None = Header(default=None), tenant_id: str | None = None):
        tenant, err = scoped(authorization, tenant_id)
        if err:
            return err
        now = clock()
        collectors = []
        for r in db.collectors(tenant.tenant_id):
            collectors.append({
                "collector_id": r["collector_id"], "tenant_id": tenant.tenant_id, "tenant_name": tenant.name,
                "region": r["region"], "collector_version": r["version"],
                "last_heartbeat_at": iso(r["last_heartbeat_at"]), "last_telemetry_at": iso(r["last_telemetry_at"]),
                "cpu_percent": r["cpu_percent"], "memory_percent": r["memory_percent"],
                "queue_backlog": r["queue_backlog"], "collector_reported_state": r["reported_state"],
                "collector_health": collector_health(r, now, cfg),
            })
        infra = infrastructure_health(db.metrics_since(tenant.tenant_id, now - cfg.infra_window_seconds))
        return envelope(tenant, {"collectors": collectors, "infrastructure": infra})

    @app.get("/api/v1/incidents")
    def incidents(authorization: str | None = Header(default=None), limit: int = Query(50, ge=1, le=200),
                  tenant_id: str | None = None):
        tenant, err = scoped(authorization, tenant_id)
        if err:
            return err
        rows = db.incidents(tenant.tenant_id, limit)
        for r in rows:
            r["updated_at"] = iso(r["updated_at"])
        snap = db.load_snapshot(tenant.tenant_id)
        graph = (snap or {}).get("dependency_graph") or ServiceDependencyGraph().to_dict()
        return envelope(tenant, {
            "incidents": rows,
            "anomalies": (snap or {}).get("anomalies", []),
            "dependency_graph": graph,
            "analysis": {"engine": "aegis-aiops-deterministic", "updated_at": iso((snap or {}).get("updated_at")),
                         "events_analyzed": (snap or {}).get("events_analyzed", 0),
                         "errors": [{"at": iso(e["ts"]), "error": e["error"].splitlines()[0]}
                                    for e in db.aiops_errors(tenant.tenant_id, 5)]},
        })

    @app.post("/api/v1/incidents")
    async def incidents_write(request: Request, x_aegis_aiops_key: str | None = Header(default=None)):
        """External AIOps -> backend write path (separate key). The built-in worker writes directly."""
        if not x_aegis_aiops_key or not hmac.compare_digest(x_aegis_aiops_key.encode(), cfg.aiops_key.encode()):
            return reject(401, "unauthorized")
        try:
            inc = IncidentIn.model_validate_json(await request.body())
        except ValidationError as exc:
            return reject(422, "schema_invalid", errors=safe_errors(exc))
        if cfg.tenant_by_id(inc.tenant_id) is None:
            return reject(404, "unknown_tenant")
        db.upsert_incident(inc.tenant_id, inc.incident_id, inc.model_dump(), clock())
        return {"status": "stored", "incident_id": inc.incident_id}

    @app.get("/api/v1/health")
    def health(authorization: str | None = Header(default=None)):
        """Public liveness. With a valid token it adds the tenant summary and the AIOps health fields."""
        out: dict[str, Any] = {"service": "aegis-backend", "version": app.version,
                               "database": "ok" if db.ping() else "down", "time": iso(clock())}
        tenant = tenant_from(authorization)
        if tenant:
            now = clock()
            states = [collector_health(r, now, cfg)["state"] for r in db.collectors(tenant.tenant_id)]
            infra = infrastructure_health(db.metrics_since(tenant.tenant_id, now - cfg.infra_window_seconds))
            snap = db.load_snapshot(tenant.tenant_id) or {}
            active = [i for i in db.incidents(tenant.tenant_id, 500) if i.get("status", "active") in ("active", "open")]
            healthy = sum(1 for s in states if s in ("excellent", "good"))
            worst_c, worst_i = worst("excellent", *states), worst("excellent", *[i["state"] for i in infra])
            out.update({
                "status": "degraded" if (active or worst_c in ("fair", "poor") or worst_i in ("fair", "poor")) else "healthy",
                "engine": "aegis-aiops-deterministic",
                "graph_engine": (snap.get("aiops_health") or {}).get("graph_engine", ServiceDependencyGraph().backend_engine),
                "active_incidents": len(active),
                "healthy_collectors": healthy,
                "unhealthy_collectors": len(states) - healthy,
                "anomaly_count": len(snap.get("anomalies", [])),
                "aiops_errors": len(db.aiops_errors(tenant.tenant_id, 50)),
            })
            out["tenant"] = {
                "tenant_id": tenant.tenant_id, "events_stored": db.count_events(tenant.tenant_id),
                "collectors": len(states),
                "collectors_by_state": {s: states.count(s) for s in ("excellent", "good", "fair", "poor")},
                "worst_collector_state": worst_c, "worst_infrastructure_state": worst_i,
                "ingest_counters": stats.get(tenant.tenant_id, {}),
            }
        return {"status": "ok", "data": out}

    return app


def app_factory() -> FastAPI:  # uvicorn backend.main:app_factory --factory
    return create_app()
