import hashlib
import json

from .conftest import NOW, TOKEN_A, TOKEN_B, auth, body_of, heartbeat, iso, metric, post


def test_valid_event_ingested_and_acked(client):
    r = post(client, metric())
    assert r.status_code == 200
    j = r.json()
    assert j["status"] == "accepted" and j["event_id"] == "evt-000001" and j["hash_verified"] is True
    recent = client.get("/api/v1/events/recent", headers=auth()).json()
    assert recent["tenant_id"] == "tenant-a"
    assert [e["event_id"] for e in recent["data"]["events"]] == ["evt-000001"]
    assert recent["data"]["events"][0]["metric_value"] == 42.5


def test_all_three_event_types_accepted(client):
    assert post(client, metric(1)).status_code == 200
    assert post(client, heartbeat(2)).status_code == 200
    a = {"event_id": "evt-000003", "collector_id": "collector-001", "event_type": "auth_failure_summary",
         "service_id": "auth-service", "timestamp_utc": iso(NOW), "source_timezone": "Asia/Kolkata",
         "region": "ap-south", "severity": "high", "policy_version": "v1",
         "failure_count": 18, "window_seconds": 60, "summary_code": "REPEATED_AUTH_FAILURE"}
    assert post(client, a).status_code == 200


def test_unknown_fields_rejected(client):
    for extra in ({"username": "alice"}, {"tenant_id": "tenant-b"}, {"raw_line": "x"}):
        r = post(client, metric(1, **extra))
        assert r.status_code == 422 and r.json()["code"] == "schema_invalid"
        assert "alice" not in r.text  # values are never echoed back
    assert client.get("/api/v1/events/recent", headers=auth()).json()["data"]["events"] == []


def test_invalid_token_rejected(client):
    assert post(client, metric(), token="wrong").status_code == 401
    assert post(client, metric(), token=None).status_code == 401
    assert client.get("/api/v1/fleet").status_code == 401
    assert client.get("/api/v1/events/recent", headers=auth("wrong")).status_code == 401


def test_cross_tenant_isolation(client):
    # tenant-a's collector reports; tenant-b must not see it
    post(client, metric(1))
    post(client, heartbeat(2))
    rb = client.get("/api/v1/events/recent", headers=auth(TOKEN_B)).json()
    assert rb["data"]["events"] == [] and rb["tenant_id"] == "tenant-b"
    assert client.get("/api/v1/fleet", headers=auth(TOKEN_B)).json()["data"]["collectors"] == []
    # explicitly asking for the other tenant's data is refused
    r = client.get("/api/v1/events/recent", params={"tenant_id": "tenant-a"}, headers=auth(TOKEN_B))
    assert r.status_code == 403
    assert client.get("/api/v1/fleet", params={"tenant_id": "tenant-a"}, headers=auth(TOKEN_B)).status_code == 403
    # same collector_id + event_id from another tenant is stored separately, not deduped
    eb = metric(1, region="eu-west")
    assert post(client, eb, token=TOKEN_B).json()["status"] == "accepted"
    assert len(client.get("/api/v1/events/recent", headers=auth(TOKEN_A)).json()["data"]["events"]) == 2
    assert len(client.get("/api/v1/events/recent", headers=auth(TOKEN_B)).json()["data"]["events"]) == 1


def test_payload_cannot_choose_tenant(client):
    r = post(client, metric(1, tenant_id="tenant-b"))
    assert r.status_code == 422


def test_hash_mismatch_rejected(client):
    ev = metric()
    r = post(client, ev, sha="0" * 64)
    assert r.status_code == 400 and r.json()["code"] == "hash_mismatch"
    # tampered body, hash of the original
    raw = body_of(ev)
    r = post(client, ev, raw=raw.replace(b"42.5", b"99.9"), sha=hashlib.sha256(raw).hexdigest())
    assert r.status_code == 400
    # missing header
    r = client.post("/api/v1/events", content=raw, headers=auth())
    assert r.status_code == 400 and r.json()["code"] == "hash_missing"
    assert client.get("/api/v1/events/recent", headers=auth()).json()["data"]["events"] == []


def test_hash_is_over_exact_bytes_not_reserialized(client):
    # same JSON content, different whitespace: hash of the sent bytes must be what is checked
    raw = json.dumps(metric(), indent=2).encode()
    assert post(client, None, raw=raw).status_code == 200


def test_duplicate_retry_creates_one_record(client):
    ev = metric()
    assert post(client, ev).json()["status"] == "accepted"
    r = post(client, ev)
    assert r.status_code == 200 and r.json()["status"] == "duplicate"
    assert len(client.get("/api/v1/events/recent", headers=auth()).json()["data"]["events"]) == 1
    assert client.get("/api/v1/health", headers=auth()).json()["data"]["tenant"]["events_stored"] == 1


def test_region_validation(client):
    r = post(client, metric(region="eu-west"))
    assert r.status_code == 403 and r.json()["code"] == "region_not_allowed"
    assert post(client, metric(region="ap-south")).status_code == 200


def test_timestamps_validated_and_flags(client, clock):
    assert post(client, metric(1, t=NOW + 3600)).status_code == 422  # far future
    bad = metric(2, timestamp_utc="2026-01-01T00:00:00+05:30")
    assert post(client, bad).status_code == 422  # not UTC
    assert post(client, metric(3, timestamp_utc="yesterday")).status_code == 422
    assert post(client, metric(4, t=NOW - 300)).json()["flags"] == ["late"]
    r = post(client, metric(5, t=NOW - 600))  # older than evt 4, arrives after it
    assert set(r.json()["flags"]) == {"late", "out_of_order"}
    # stored with event time and receipt time kept separate
    e = client.get("/api/v1/events/recent", headers=auth()).json()["data"]["egress_audit"][0]
    assert e["timestamp_utc"] == iso(NOW - 600) and e["received_at"] == iso(NOW)


def test_heartbeat_drives_collector_status(client, clock):
    def health():
        c = client.get("/api/v1/fleet", headers=auth()).json()["data"]["collectors"][0]
        return c["collector_health"]["state"], c

    post(client, heartbeat(1, t=NOW, queue_backlog=3, cpu_percent=20.5, memory_percent=40.0))
    state, c = health()
    assert state == "excellent"
    assert c["collector_version"] == "0.1.0" and c["queue_backlog"] == 3 and c["cpu_percent"] == 20.5
    assert c["region"] == "ap-south" and c["tenant_id"] == "tenant-a"
    clock.t = NOW + 12; assert health()[0] == "good"
    clock.t = NOW + 25; assert health()[0] == "fair"
    clock.t = NOW + 44; assert health()[0] == "fair"
    clock.t = NOW + 45; st, c = health()
    assert st == "poor" and "no heartbeat" in c["collector_health"]["reasons"][0]
    # a fresh heartbeat recovers it
    post(client, heartbeat(2, t=NOW + 46)); clock.t = NOW + 46
    assert health()[0] == "excellent"


def test_heartbeat_vs_telemetry_tracked_separately(client, clock):
    post(client, heartbeat(1))
    post(client, metric(2))
    c = client.get("/api/v1/fleet", headers=auth()).json()["data"]["collectors"][0]
    assert c["last_heartbeat_at"] and c["last_telemetry_at"]
    clock.t = NOW + 70  # heartbeat stopped, telemetry stale too
    c = client.get("/api/v1/fleet", headers=auth()).json()["data"]["collectors"][0]
    assert c["collector_health"]["state"] == "poor"


def test_backlog_downgrades_collector(client):
    post(client, heartbeat(1, queue_backlog=600))
    c = client.get("/api/v1/fleet", headers=auth()).json()["data"]["collectors"][0]
    assert c["collector_health"]["state"] == "poor"


def test_infrastructure_health_separate_from_collector(client):
    post(client, heartbeat(1))
    post(client, metric(2, service_id="payment-api", severity="high", metric_value=95.0))
    post(client, metric(3, service_id="payments-db", severity="info"))
    d = client.get("/api/v1/fleet", headers=auth()).json()["data"]
    assert d["collectors"][0]["collector_health"]["state"] == "excellent"  # collector is fine
    infra = {i["service_id"]: i["state"] for i in d["infrastructure"]}
    assert infra == {"payment-api": "fair", "payments-db": "excellent"}


def test_incidents_flow_and_isolation(client):
    inc = {"incident_id": "inc-1", "tenant_id": "tenant-a", "title": "payment-api slow", "severity": "high",
           "root_causes": [{"rank": 1, "service_id": "payments-db", "score": 0.82}], "alerts_collapsed": 14}
    assert client.post("/api/v1/incidents", json=inc).status_code == 401
    r = client.post("/api/v1/incidents", json=inc, headers={"X-Aegis-AIOps-Key": "dev-aiops-key"})
    assert r.status_code == 200
    got = client.get("/api/v1/incidents", headers=auth()).json()["data"]["incidents"]
    assert got[0]["incident_id"] == "inc-1" and got[0]["root_causes"][0]["rank"] == 1
    assert client.get("/api/v1/incidents", headers=auth(TOKEN_B)).json()["data"]["incidents"] == []


def test_health_endpoint_public_and_tenant_summary(client):
    pub = client.get("/api/v1/health").json()["data"]
    assert pub["database"] == "ok" and "tenant" not in pub
    post(client, heartbeat(1))
    t = client.get("/api/v1/health", headers=auth()).json()["data"]["tenant"]
    assert t["collectors"] == 1 and t["worst_collector_state"] == "excellent"
    assert t["ingest_counters"]["accepted"] == 1


def test_event_ids_and_fields_validated(client):
    assert post(client, metric(1, event_id="has space")).status_code == 422
    assert post(client, metric(1, metric_value="nan")).status_code == 422
    assert post(client, metric(1, severity="loud")).status_code == 422
    ev = metric(1); del ev["metric_name"]
    assert post(client, ev).status_code == 422
    assert post(client, metric(1, event_type="raw_log")).status_code == 422


# ---- integration additions: exact bytes, rejections as evidence, CORS, AIOps ----------

def test_egress_record_holds_exact_bytes_and_both_hashes(client):
    raw = json.dumps(metric(), indent=2).encode()  # deliberately not canonical
    r = post(client, None, raw=raw)
    j = r.json()
    assert j["sender_sha256"] == j["backend_sha256"] == hashlib.sha256(raw).hexdigest()
    rec = client.get("/api/v1/events/recent", headers=auth()).json()["data"]["egress_audit"][0]
    assert rec["sent_payload_exact"] == raw.decode()          # byte-for-byte what was received
    assert hashlib.sha256(rec["sent_payload_exact"].encode()).hexdigest() == rec["backend_sha256"]
    assert rec["sender_sha256"] == rec["backend_sha256"] and rec["hash_match"] is True
    assert rec["verification_status"] == "verified" and rec["acknowledgement"]["status"] == "accepted"
    assert rec["policy_version"] == "v1" and rec["event_id"] == "evt-000001"


def test_rejections_are_visible_but_bodies_never_stored(client):
    secret = "sk-live-4eC39HqLyjWDarjtT1zdp7dc"
    r = post(client, metric(1, note=secret))           # unknown field carrying a secret
    assert r.status_code == 422 and secret not in r.text
    r = post(client, metric(2), sha="0" * 64)
    assert r.status_code == 400
    d = client.get("/api/v1/events/recent", headers=auth()).json()["data"]
    assert d["events"] == [] and d["egress_summary"]["rejected"] == 2
    statuses = {x["verification_status"] for x in d["egress_audit"]}
    assert statuses == {"rejected", "hash_mismatch"}
    assert secret not in json.dumps(d)                 # rejected bodies are never retained
    hm = [x for x in d["egress_audit"] if x["verification_status"] == "hash_mismatch"][0]
    assert hm["hash_match"] is False and hm["sender_sha256"] == "0" * 64 and hm["backend_sha256"] != "0" * 64


def test_duplicate_delivery_counted(client):
    ev = metric()
    post(client, ev); post(client, ev); post(client, ev)
    d = client.get("/api/v1/events/recent", headers=auth()).json()["data"]
    assert d["egress_summary"]["duplicate_deliveries"] == 2 and len(d["events"]) == 1


def test_cors_allows_vite_dev_server(client):
    r = client.options("/api/v1/fleet", headers={"Origin": "http://localhost:5173",
                       "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"})
    assert r.status_code == 200 and r.headers["access-control-allow-origin"] == "http://localhost:5173"
    r = client.options("/api/v1/fleet", headers={"Origin": "http://evil.example",
                       "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in r.headers


def test_metric_alias_normalised_for_dashboard_but_wire_kept(client):
    post(client, metric(1, metric_name="cpu_usage"))
    d = client.get("/api/v1/events/recent", headers=auth()).json()["data"]
    assert d["events"][0]["metric_name"] == "cpu_percent" and d["events"][0]["original_metric_name"] == "cpu_usage"
    assert json.loads(d["egress_audit"][0]["sent_payload_exact"])["metric_name"] == "cpu_usage"


def test_incidents_endpoint_empty_is_well_formed(client):
    d = client.get("/api/v1/incidents", headers=auth()).json()["data"]
    assert d["incidents"] == [] and d["anomalies"] == [] and d["dependency_graph"]["nodes"]


def test_health_has_aiops_contract_fields(client):
    post(client, heartbeat(1))
    h = client.get("/api/v1/health", headers=auth()).json()["data"]
    for k in ("status", "engine", "graph_engine", "active_incidents", "healthy_collectors",
              "unhealthy_collectors", "anomaly_count"):
        assert k in h
    assert h["healthy_collectors"] == 1 and h["status"] == "healthy"
