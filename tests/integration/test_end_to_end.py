"""End-to-end acceptance: collector -> backend -> AIOps -> incident API, all real components."""

import hashlib
import json
import sqlite3

import pytest
import requests

from collector.simulator import FAKE_API_KEY, FAKE_CARD, FAKE_EMAIL

from .harness import TOKEN_A, TOKEN_B, BackendServer, Clock, CollectorRig


@pytest.fixture
def stack(tmp_path):
    clock = Clock()
    srv = BackendServer(str(tmp_path / "backend.db"), clock).start()
    rig = CollectorRig(tmp_path, srv.url, clock)
    yield srv, rig, clock
    rig.close()
    srv.stop()


def run_latency_scenario(srv, rig, ticks=15):
    for _ in range(ticks):
        rig.tick("payment_latency_spike")
    srv.flush_aiops()


def incidents(srv, token=TOKEN_A):
    return srv.get("/api/v1/incidents", token).json()["data"]


# ---------- the required acceptance scenario ----------------------------------------------------

def test_payment_latency_spike_end_to_end(stack):
    srv, rig, clock = stack
    # steps 5-8: the collector processes events, passes the allow-list, writes the outbox BEFORE sending
    for _ in range(3):
        rig.tick("payment_latency_spike", send=False)
    assert rig.store.backlog() > 0                       # outbox holds them (nothing sent yet)
    assert rig.collector.stats["blocked"] == 0           # allow-list let the approved events through
    prepared = [r for r in rig.store.audit_records() if r[2] == "prepared"]
    assert len(prepared) == rig.store.backlog()          # audit record exists for each queued event
    rig.drain()
    for _ in range(12):
        rig.tick("payment_latency_spike")
    srv.flush_aiops()
    assert rig.store.backlog() == 0 and rig.sender.consecutive_failures == 0

    # steps 9-11: reached FastAPI, authenticated, stored, hashes match the collector's own record
    recent = srv.get("/api/v1/events/recent", limit=500).json()["data"]
    eg = {r["event_id"]: r for r in recent["egress_audit"] if r["verification_status"] == "verified"}
    assert set(rig.emitted) == set(eg), "every emitted event arrived exactly once"
    collector_hash = {r[3]: r[4] for r in rig.store.audit_records() if r[2] == "prepared"}
    for eid, rec in eg.items():
        assert rec["sender_sha256"] == rec["backend_sha256"] == collector_hash[eid]
        assert hashlib.sha256(rec["sent_payload_exact"].encode()).hexdigest() == rec["backend_sha256"]
        assert rec["acknowledgement"]["status"] == "accepted"
    ok, bad = rig.store.verify_audit_chain()
    assert ok, f"collector audit chain broken at {bad}"

    # steps 12-14: AIOps detected it, correlated it, and the incident is retrievable from the backend
    d = incidents(srv)
    lat = [a for a in d["anomalies"] if a["service_id"] == "payment-service" and a["metric_name"] == "latency_ms"]
    assert lat and lat[0]["detection_mode"] in ("baseline-based", "threshold-based") and lat[0]["sustained"]
    assert len(d["incidents"]) == 1
    inc = d["incidents"][0]
    assert inc["incident_id"] == "INC-0001" and inc["severity"] == "critical"
    assert "payment-service" in [s["service_id"] for s in inc["affected_services"]]
    top = inc["root_cause_hypotheses"][0]
    assert top["rank"] == 1 and top["service_id"] == "payment-service" and top["is_hypothesis"] is True
    assert top["supporting_evidence"], "evidence attached"
    # evidence must point at real stored events, never invented ones
    stored_ids = {e["event_id"] for e in recent["events"]}
    anomaly_ids = {e for a in d["anomalies"] for e in a["supporting_event_ids"]}
    assert anomaly_ids and anomaly_ids <= stored_ids
    # the database was healthy in this scenario: it must NOT be ranked as the cause
    assert all(h["service_id"] != "database" or h["rank"] > 1 for h in inc["root_cause_hypotheses"])
    assert inc["recommended_action"]["approval_required"] is True       # human-approved, simulated only
    assert inc["recommended_action"]["approval_status"] == "pending_human_approval"

    # health endpoint reflects it
    h = srv.get("/api/v1/health").json()["data"]
    assert h["active_incidents"] == 1 and h["status"] == "degraded" and h["aiops_errors"] == 0

    # step 15 (dashboard) is covered by the vitest suite in frontend/ against this same real API


def test_incident_ids_stable_and_not_duplicated_on_refresh(stack):
    srv, rig, clock = stack
    run_latency_scenario(srv, rig)
    first = incidents(srv)["incidents"]
    for _ in range(3):
        srv.app.state.aiops.refresh("tenant-a")
    rig.tick("payment_latency_spike"); srv.flush_aiops()
    again = incidents(srv)["incidents"]
    assert [i["incident_id"] for i in again] == [i["incident_id"] for i in first] == ["INC-0001"]


# ---------- security / failure-mode tests ----------------------------------------------------------

def test_secret_containing_raw_logs_never_reach_backend(stack, tmp_path):
    srv, rig, clock = stack
    for _ in range(4):
        rig.tick("secret_injection")
    srv.flush_aiops()
    # the raw lines are kept locally ...
    assert rig.store.raw_count() >= 4
    # ... and nowhere in the backend: not in its database, not in any API response
    conn = sqlite3.connect(srv.db_path)
    dump = "\n".join(conn.iterdump())
    conn.close()
    api = "".join(srv.get(p, limit=500).text for p in
                  ("/api/v1/events/recent", "/api/v1/fleet", "/api/v1/incidents", "/api/v1/health"))
    for secret in (FAKE_API_KEY, FAKE_EMAIL, FAKE_CARD, "4111"):
        assert secret not in dump and secret not in api


def test_auth_failure_burst_sends_only_a_summary(stack):
    srv, rig, clock = stack
    for _ in range(5):
        rig.tick("auth_attack")
    srv.flush_aiops()
    recent = srv.get("/api/v1/events/recent", limit=500).json()["data"]
    summaries = [e for e in recent["events"] if e["event_type"] == "auth_failure_summary"]
    assert summaries and all("username" not in e and "ip_address" not in e for e in summaries)
    text = json.dumps(recent)
    assert "alice" not in text and "203.0.113" not in text


def test_backend_outage_and_recovery_no_loss_no_duplicates(tmp_path):
    clock = Clock()
    db = str(tmp_path / "backend.db")
    srv = BackendServer(db, clock).start()
    port = srv.port
    rig = CollectorRig(tmp_path, srv.url, clock)
    try:
        for _ in range(3):
            rig.tick("normal")
        sent_before = set(rig.emitted)
        srv.stop()                                         # backend goes down
        for _ in range(4):
            rig.tick("normal")                             # collector keeps working
        assert rig.store.backlog() > 0 and rig.sender.consecutive_failures >= 1
        queued = {r.event_id: r.payload for r in rig.store.due(clock() + 10_000, 10_000)}
        assert queued and not (set(queued) & sent_before)
        health_while_down = rig.collector.collector_health(rig.sender.consecutive_failures)
        assert health_while_down in ("good", "fair", "poor")  # collector reports degraded state honestly

        srv = BackendServer(db, clock, port=port).start()  # backend returns (same DB, same port)
        clock.advance(120)                                 # past any backoff
        rig.drain()
        assert rig.store.backlog() == 0                    # delivered only after real acks
        got = srv.get("/api/v1/events/recent", limit=500).json()["data"]
        ids = [e["event_id"] for e in got["egress_audit"] if e["verification_status"] == "verified"]
        assert len(ids) == len(set(ids)) and set(ids) == set(rig.emitted)   # no loss, no duplicates
        # same event_id and byte-identical payload after retry
        for rec in got["egress_audit"]:
            if rec["event_id"] in queued:
                assert rec["sent_payload_exact"].encode() == queued[rec["event_id"]]
                assert "late" in rec["flags"]
    finally:
        rig.close(); srv.stop()


def test_duplicate_delivery_is_ignored(stack):
    srv, rig, clock = stack
    run_latency_scenario(srv, rig)
    rec = srv.get("/api/v1/events/recent", limit=500).json()["data"]["egress_audit"][0]
    n_before = len(srv.get("/api/v1/events/recent", limit=500).json()["data"]["events"])
    for _ in range(3):
        r = requests.post(srv.url + "/api/v1/events", data=rec["sent_payload_exact"].encode(), timeout=5,
                          headers={"Authorization": f"Bearer {TOKEN_A}", "Content-Type": "application/json",
                                   "X-Content-SHA256": rec["sender_sha256"]})
        assert r.status_code == 200 and r.json()["status"] == "duplicate"
    after = srv.get("/api/v1/events/recent", limit=500).json()["data"]
    assert len(after["events"]) == n_before and after["egress_summary"]["duplicate_deliveries"] == 3
    srv.flush_aiops()
    assert len(incidents(srv)["incidents"]) == 1


def test_invalid_schema_rejected_and_visible_as_evidence(stack):
    srv, rig, clock = stack
    bad = json.dumps({"event_id": "evt-x", "event_type": "raw_log", "message": "password=hunter2"}).encode()
    r = requests.post(srv.url + "/api/v1/events", data=bad, timeout=5, headers={
        "Authorization": f"Bearer {TOKEN_A}", "X-Content-SHA256": hashlib.sha256(bad).hexdigest()})
    assert r.status_code == 422 and "hunter2" not in r.text
    d = srv.get("/api/v1/events/recent").json()["data"]
    assert d["egress_summary"]["rejected"] == 1 and "hunter2" not in json.dumps(d)


def test_tampered_payload_rejected_by_backend_hash_check(stack):
    srv, rig, clock = stack
    rig.tick("normal", send=False)
    row = rig.store.due(clock() + 10_000, 1)[0]
    tampered = row.payload.replace(b"info", b"crit", 1)
    r = requests.post(srv.url + "/api/v1/events", data=tampered, timeout=5, headers={
        "Authorization": f"Bearer {TOKEN_A}", "X-Content-SHA256": row.sha256})
    assert r.status_code == 400 and r.json()["code"] == "hash_mismatch"
    assert r.json()["backend_sha256"] == hashlib.sha256(tampered).hexdigest() != row.sha256


def test_cross_tenant_access_rejected_and_data_separated(stack):
    srv, rig, clock = stack
    run_latency_scenario(srv, rig)
    assert srv.get("/api/v1/incidents", TOKEN_B, tenant_id="tenant-a").status_code == 403
    assert srv.get("/api/v1/events/recent", TOKEN_B, tenant_id="tenant-a").status_code == 403
    b = incidents(srv, TOKEN_B)
    assert b["incidents"] == [] and b["anomalies"] == []
    assert srv.get("/api/v1/fleet", TOKEN_B).json()["data"]["collectors"] == []
    assert srv.get("/api/v1/fleet", "bad-token").status_code == 401


def test_collector_with_wrong_region_or_token_is_refused(tmp_path):
    clock = Clock()
    srv = BackendServer(str(tmp_path / "b.db"), clock).start()
    try:
        # tenant-b's token only accepts region eu-west; this collector reports ap-south
        rig = CollectorRig(tmp_path, srv.url, clock, token=TOKEN_B)
        rig.tick("normal")
        assert rig.store.backlog() > 0 and rig.sender.consecutive_failures >= 1   # kept, not lost
        assert srv.get("/api/v1/events/recent", TOKEN_B).json()["data"]["events"] == []
        rej = srv.get("/api/v1/events/recent", TOKEN_B).json()["data"]["egress_summary"]["rejected"]
        assert rej >= 1
        rig.close()
        rig = CollectorRig(tmp_path, srv.url, clock, token="nope")  # same outbox file, bad token
        rig.tick("normal")
        assert rig.sender.consecutive_failures >= 1
        rig.close()
    finally:
        srv.stop()


def test_missing_heartbeat_makes_collector_poor_and_raises_offline_anomaly(stack):
    srv, rig, clock = stack
    for _ in range(6):
        rig.tick("normal")
    c = srv.get("/api/v1/fleet").json()["data"]["collectors"][0]
    assert c["collector_health"]["state"] == "excellent"
    clock.advance(50)                                      # collector silent for > 45 s
    srv.app.state.aiops.refresh("tenant-a")
    c = srv.get("/api/v1/fleet").json()["data"]["collectors"][0]
    assert c["collector_health"]["state"] == "poor"
    assert "no heartbeat" in c["collector_health"]["reasons"][0]
    d = incidents(srv)
    assert any(a["metric_name"] == "collector_heartbeat_gap_seconds" for a in d["anomalies"])
    assert srv.get("/api/v1/health").json()["data"]["status"] == "degraded"


def test_empty_tenant_gets_well_formed_empty_responses(stack):
    srv, rig, clock = stack
    for path, keys in (("/api/v1/events/recent", ("events", "egress_audit", "egress_summary")),
                       ("/api/v1/fleet", ("collectors", "infrastructure")),
                       ("/api/v1/incidents", ("incidents", "anomalies", "dependency_graph"))):
        r = srv.get(path, TOKEN_B)
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok" and all(k in body["data"] for k in keys)
    h = srv.get("/api/v1/health", TOKEN_B).json()["data"]
    assert h["active_incidents"] == 0 and h["status"] == "healthy"


def test_aiops_failure_never_loses_the_accepted_event(tmp_path, monkeypatch):
    clock = Clock()
    srv = BackendServer(str(tmp_path / "b.db"), clock, aiops_mode="sync").start()
    rig = CollectorRig(tmp_path, srv.url, clock)
    try:
        import aiops.pipeline as pl
        monkeypatch.setattr(pl.AegisAIOpsPipeline, "run", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        rig.tick("normal")
        assert rig.store.backlog() == 0                     # still acknowledged and removed
        d = srv.get("/api/v1/events/recent").json()["data"]
        assert len(d["events"]) > 0                         # event stored despite AIOps failure
        inc = incidents(srv)
        assert inc["analysis"]["errors"] and "boom" in inc["analysis"]["errors"][0]["error"]
        assert srv.get("/api/v1/health").json()["data"]["aiops_errors"] >= 1
    finally:
        rig.close(); srv.stop()


def test_recent_events_are_returned_in_event_time_order_even_when_delivered_out_of_order(stack):
    """Regression: /events/recent used arrival order, so late deliveries drew charts backwards."""
    import requests
    srv, rig, clock = stack
    for _ in range(8):
        rig.tick("payment_latency_spike", send=False)
    rows = rig.store.due(clock() + 1e6, 10000)
    assert len(rows) > 10
    for r in reversed(rows):  # newest first -> maximally out of order
        resp = requests.post(srv.url + "/api/v1/events", data=r.payload, timeout=5, headers={
            "Authorization": f"Bearer {TOKEN_A}", "X-Content-SHA256": r.sha256})
        assert resp.status_code == 200, resp.text
        rig.store.ack(r.event_id, clock())
    events = srv.get("/api/v1/events/recent", limit=500).json()["data"]["events"]
    stamps = [e["timestamp_utc"] for e in events]
    assert len(stamps) == len(rows)
    assert stamps == sorted(stamps)
