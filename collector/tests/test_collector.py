import json
import sqlite3

import pytest

from collector.egress import serialize_event, sha256_hex
from collector.policy import PolicyViolation, enforce_allowlist, validate_outbound
from collector.redaction import find_sensitive, redact
from collector.simulator import FAKE_API_KEY, FAKE_CARD, FAKE_EMAIL


def metric_rec(**kw):
    rec = {"kind": "metric", "service_id": "payment-api", "metric_name": "cpu_usage",
           "value": 42.0, "unit": "percent"}
    rec.update(kw)
    return rec


# 1. fake API key never appears in any outbound payload
def test_secret_never_in_outbound_payloads(make, saas):
    cfg, store, col, sender = make()
    col.ingest(metric_rec(raw_line=f"api_key={FAKE_API_KEY} {FAKE_EMAIL} {FAKE_CARD}"))
    # also try to smuggle it through a candidate field
    col.emit({"event_type": "metric", "service_id": "payment-api", "metric_name": "cpu_usage",
              "metric_value": 1, "unit": "percent", "note": FAKE_API_KEY})
    col.heartbeat()
    sender.drain()
    sender.drain()
    assert saas.received
    for _, body in saas.received:
        for secret in (FAKE_API_KEY, FAKE_EMAIL, FAKE_CARD, "4111"):
            assert secret.encode() not in body
    # the raw line is kept locally only
    assert store.raw_count() == 1


# 2. unknown fields are rejected
def test_unknown_fields_rejected():
    ev = {"event_type": "heartbeat", "health_scope": "collector", "health_state": "good",
          "collector_version": "0.1.0", "event_id": "evt-000001", "collector_id": "c1",
          "timestamp_utc": "2026-01-01T00:00:00Z", "source_timezone": "Asia/Kolkata",
          "region": "ap-south", "severity": "info", "policy_version": "v1"}
    validate_outbound(ev)
    with pytest.raises(PolicyViolation):
        validate_outbound({**ev, "username": "alice"})
    clean, dropped = enforce_allowlist({**ev, "username": "alice"})
    assert "username" not in clean and dropped == ["username"]


def test_secret_in_allowed_field_is_blocked(make):
    cfg, store, col, sender = make()
    # service_id is allow-listed but must still be a clean identifier
    out = col.emit({"event_type": "metric", "service_id": f"api_key={FAKE_API_KEY}",
                    "metric_name": "cpu_usage", "metric_value": 1, "unit": "percent"})
    assert out is None and store.backlog() == 0
    assert any("blocked" in v[2] for v in store.violations())
    # violation log never stores the secret value
    assert all(FAKE_API_KEY not in str(v) for v in store.violations())


# 3. raw auth records never leave; only a summary does
def test_raw_auth_records_never_leave(make, saas):
    cfg, store, col, sender = make(auth_threshold=3, auth_window_seconds=60)
    for i in range(5):
        col.ingest({"kind": "auth", "service_id": "auth-service", "outcome": "failure",
                    "raw_line": f"login failed user=alice{i} ip=203.0.113.{i}"})
    sender.drain()
    sender.drain()
    sender.drain()
    types = [json.loads(b)["event_type"] for _, b in saas.received]
    assert types == ["auth_failure_summary"]  # early summary only so far
    for _, body in saas.received:
        assert b"alice" not in body and b"203.0.113" not in body
    assert store.raw_count() == 5


def test_auth_final_summary_at_window_close(make, saas, clock):
    cfg, store, col, sender = make(auth_threshold=3, auth_window_seconds=60)
    for _ in range(5):
        col.ingest({"kind": "auth", "service_id": "auth-service", "outcome": "failure"})
    clock.advance(61)
    col.tick()
    sender.drain()
    sender.drain()
    counts = [json.loads(b)["failure_count"] for _, b in saas.received]
    assert counts == [3, 5]


# 4. SHA-256 matches exact transmitted bytes
def test_hash_matches_transmitted_bytes(make, saas):
    cfg, store, col, sender = make()
    col.ingest(metric_rec())
    sender.drain()
    headers, body = saas.received[0]
    assert headers["X-Content-SHA256"] == sha256_hex(body)
    assert headers["Authorization"] == "Bearer test-token"
    ev = json.loads(body)
    assert "sha256" not in ev and "hash" not in body.decode()  # hash is not inside the bytes
    assert serialize_event(ev) == body  # deterministic serialization


# 5. failed delivery retains the event in SQLite
def test_failed_delivery_retains_event(make, saas, clock):
    cfg, store, col, sender = make()
    saas.status = 503
    eid = col.ingest(metric_rec())[0]
    res = sender.drain()
    assert res["failed"] == 1
    assert store.backlog() == 1
    row = store.get(eid)
    assert row.attempts == 1 and row.next_attempt_at > clock()
    # survives a process restart: reopen the DB file
    conn = sqlite3.connect(cfg.db_path)
    assert conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 1
    conn.close()


# 6. successful ack removes it
def test_ack_removes_event(make, saas):
    cfg, store, col, sender = make()
    col.ingest(metric_rec())
    assert store.backlog() == 1
    assert sender.drain()["sent"] == 1
    assert store.backlog() == 0


# 7. retry does not create a new event_id and re-sends identical bytes
def test_retry_same_event_id_and_bytes(make, saas, clock):
    cfg, store, col, sender = make()
    saas.status = 500
    eid = col.ingest(metric_rec())[0]
    sender.drain()
    clock.advance(120)
    sender.drain()
    saas.status = 200
    clock.advance(120)
    sender.drain()
    assert len(saas.received) == 3
    bodies = [b for _, b in saas.received]
    assert len(set(bodies)) == 1
    assert json.loads(bodies[0])["event_id"] == eid
    assert store.backlog() == 0


# extras
def test_backoff_is_exponential_and_capped(make):
    cfg, store, col, sender = make(backoff_base=1.0, backoff_max=8.0)
    assert [sender._backoff(a) for a in range(5)] == [1.0, 2.0, 4.0, 8.0, 8.0]


def test_event_ids_unique_across_restart(make, tmp_path):
    cfg, store, col, sender = make()
    a = col.ingest(metric_rec())[0]
    store.close()
    from collector.store import Store
    store2 = Store(cfg.db_path)
    b, _ = store2.allocate_event_id()
    assert a != b
    store2.close()


def test_audit_chain_detects_tampering(make):
    cfg, store, col, sender = make()
    for _ in range(3):
        col.ingest(metric_rec())
    assert store.verify_audit_chain() == (True, None)
    conn = sqlite3.connect(cfg.db_path)
    conn.execute("UPDATE audit SET sha256='f'*0 || 'deadbeef' WHERE id=2")
    conn.commit()
    conn.close()
    ok, bad = store.verify_audit_chain()
    assert not ok and bad == 2


def test_raw_logs_expire(make, clock):
    cfg, store, col, sender = make(raw_retention_seconds=10)
    col.ingest(metric_rec(raw_line="hello"))
    assert store.raw_count() == 1
    clock.advance(11)
    col.tick()
    assert store.raw_count() == 0


def test_heartbeat_health_states(make, saas):
    cfg, store, col, sender = make()
    assert col.collector_health(0) == "excellent"
    assert col.collector_health(1) == "good"
    assert col.collector_health(2) == "fair"
    assert col.collector_health(5) == "poor"
    col.heartbeat()
    sender.drain()
    ev = json.loads(saas.received[0][1])
    assert ev["event_type"] == "heartbeat" and ev["health_scope"] == "collector"


def test_redaction_counts_only():
    text = f"key={FAKE_API_KEY} mail={FAKE_EMAIL} card={FAKE_CARD}"
    hits = find_sensitive(text)
    assert {"api_key", "email", "card_number"} <= set(hits)
    masked, counts = redact(text)
    assert FAKE_API_KEY not in masked and FAKE_EMAIL not in masked and "4111" not in masked
    assert counts == hits


def test_numeric_noise_not_flagged():
    # event ids and plain metrics must not trip the outbound scan
    assert find_sensitive("evt-000123 2026-01-01T00:00:00Z 42.5") == {}
