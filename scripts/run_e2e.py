#!/usr/bin/env python3
"""Live end-to-end demonstration with REAL processes and the real clock.

Starts the backend (uvicorn), runs the real collector CLI against it on the payment-latency scenario,
waits for the AIOps incident, checks every acceptance step through the public API, then runs the React
dashboard tests against that same live API. Exits non-zero on any failure.

    python scripts/run_e2e.py            # from the repo root
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
PORT = int(os.environ.get("AEGIS_E2E_PORT", "8765"))
BASE = f"http://127.0.0.1:{PORT}"
TOKEN_A, TOKEN_B = "dev-token-tenant-a", "dev-token-tenant-b"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""), flush=True)
    return bool(ok)


def get(path: str, token: str = TOKEN_A, **params):
    return requests.get(BASE + path, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=5)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="aegis-e2e-"))
    env = dict(os.environ, AEGIS_DB_DSN="dbname=aegis_e2e_db user=aegis_user password=aegis_pass host=127.0.0.1", PYTHONPATH=str(ROOT))
    print(f"working dir: {tmp}\n1) starting backend on {BASE}", flush=True)
    backend = subprocess.Popen([sys.executable, "-m", "uvicorn", "backend.main:app_factory", "--factory",
                                "--port", str(PORT), "--log-level", "warning"], cwd=ROOT, env=env)
    try:
        for _ in range(60):
            try:
                if requests.get(BASE + "/api/v1/health", timeout=1).ok:
                    break
            except requests.RequestException:
                time.sleep(0.25)
        else:
            check("backend starts", False)
            return 1
        check("backend starts (GET /api/v1/health)", True)

        print("2) running the real collector (payment_latency_spike scenario)", flush=True)
        cenv = dict(env, AEGIS_ENDPOINT=BASE + "/api/v1/events", AEGIS_COLLECTOR_TOKEN=TOKEN_A,
                    AEGIS_DB_PATH=str(tmp / "collector.db"), AEGIS_TICK_SECONDS="0.3",
                    AEGIS_HEARTBEAT_SECONDS="1")
        run = subprocess.run([sys.executable, "-m", "collector.main", "run", "--scenario",
                              "payment_latency_spike", "--ticks", "22"], cwd=ROOT, env=cenv,
                             capture_output=True, text=True, timeout=120)
        check("collector ran and finished with exit 0", run.returncode == 0, run.stdout.strip().splitlines()[-1])
        check("outbox drained (backlog=0)", "backlog=0" in run.stdout.strip().splitlines()[-1])
        check("nothing blocked by the allow-list", "blocked=0" in run.stdout.strip().splitlines()[-1])

        print("3) checking the backend through its public API", flush=True)
        deadline = time.time() + 20
        d = {}
        while time.time() < deadline:
            d = get("/api/v1/incidents").json()["data"]
            if d["incidents"]:
                break
            time.sleep(0.5)
        recent = get("/api/v1/events/recent", limit=500).json()["data"]
        verified = [r for r in recent["egress_audit"] if r["verification_status"] == "verified"]
        check("events stored by the backend", len(verified) > 20, f"{len(verified)} verified")
        check("backend SHA-256 == collector SHA-256 for every event",
              all(r["sender_sha256"] == r["backend_sha256"] and
                  hashlib.sha256(r["sent_payload_exact"].encode()).hexdigest() == r["backend_sha256"] for r in verified))
        check("no duplicates stored", len({r["event_id"] for r in verified}) == len(verified))
        check("AIOps detected the payment-service latency anomaly",
              any(a["service_id"] == "payment-service" and a["metric_name"] == "latency_ms" for a in d["anomalies"]),
              f"{len(d['anomalies'])} anomalies")
        inc = d["incidents"][0] if d["incidents"] else None
        check("incident generated and retrievable", inc is not None, inc["incident_id"] if inc else "")
        if inc:
            top = inc["root_cause_hypotheses"][0]
            check("top-ranked hypothesis is payment-service with evidence",
                  top["service_id"] == "payment-service" and len(top["supporting_evidence"]) > 0,
                  f"confidence {top['confidence_score']}, {len(top['supporting_evidence'])} supporting, "
                  f"{len(top['contradicting_evidence'])} contradicting")
        check("tenant-b sees none of it", get("/api/v1/incidents", TOKEN_B).json()["data"]["incidents"] == []
              and get("/api/v1/incidents", TOKEN_B, tenant_id="tenant-a").status_code == 403)
        check("AIOps errors recorded: none", get("/api/v1/health").json()["data"]["aiops_errors"] == 0)

        print("4) React dashboard tests against this live backend", flush=True)
        fenv = dict(os.environ, AEGIS_LIVE_API_URL=BASE, AEGIS_LIVE_API_TOKEN=TOKEN_A)
        ui = subprocess.run(["npm", "run", "test:live", "--silent"], cwd=ROOT / "frontend", env=fenv,
                            capture_output=True, text=True, timeout=180)
        tail = [l for l in ui.stdout.splitlines() if "Tests" in l]
        check("dashboard displays the real incident + evidence + backend egress proof", ui.returncode == 0,
              tail[-1].strip() if tail else ui.stdout[-300:] + ui.stderr[-300:])
    finally:
        backend.terminate()
        try:
            backend.wait(timeout=10)
        except subprocess.TimeoutExpired:
            backend.kill()
        shutil.rmtree(tmp, ignore_errors=True)

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
