# Aegis API Response Contract (Coordination with Backend / Person 2)

This document defines the JSON response schemas expected by the React dashboard (`frontend/src/services/apiClient.js`) and produced by the deterministic AIOps engine (`aiops/pipeline.py`). The shared event schema (`shared/event_schema.json`) is left untouched.

## 1. `GET /api/v1/health`

```json
{
  "status": "healthy | degraded",
  "engine": "aegis-aiops-deterministic",
  "graph_engine": "networkx",
  "active_incidents": 1,
  "healthy_collectors": 3,
  "unhealthy_collectors": 1,
  "anomaly_count": 9
}
```

## 2. `GET /api/v1/events/recent`

Returns approved telemetry events plus privacy/egress verification metadata.

```json
{
  "events": [
    {
      "event_id": "corr-m-0800",
      "collector_id": "col-db-01",
      "event_type": "metric",
      "service_id": "database",
      "timestamp_utc": "2026-11-20T10:03:00Z",
      "source_timezone": "Asia/Kolkata",
      "region": "ap-south-1",
      "severity": "critical",
      "policy_version": "aegis-privacy-v1.2",
      "metric_name": "cpu_percent",
      "metric_value": 86.0,
      "unit": "percent",
      "window_seconds": 30,
      "health_scope": "service",
      "resource_id": "db-primary-01",
      "dependency_id": "none"
    }
  ],
  "egress_audit": [
    {
      "event_id": "corr-m-0800",
      "event_type": "metric",
      "service_id": "database",
      "collector_id": "col-db-01",
      "timestamp_utc": "2026-11-20T10:03:00Z",
      "policy_version": "aegis-privacy-v1.2",
      "approved_payload": {},
      "sha256_hash": "<64-char hex digest>",
      "verification_status": "verified"
    }
  ]
}
```

> Compatibility note: `apiClient.js` also accepts a bare array of events from `GET /api/v1/events/recent` and computes client-side SHA-256 hashes automatically if `egress_audit` is omitted by the backend.

## 3. `GET /api/v1/fleet`

```json
{
  "collectors": [
    {
      "collector_id": "col-db-01",
      "tenant": "acme-payments",
      "region": "ap-south-1",
      "service_id": "database",
      "health_state": "healthy | degraded | unhealthy | offline",
      "last_heartbeat": "2026-11-20T10:05:00Z",
      "last_telemetry": "2026-11-20T10:05:00Z",
      "queue_backlog": 240,
      "collector_version": "0.4.2"
    }
  ]
}
```

## 4. `GET /api/v1/incidents`

```json
{
  "incidents": [
    {
      "incident_id": "INC-0001",
      "title": "Correlated Payment Path Degradation — Suspected Database Contributor",
      "severity": "critical",
      "status": "active",
      "first_observed_utc": "2026-11-20T10:04:00Z",
      "affected_services": [{"service_id": "database", "label": "Database"}],
      "related_metric_deviations": [],
      "dependency_path": ["API Gateway -> Payment Service -> Database"],
      "timeline": [],
      "supporting_evidence": [],
      "contradicting_evidence": [],
      "root_cause_hypotheses": [
        {
          "rank": 1,
          "service_id": "database",
          "service_label": "Database",
          "hypothesis": "Sustained CPU saturation on Database",
          "is_hypothesis": true,
          "confidence_score": 0.88,
          "confidence_label": "High-priority hypothesis (not confirmed)",
          "ranking_explanation": "...",
          "supporting_evidence": [],
          "contradicting_evidence": []
        }
      ],
      "confidence_explanation": "...",
      "recommended_action": {
        "action": "...",
        "approval_required": true,
        "approval_status": "pending_human_approval",
        "rollback_note": "...",
        "audit_records": []
      }
    }
  ],
  "anomalies": [],
  "dependency_graph": {
    "nodes": [],
    "edges": []
  }
}
```
