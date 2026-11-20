"""Deterministic anomaly detector for Aegis infrastructure telemetry.

Features:
- Analyses CPU, memory, latency, and packet-loss metrics (plus auth failures and heartbeats).
- Rolling statistical baselines (mean + sample standard deviation) with configurable thresholds.
- Static threshold fallback for cold-start situations (< min_baseline_samples).
- Requires at least N consecutive deviations (default 3) for sustained metric anomalies.
- Explicitly labels every result as 'baseline-based' or 'threshold-based'.
- Purely deterministic: zero LLM involvement in detection.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

from .config import AIOpsConfig, DEFAULT_CONFIG, MetricThresholdConfig
from .schema import validate_event


def parse_utc_timestamp(ts: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp string into an aware datetime."""
    cleaned = ts.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass
class AnomalyRecord:
    """Structured anomaly produced by the deterministic detector."""

    anomaly_id: str
    event_id: str
    collector_id: str
    service_id: str
    region: str
    timestamp_utc: str
    event_type: str
    metric_name: str
    metric_value: float
    unit: str
    severity: str  # warning | critical
    detection_mode: str  # baseline-based | threshold-based
    sustained: bool
    consecutive_count: int
    baseline_mean: Optional[float]
    baseline_std: Optional[float]
    z_score: Optional[float]
    threshold_used: float
    reason: str
    supporting_event_ids: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DeterministicAnomalyDetector:
    """Stateful deterministic anomaly detector over approved Aegis events."""

    SUPPORTED_METRICS = {
        "cpu_percent",
        "memory_percent",
        "latency_ms",
        "packet_loss_percent",
    }

    def __init__(self, config: Optional[AIOpsConfig] = None) -> None:
        self.config = config or DEFAULT_CONFIG
        # Rolling healthy baseline windows keyed by (service_id, resource_id, metric_name)
        self._baselines: Dict[Tuple[str, str, str], Deque[float]] = defaultdict(
            lambda: deque(maxlen=self.config.rolling_window_size)
        )
        # Consecutive deviation buffers keyed by (service_id, resource_id, metric_name)
        self._pending_deviations: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
        # Last known heartbeat per collector
        self._last_heartbeat: Dict[str, Dict[str, Any]] = {}
        self._anomaly_seq = 0

    def _next_id(self) -> str:
        self._anomaly_seq += 1
        return f"anom-{self._anomaly_seq:04d}"

    def _evaluate_metric_point(
        self,
        key: Tuple[str, str, str],
        value: float,
        metric_cfg: MetricThresholdConfig,
    ) -> Dict[str, Any]:
        """Evaluate a single metric reading against rolling baseline or cold-start static threshold."""
        window = self._baselines[key]
        if len(window) >= self.config.min_baseline_samples:
            mean = sum(window) / len(window)
            variance = sum((x - mean) ** 2 for x in window) / max(len(window) - 1, 1)
            std = math.sqrt(variance)
            effective_std = max(std, metric_cfg.min_absolute_delta / 3.0)
            z_score = (value - mean) / effective_std
            delta = value - mean

            # Must exceed z-score AND a minimum absolute delta to avoid micro-jitter noise.
            if z_score >= metric_cfg.z_score_critical and delta >= metric_cfg.min_absolute_delta:
                severity = "critical"
                is_deviating = True
                threshold_used = round(mean + metric_cfg.z_score_critical * effective_std, 2)
            elif z_score >= metric_cfg.z_score_warning and delta >= metric_cfg.min_absolute_delta:
                severity = "warning"
                is_deviating = True
                threshold_used = round(mean + metric_cfg.z_score_warning * effective_std, 2)
            elif value >= metric_cfg.critical_threshold:
                # Hard ceiling safeguard even if baseline drifted upward
                severity = "critical"
                is_deviating = True
                threshold_used = metric_cfg.critical_threshold
            else:
                severity = "normal"
                is_deviating = False
                threshold_used = round(mean + metric_cfg.z_score_warning * effective_std, 2)

            return {
                "is_deviating": is_deviating,
                "severity": severity,
                "detection_mode": "baseline-based",
                "baseline_mean": round(mean, 2),
                "baseline_std": round(std, 2),
                "z_score": round(z_score, 2),
                "threshold_used": threshold_used,
            }

        # Cold-start static threshold fallback
        if value >= metric_cfg.critical_threshold:
            severity = "critical"
            is_deviating = True
            threshold_used = metric_cfg.critical_threshold
        elif value >= metric_cfg.warning_threshold:
            severity = "warning"
            is_deviating = True
            threshold_used = metric_cfg.warning_threshold
        else:
            severity = "normal"
            is_deviating = False
            threshold_used = metric_cfg.warning_threshold

        return {
            "is_deviating": is_deviating,
            "severity": severity,
            "detection_mode": "threshold-based",
            "baseline_mean": None,
            "baseline_std": None,
            "z_score": None,
            "threshold_used": threshold_used,
        }

    def process_events(
        self,
        events: List[Dict[str, Any]],
        reference_time_utc: Optional[str] = None,
    ) -> List[AnomalyRecord]:
        """Process a chronologically sorted batch of approved events and return detected anomalies."""
        sorted_events = sorted(events, key=lambda e: parse_utc_timestamp(e["timestamp_utc"]))
        anomalies: List[AnomalyRecord] = []

        for event in sorted_events:
            is_valid, _ = validate_event(event)
            if not is_valid:
                continue

            etype = event["event_type"]
            if etype == "metric":
                anom = self._process_metric_event(event)
                if anom:
                    anomalies.append(anom)
            elif etype == "heartbeat":
                anom = self._process_heartbeat_event(event)
                if anom:
                    anomalies.append(anom)
            elif etype == "auth_failure_summary":
                anom = self._process_auth_failure_event(event)
                if anom:
                    anomalies.append(anom)

        # Check for offline collectors relative to latest event timestamp or explicit reference_time_utc
        if sorted_events:
            ref_dt = (
                parse_utc_timestamp(reference_time_utc)
                if reference_time_utc
                else parse_utc_timestamp(sorted_events[-1]["timestamp_utc"])
            )
            anomalies.extend(self._detect_offline_collectors(ref_dt))

        return anomalies

    def _process_metric_event(self, event: Dict[str, Any]) -> Optional[AnomalyRecord]:
        metric_name = event["metric_name"]
        metric_cfg = self.config.metrics.get(metric_name)
        if not metric_cfg:
            return None

        key = (event["service_id"], event.get("resource_id") or "default", metric_name)
        value = float(event["metric_value"])
        eval_res = self._evaluate_metric_point(key, value, metric_cfg)

        if not eval_res["is_deviating"]:
            # Healthy observation updates the rolling baseline and resets streak.
            self._baselines[key].append(value)
            self._pending_deviations[key].clear()
            return None

        # Deviating observation: record streak without poisoning the rolling baseline.
        streak = self._pending_deviations[key]
        streak.append({"event": event, "eval": eval_res})

        required = (
            self.config.min_consecutive_deviations if metric_cfg.require_sustained else 1
        )
        if len(streak) < required:
            return None

        # Emit sustained anomaly once threshold of consecutive deviations is reached
        # (and on subsequent sustained readings so timeline reflects ongoing persistence).
        consecutive_count = len(streak)
        supporting_ids = [item["event"]["event_id"] for item in streak[-required:]]
        mode = eval_res["detection_mode"]

        if mode == "baseline-based":
            reason = (
                f"Sustained {metric_name} deviation ({consecutive_count} consecutive readings): "
                f"{value} {event['unit']} vs rolling baseline mean {eval_res['baseline_mean']} "
                f"(std {eval_res['baseline_std']}, z={eval_res['z_score']})."
            )
        else:
            reason = (
                f"Cold-start threshold breach ({consecutive_count} consecutive readings): "
                f"{metric_name}={value} {event['unit']} exceeded static threshold "
                f"{eval_res['threshold_used']} {event['unit']}."
            )

        return AnomalyRecord(
            anomaly_id=self._next_id(),
            event_id=event["event_id"],
            collector_id=event["collector_id"],
            service_id=event["service_id"],
            region=event["region"],
            timestamp_utc=event["timestamp_utc"],
            event_type="metric",
            metric_name=metric_name,
            metric_value=value,
            unit=event["unit"],
            severity=eval_res["severity"],
            detection_mode=mode,
            sustained=True,
            consecutive_count=consecutive_count,
            baseline_mean=eval_res["baseline_mean"],
            baseline_std=eval_res["baseline_std"],
            z_score=eval_res["z_score"],
            threshold_used=eval_res["threshold_used"],
            reason=reason,
            supporting_event_ids=supporting_ids,
        )

    def _process_heartbeat_event(self, event: Dict[str, Any]) -> Optional[AnomalyRecord]:
        collector_id = event["collector_id"]
        self._last_heartbeat[collector_id] = event
        health_state = str(event.get("health_state", "healthy")).lower()
        backlog = float(event.get("queue_backlog") or 0)

        if health_state in {"unhealthy", "offline", "degraded"} or backlog >= 200:
            severity = "critical" if health_state in {"unhealthy", "offline"} or backlog >= 500 else "warning"
            return AnomalyRecord(
                anomaly_id=self._next_id(),
                event_id=event["event_id"],
                collector_id=collector_id,
                service_id=event.get("service_id") or collector_id,
                region=event["region"],
                timestamp_utc=event["timestamp_utc"],
                event_type="heartbeat",
                metric_name="collector_health",
                metric_value=backlog,
                unit="queued_events",
                severity=severity,
                detection_mode="threshold-based",
                sustained=True,
                consecutive_count=1,
                baseline_mean=None,
                baseline_std=None,
                z_score=None,
                threshold_used=200.0,
                reason=(
                    f"Collector {collector_id} reported health_state='{health_state}' "
                    f"with queue_backlog={int(backlog)}."
                ),
                supporting_event_ids=[event["event_id"]],
            )
        return None

    def _process_auth_failure_event(self, event: Dict[str, Any]) -> Optional[AnomalyRecord]:
        failure_count = int(event["failure_count"])
        if failure_count < self.config.auth_failure_warning_threshold:
            return None

        if failure_count >= self.config.auth_failure_critical_threshold:
            severity = "critical"
            threshold_used = float(self.config.auth_failure_critical_threshold)
        else:
            severity = "warning"
            threshold_used = float(self.config.auth_failure_warning_threshold)

        return AnomalyRecord(
            anomaly_id=self._next_id(),
            event_id=event["event_id"],
            collector_id=event["collector_id"],
            service_id=event["service_id"],
            region=event["region"],
            timestamp_utc=event["timestamp_utc"],
            event_type="auth_failure_summary",
            metric_name="auth_failure_count",
            metric_value=float(failure_count),
            unit="failures",
            severity=severity,
            detection_mode="threshold-based",
            sustained=True,
            consecutive_count=1,
            baseline_mean=None,
            baseline_std=None,
            z_score=None,
            threshold_used=threshold_used,
            reason=(
                f"Repeated failed logins detected ({failure_count} failures in "
                f"{event['window_seconds']}s, code={event['summary_code']}) "
                f"exceeding static threshold {int(threshold_used)}."
            ),
            supporting_event_ids=[event["event_id"]],
        )

    def _detect_offline_collectors(self, reference_dt: datetime) -> List[AnomalyRecord]:
        offline_anomalies: List[AnomalyRecord] = []
        timeout = self.config.collector_offline_timeout_seconds

        for collector_id, hb in self._last_heartbeat.items():
            last_dt = parse_utc_timestamp(hb["timestamp_utc"])
            age_seconds = (reference_dt - last_dt).total_seconds()
            if age_seconds > timeout:
                offline_anomalies.append(
                    AnomalyRecord(
                        anomaly_id=self._next_id(),
                        event_id=hb["event_id"],
                        collector_id=collector_id,
                        service_id=hb.get("service_id") or collector_id,
                        region=hb["region"],
                        timestamp_utc=reference_dt.isoformat().replace("+00:00", "Z"),
                        event_type="heartbeat",
                        metric_name="collector_heartbeat_gap_seconds",
                        metric_value=round(age_seconds, 1),
                        unit="seconds",
                        severity="critical",
                        detection_mode="threshold-based",
                        sustained=True,
                        consecutive_count=1,
                        baseline_mean=None,
                        baseline_std=None,
                        z_score=None,
                        threshold_used=float(timeout),
                        reason=(
                            f"Collector {collector_id} missed heartbeats for {int(age_seconds)}s "
                            f"(last seen {hb['timestamp_utc']}, timeout {timeout}s)."
                        ),
                        supporting_event_ids=[hb["event_id"]],
                    )
                )
        return offline_anomalies
