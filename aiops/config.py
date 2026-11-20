"""Configurable thresholds and runtime parameters for the Aegis AIOps engine."""

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class MetricThresholdConfig:
    """Static cold-start thresholds and rolling statistical parameters for a metric."""

    warning_threshold: float
    critical_threshold: float
    z_score_warning: float = 2.5
    z_score_critical: float = 3.5
    min_absolute_delta: float = 1.0
    unit: str = ""
    require_sustained: bool = True


@dataclass
class AIOpsConfig:
    """Top-level configuration for deterministic anomaly detection and incident correlation."""

    rolling_window_size: int = 20
    min_baseline_samples: int = 5
    min_consecutive_deviations: int = 3
    correlation_window_seconds: int = 300
    collector_offline_timeout_seconds: int = 120
    auth_failure_warning_threshold: int = 15
    auth_failure_critical_threshold: int = 50
    max_root_cause_hypotheses: int = 3
    metrics: Dict[str, MetricThresholdConfig] = field(
        default_factory=lambda: {
            "cpu_percent": MetricThresholdConfig(
                warning_threshold=80.0,
                critical_threshold=92.0,
                z_score_warning=2.5,
                z_score_critical=3.5,
                min_absolute_delta=8.0,
                unit="percent",
                require_sustained=True,
            ),
            "memory_percent": MetricThresholdConfig(
                warning_threshold=82.0,
                critical_threshold=94.0,
                z_score_warning=2.5,
                z_score_critical=3.5,
                min_absolute_delta=6.0,
                unit="percent",
                require_sustained=True,
            ),
            "latency_ms": MetricThresholdConfig(
                warning_threshold=250.0,
                critical_threshold=500.0,
                z_score_warning=2.5,
                z_score_critical=3.5,
                min_absolute_delta=40.0,
                unit="ms",
                require_sustained=True,
            ),
            "packet_loss_percent": MetricThresholdConfig(
                warning_threshold=2.0,
                critical_threshold=5.0,
                z_score_warning=2.5,
                z_score_critical=3.5,
                min_absolute_delta=1.0,
                unit="percent",
                require_sustained=True,
            ),
        }
    )


DEFAULT_CONFIG = AIOpsConfig()
