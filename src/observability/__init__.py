"""Observability module for logging, metrics, health, and tracing."""

from src.observability.structured_logger import (
    setup_structured_logging,
    set_correlation_id,
    get_correlation_id,
    log_with_context,
    log_detection,
    log_api_call,
    log_error,
)
from src.observability.metrics import (
    MetricsRegistry,
    increment_counter,
    set_gauge,
    observe_histogram,
    get_metrics,
    METRIC_SCANS_TOTAL,
    METRIC_DETECTIONS_TOTAL,
    METRIC_REDIRECT_CHAINS_TOTAL,
    METRIC_API_CALLS_TOTAL,
    METRIC_REPORTS_SENT_TOTAL,
    METRIC_CIRCUIT_BREAKER_STATE,
    METRIC_API_LATENCY_SECONDS,
    METRIC_SCAN_DURATION_SECONDS,
)
from src.observability.health import (
    HealthCheck,
    check_database,
    check_circuit_breakers,
    check_disk_space,
    create_health_checker,
    STATUS_HEALTHY,
    STATUS_DEGRADED,
    STATUS_UNHEALTHY,
)
from src.observability.tracing import (
    Span,
    SpanManager,
    trace_operation,
    span_manager,
)

__all__ = [
    # Logging
    "setup_structured_logging",
    "set_correlation_id",
    "get_correlation_id",
    "log_with_context",
    "log_detection",
    "log_api_call",
    "log_error",
    # Metrics
    "MetricsRegistry",
    "increment_counter",
    "set_gauge",
    "observe_histogram",
    "get_metrics",
    "METRIC_SCANS_TOTAL",
    "METRIC_DETECTIONS_TOTAL",
    "METRIC_REDIRECT_CHAINS_TOTAL",
    "METRIC_API_CALLS_TOTAL",
    "METRIC_REPORTS_SENT_TOTAL",
    "METRIC_CIRCUIT_BREAKER_STATE",
    "METRIC_API_LATENCY_SECONDS",
    "METRIC_SCAN_DURATION_SECONDS",
    # Health
    "HealthCheck",
    "check_database",
    "check_circuit_breakers",
    "check_disk_space",
    "create_health_checker",
    "STATUS_HEALTHY",
    "STATUS_DEGRADED",
    "STATUS_UNHEALTHY",
    # Tracing
    "Span",
    "SpanManager",
    "trace_operation",
    "span_manager",
]
