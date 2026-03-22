"""
Centralized metrics registry for Anisakys.

Thread-safe registry for counters, gauges, and histograms.
No external dependencies (stdlib only). Prometheus endpoint live at
/metrics via prometheus_client (D5). Application-level instrumentation
via increment_counter() et al. can be added incrementally.

Predefined metric names follow the Prometheus naming convention:
    anisakys_<component>_<measure>_<unit>

Usage:
    >>> from src.observability.metrics import increment_counter, get_metrics
    >>> increment_counter("anisakys_scans_total")
    >>> increment_counter("anisakys_api_calls_total", api_name="VirusTotal")
    >>> metrics = get_metrics()
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Internal data structures
# ---------------------------------------------------------------------------


@dataclass
class Counter:
    """Monotonically increasing counter."""

    name: str
    value: int = 0
    labels: Dict[str, str] = field(default_factory=dict)

    def increment(self, amount: int = 1) -> None:
        self.value += amount


@dataclass
class Gauge:
    """A value that can go up or down."""

    name: str
    value: float = 0.0
    labels: Dict[str, str] = field(default_factory=dict)
    last_updated: float = field(default_factory=time.time)

    def set(self, value: float) -> None:
        self.value = value
        self.last_updated = time.time()


@dataclass
class Histogram:
    """Distribution of observed values."""

    name: str
    observations: List[float] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)

    def observe(self, value: float) -> None:
        self.observations.append(value)

    @property
    def count(self) -> int:
        return len(self.observations)

    @property
    def sum(self) -> float:
        return sum(self.observations)

    @property
    def mean(self) -> Optional[float]:
        if not self.observations:
            return None
        return self.sum / self.count

    @property
    def p95(self) -> Optional[float]:
        if not self.observations:
            return None
        sorted_obs = sorted(self.observations)
        idx = int(len(sorted_obs) * 0.95)
        return sorted_obs[min(idx, len(sorted_obs) - 1)]

    @property
    def p99(self) -> Optional[float]:
        if not self.observations:
            return None
        sorted_obs = sorted(self.observations)
        idx = int(len(sorted_obs) * 0.99)
        return sorted_obs[min(idx, len(sorted_obs) - 1)]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def _make_key(name: str, labels: Optional[Dict[str, str]]) -> str:
    """Build a unique key from metric name and labels."""
    if not labels:
        return name
    label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
    return f"{name}{{{label_str}}}"


class MetricsRegistry:
    """
    Thread-safe singleton registry for all application metrics.

    Stores counters, gauges, and histograms keyed by name + labels.
    """

    _instance: Optional["MetricsRegistry"] = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._counters: Dict[str, Counter] = {}
        self._gauges: Dict[str, Gauge] = {}
        self._histograms: Dict[str, Histogram] = {}
        self._lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "MetricsRegistry":
        """Return the global singleton registry."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # ------------------------------------------------------------------
    # Counters
    # ------------------------------------------------------------------

    def increment(self, name: str, value: int = 1, labels: Optional[Dict[str, str]] = None) -> None:
        """Increment a counter by value (default 1)."""
        key = _make_key(name, labels)
        with self._lock:
            if key not in self._counters:
                self._counters[key] = Counter(name=name, labels=labels or {})
            self._counters[key].increment(value)

    def get_counter(self, name: str, labels: Optional[Dict[str, str]] = None) -> int:
        """Return current counter value (0 if not set)."""
        key = _make_key(name, labels)
        with self._lock:
            counter = self._counters.get(key)
            return counter.value if counter else 0

    # ------------------------------------------------------------------
    # Gauges
    # ------------------------------------------------------------------

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Set a gauge to an absolute value."""
        key = _make_key(name, labels)
        with self._lock:
            if key not in self._gauges:
                self._gauges[key] = Gauge(name=name, labels=labels or {})
            self._gauges[key].set(value)

    def get_gauge(self, name: str, labels: Optional[Dict[str, str]] = None) -> Optional[float]:
        """Return current gauge value (None if not set)."""
        key = _make_key(name, labels)
        with self._lock:
            gauge = self._gauges.get(key)
            return gauge.value if gauge else None

    # ------------------------------------------------------------------
    # Histograms
    # ------------------------------------------------------------------

    def observe(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Record an observation in a histogram."""
        key = _make_key(name, labels)
        with self._lock:
            if key not in self._histograms:
                self._histograms[key] = Histogram(name=name, labels=labels or {})
            self._histograms[key].observe(value)

    def get_histogram(
        self, name: str, labels: Optional[Dict[str, str]] = None
    ) -> Optional[Dict[str, Any]]:
        """Return histogram summary (count, sum, mean, p95, p99) or None."""
        key = _make_key(name, labels)
        with self._lock:
            hist = self._histograms.get(key)
            if hist is None:
                return None
            return {
                "count": hist.count,
                "sum": hist.sum,
                "mean": hist.mean,
                "p95": hist.p95,
                "p99": hist.p99,
            }

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def get_all(self) -> Dict[str, Any]:
        """Return all metrics as a serializable dict."""
        with self._lock:
            return {
                "counters": {
                    key: {"name": c.name, "value": c.value, "labels": c.labels}
                    for key, c in self._counters.items()
                },
                "gauges": {
                    key: {"name": g.name, "value": g.value, "labels": g.labels}
                    for key, g in self._gauges.items()
                },
                "histograms": {
                    key: {
                        "name": h.name,
                        "count": h.count,
                        "sum": h.sum,
                        "mean": h.mean,
                        "p95": h.p95,
                        "p99": h.p99,
                        "labels": h.labels,
                    }
                    for key, h in self._histograms.items()
                },
            }

    def reset(self) -> None:
        """Reset all metrics (primarily for testing)."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()


# ---------------------------------------------------------------------------
# Convenience module-level functions (use the global singleton)
# ---------------------------------------------------------------------------


def increment_counter(name: str, value: int = 1, **labels: str) -> None:
    """
    Increment a counter metric.

    Example:
        >>> increment_counter("anisakys_scans_total")
        >>> increment_counter("anisakys_api_calls_total", api_name="VirusTotal")
    """
    MetricsRegistry.get_instance().increment(name, value, labels or None)


def set_gauge(name: str, value: float, **labels: str) -> None:
    """
    Set a gauge metric to an absolute value.

    Example:
        >>> set_gauge("anisakys_circuit_breaker_state", 1.0, api_name="VirusTotal")
    """
    MetricsRegistry.get_instance().set_gauge(name, value, labels or None)


def observe_histogram(name: str, value: float, **labels: str) -> None:
    """
    Record an observation in a histogram.

    Example:
        >>> observe_histogram("anisakys_api_latency_seconds", 0.342, api_name="URLVoid")
    """
    MetricsRegistry.get_instance().observe(name, value, labels or None)


def get_metrics() -> Dict[str, Any]:
    """
    Return all current metrics as a serializable dict.

    Example:
        >>> metrics = get_metrics()
        >>> print(metrics["counters"]["anisakys_scans_total"]["value"])
    """
    return MetricsRegistry.get_instance().get_all()


# ---------------------------------------------------------------------------
# Predefined metric name constants
# ---------------------------------------------------------------------------

# Counters
METRIC_SCANS_TOTAL = "anisakys_scans_total"
METRIC_DETECTIONS_TOTAL = "anisakys_detections_total"
METRIC_REDIRECT_CHAINS_TOTAL = "anisakys_redirect_chains_detected_total"
METRIC_API_CALLS_TOTAL = "anisakys_api_calls_total"
METRIC_REPORTS_SENT_TOTAL = "anisakys_reports_sent_total"

# Gauges
METRIC_CIRCUIT_BREAKER_STATE = "anisakys_circuit_breaker_state"

# Histograms
METRIC_API_LATENCY_SECONDS = "anisakys_api_latency_seconds"
METRIC_SCAN_DURATION_SECONDS = "anisakys_scan_duration_seconds"
