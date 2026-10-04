"""Operational metrics of the takedown pipeline, measured from the database.

Every process (scanner, scheduler, API) writes to the same PostgreSQL database,
so the database is where the pipeline can be measured end to end:

* **TTD** (time to detect): ``first_seen`` minus the domain's registration date.
* **TTR** (time to report): first delivered abuse e-mail minus ``first_seen``.
* **TTT** (time to takedown): first and last confirmed outage after the first
  delivered report (``site_status_events``), plus re-emergences (``down`` sites
  that came back ``up``).
* **Lead over public feeds**: when a feed corroborated a tracked site minus when
  the site was first seen (positive: Anisakys saw it first).
* Queue depth, delivery outcomes, abuse-desk responses, enrichment success
  (screenshot attached, abuse contact found) and analyst labels.

Durations are reported in hours as count/median/p90/mean over the sites first
seen in the last ``days`` days. Values that cannot be known are left out, never
guessed (D16): a site without a registration date has no TTD.

:class:`OperationalMetricsCollector` exposes the same numbers to Prometheus on
``/metrics``, recomputed at most once per ``ttl_seconds``.
"""

from __future__ import annotations

import datetime
import logging
import math
import threading
import time
from typing import Any, Dict, Iterator, List, Optional, Sequence

from prometheus_client import REGISTRY
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from src.reporting.db import short_transaction

logger = logging.getLogger(__name__)

DEFAULT_WINDOW_DAYS = 30
MAX_WINDOW_DAYS = 365
_QUERY_TIMEOUT_MS = 30_000

# Naive legacy timestamps are UTC (D16); this converts them to timestamptz.
_FIRST_SEEN_UTC = "(ps.first_seen AT TIME ZONE 'UTC')"

_TTD_SQL = f"""
    SELECT EXTRACT(EPOCH FROM ({_FIRST_SEEN_UTC}
                               - (ps.registration_date AT TIME ZONE 'UTC'))) / 3600.0
    FROM phishing_sites ps
    WHERE {_FIRST_SEEN_UTC} >= :since
      AND ps.registration_date IS NOT NULL
      AND ps.registration_date <= ps.first_seen
"""

_FIRST_REPORT_CTE = """
    first_report AS (
        SELECT ps.id AS site_id, MIN(o.sent_at) AS first_sent
        FROM abuse_report_outbox o
        JOIN phishing_sites ps ON ps.url = o.site_url
        WHERE o.channel = 'email' AND o.status = 'sent' AND o.followup_seq = 0
        GROUP BY ps.id
    )
"""

_TTR_SQL = f"""
    WITH {_FIRST_REPORT_CTE}
    SELECT EXTRACT(EPOCH FROM (fr.first_sent - {_FIRST_SEEN_UTC})) / 3600.0
    FROM first_report fr
    JOIN phishing_sites ps ON ps.id = fr.site_id
    WHERE {_FIRST_SEEN_UTC} >= :since AND fr.first_sent >= {_FIRST_SEEN_UTC}
"""

_TTT_SQL = f"""
    WITH {_FIRST_REPORT_CTE},
    outages AS (
        SELECT e.site_id, MIN(e.created_at) AS first_down, MAX(e.created_at) AS last_down
        FROM site_status_events e
        JOIN first_report fr ON fr.site_id = e.site_id
        WHERE e.new_status = 'down' AND e.created_at >= fr.first_sent
        GROUP BY e.site_id
    )
    SELECT EXTRACT(EPOCH FROM (o.first_down - fr.first_sent)) / 3600.0,
           EXTRACT(EPOCH FROM (o.last_down - fr.first_sent)) / 3600.0
    FROM outages o
    JOIN first_report fr ON fr.site_id = o.site_id
    JOIN phishing_sites ps ON ps.id = o.site_id
    WHERE {_FIRST_SEEN_UTC} >= :since
"""

_REEMERGENCE_SQL = f"""
    SELECT COUNT(DISTINCT e.site_id), COUNT(*)
    FROM site_status_events e
    JOIN phishing_sites ps ON ps.id = e.site_id
    WHERE e.old_status = 'down' AND e.new_status = 'up' AND {_FIRST_SEEN_UTC} >= :since
"""

_FEED_LEAD_SQL = f"""
    SELECT EXTRACT(EPOCH FROM ((tr.first_detected_at AT TIME ZONE 'UTC')
                               - {_FIRST_SEEN_UTC})) / 3600.0
    FROM thread_results tr
    JOIN phishing_sites ps ON ps.url = tr.found_url
    WHERE tr.result_type = 'feed_corroboration' AND {_FIRST_SEEN_UTC} >= :since
"""

_QUEUES_SQL = """
    SELECT
        (SELECT COUNT(*) FROM abuse_report_outbox WHERE status = 'pending'),
        (SELECT COUNT(*) FROM abuse_report_outbox WHERE status = 'sending'),
        (SELECT COUNT(*) FROM abuse_report_outbox WHERE status = 'pending_manual'),
        (SELECT COUNT(*) FROM phishing_sites
          WHERE approval_requested_at IS NOT NULL AND COALESCE(manual_flag, 0) = 0
            AND label_verdict IS NULL),
        (SELECT COUNT(*) FROM phishing_sites
          WHERE COALESCE(site_status, 'up') <> 'down'
            AND ((auto_analysis_status = 'pending' AND auto_detected = 1)
                 OR (manual_flag = 1 AND auto_analysis_status IS NULL)
                 OR (source = 'external_api' AND auto_analysis_status IS NULL))),
        (SELECT COUNT(*) FROM phishing_sites
          WHERE (manual_flag = 1 OR auto_report_eligible = 1)
            AND site_status = 'up'
            AND COALESCE(label_verdict, '') <> 'benign'
            AND COALESCE(abuse_report_sent, 0) = 0)
"""

_DELIVERIES_SQL = """
    SELECT
        COUNT(*) FILTER (WHERE status = 'sent'),
        COUNT(*) FILTER (WHERE status = 'failed')
    FROM abuse_report_outbox
    WHERE channel = 'email' AND updated_at >= :since
"""

_REPORTS_SQL = """
    SELECT COALESCE(status, 'unknown'), COUNT(*),
           COUNT(*) FILTER (WHERE COALESCE(response_received, 0) = 1),
           COUNT(*) FILTER (WHERE COALESCE(screenshot_included, 0) = 1)
    FROM abuse_reports
    WHERE (created_at AT TIME ZONE 'UTC') >= :since
    GROUP BY 1
"""

_NO_CONTACT_SQL = """
    SELECT COUNT(DISTINCT report_id) FILTER (WHERE channel = 'manual_review'),
           COUNT(DISTINCT report_id)
    FROM abuse_report_outbox
    WHERE followup_seq = 0 AND created_at >= :since
"""

_LABELS_SQL = """
    SELECT verdict, action, COUNT(*)
    FROM labels
    WHERE created_at >= :since
    GROUP BY verdict, action
"""

_SITES_SQL = f"SELECT COUNT(*) FROM phishing_sites ps WHERE {_FIRST_SEEN_UTC} >= :since"

# Statuses of a report that reached an abuse desk (the response-rate base).
_DELIVERED_STATUSES = frozenset({"sent", "resolved", "timeout", "rejected", "bounced"})


def summarize(values: Sequence[float]) -> Dict[str, Optional[float]]:
    """Describe a list of durations.

    Args:
        values: Durations in hours.

    Returns:
        ``{"count", "median", "p90", "mean"}``; the statistics are ``None``
        when there is no value.
    """
    finite = sorted(float(v) for v in values if v is not None and math.isfinite(float(v)))
    if not finite:
        return {"count": 0, "median": None, "p90": None, "mean": None}
    return {
        "count": len(finite),
        "median": round(_quantile(finite, 0.5), 2),
        "p90": round(_quantile(finite, 0.9), 2),
        "mean": round(sum(finite) / len(finite), 2),
    }


def _quantile(sorted_values: Sequence[float], q: float) -> float:
    """Linear-interpolated quantile of an ascending list (numpy's default method).

    Args:
        sorted_values: Non-empty ascending values.
        q: Quantile in ``[0, 1]``.

    Returns:
        The quantile.
    """
    position = (len(sorted_values) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[int(position)]
    weight = position - lower
    return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight


def _ratio(part: int, whole: int) -> Optional[float]:
    """Return ``part / whole`` rounded, or ``None`` when ``whole`` is 0.

    Args:
        part: Numerator.
        whole: Denominator.

    Returns:
        The ratio with 4 decimals, or ``None``.
    """
    return round(part / whole, 4) if whole else None


def _column(conn: Connection, sql: str, params: Dict[str, Any]) -> List[float]:
    """Run a one-column query and return its non-null values.

    Args:
        conn: Open connection.
        sql: Query returning one numeric column.
        params: Bind parameters.

    Returns:
        The values as floats.
    """
    return [float(row[0]) for row in conn.execute(text(sql), params) if row[0] is not None]


def compute_operational_metrics(
    engine: Engine,
    days: int = DEFAULT_WINDOW_DAYS,
    now: Optional[datetime.datetime] = None,
) -> Dict[str, Any]:
    """Measure the pipeline over the sites first seen in the last ``days`` days.

    Args:
        engine: Engine of the shared database.
        days: Window length, 1-365.
        now: Reference time (UTC); defaults to the current time.

    Returns:
        The metrics document (see the module docstring).

    Raises:
        ValueError: If ``days`` is out of range.
        sqlalchemy.exc.SQLAlchemyError: If the database cannot be read.
    """
    if not 1 <= days <= MAX_WINDOW_DAYS:
        raise ValueError(f"days must be between 1 and {MAX_WINDOW_DAYS}")
    reference = now or datetime.datetime.now(datetime.timezone.utc)
    since = reference - datetime.timedelta(days=days)
    params = {"since": since}

    with short_transaction(engine, statement_timeout_ms=_QUERY_TIMEOUT_MS) as conn:
        sites = int(conn.execute(text(_SITES_SQL), params).scalar() or 0)
        ttd = _column(conn, _TTD_SQL, params)
        ttr = _column(conn, _TTR_SQL, params)
        outages = conn.execute(text(_TTT_SQL), params).fetchall()
        reemerged_sites, reemergence_events = conn.execute(text(_REEMERGENCE_SQL), params).one()
        feed_lead = _column(conn, _FEED_LEAD_SQL, params)
        queue_row = conn.execute(text(_QUEUES_SQL)).one()
        sent, failed = conn.execute(text(_DELIVERIES_SQL), params).one()
        report_rows = conn.execute(text(_REPORTS_SQL), params).fetchall()
        no_contact, outbox_reports = conn.execute(text(_NO_CONTACT_SQL), params).one()
        label_rows = conn.execute(text(_LABELS_SQL), params).fetchall()

    by_status = {row[0]: int(row[1]) for row in report_rows}
    total_reports = sum(by_status.values())
    responses = sum(int(row[2]) for row in report_rows)
    delivered = sum(count for status, count in by_status.items() if status in _DELIVERED_STATUSES)
    with_screenshot = sum(int(row[3]) for row in report_rows)

    labels_by_verdict: Dict[str, int] = {}
    labels_by_action: Dict[str, int] = {}
    for verdict, action, count in label_rows:
        labels_by_verdict[verdict] = labels_by_verdict.get(verdict, 0) + int(count)
        labels_by_action[action] = labels_by_action.get(action, 0) + int(count)

    return {
        "window_days": days,
        "since": since.isoformat(),
        "generated_at": reference.isoformat(),
        "sites_first_seen": sites,
        "durations_hours": {
            "time_to_detect": summarize(ttd),
            "time_to_report": summarize(ttr),
            "time_to_first_outage": summarize([float(r[0]) for r in outages if r[0] is not None]),
            "time_to_last_outage": summarize([float(r[1]) for r in outages if r[1] is not None]),
            "lead_over_feeds": summarize(feed_lead),
        },
        "re_emergence": {
            "sites": int(reemerged_sites or 0),
            "events": int(reemergence_events or 0),
        },
        "queues": {
            "outbox_pending": int(queue_row[0] or 0),
            "outbox_sending": int(queue_row[1] or 0),
            "analyst_tasks": int(queue_row[2] or 0),
            "approvals_waiting": int(queue_row[3] or 0),
            "analysis_pending": int(queue_row[4] or 0),
            "reportable_now": int(queue_row[5] or 0),
        },
        "deliveries": {"emails_sent": int(sent or 0), "emails_failed": int(failed or 0)},
        "reports": {
            "total": total_reports,
            "by_status": by_status,
            "responses_received": responses,
            "response_rate": _ratio(responses, delivered),
        },
        "enrichment": {
            "reports": total_reports,
            "with_screenshot": with_screenshot,
            "screenshot_rate": _ratio(with_screenshot, total_reports),
            "without_contact": int(no_contact or 0),
            "contact_rate": _ratio(
                int(outbox_reports or 0) - int(no_contact or 0), int(outbox_reports or 0)
            ),
        },
        "labels": {"by_verdict": labels_by_verdict, "by_action": labels_by_action},
    }


class OperationalMetricsCollector(Collector):
    """Prometheus collector that publishes :func:`compute_operational_metrics`.

    The numbers are recomputed at most once per ``ttl_seconds``; a database
    error yields no samples (and a log line) instead of failing the scrape.
    """

    def __init__(
        self, engine: Engine, days: int = DEFAULT_WINDOW_DAYS, ttl_seconds: float = 60.0
    ) -> None:
        """Create a collector.

        Args:
            engine: Engine of the shared database.
            days: Window of the duration metrics.
            ttl_seconds: How long one computation is reused.
        """
        self.engine = engine
        self.days = days
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._cached: Optional[Dict[str, Any]] = None
        self._cached_at = 0.0

    def snapshot(self) -> Optional[Dict[str, Any]]:
        """Return the cached metrics, recomputing them when stale.

        Returns:
            The metrics document, or ``None`` when it cannot be computed.
        """
        with self._lock:
            if self._cached is not None and time.monotonic() - self._cached_at < self.ttl_seconds:
                return self._cached
            try:
                self._cached = compute_operational_metrics(self.engine, self.days)
                self._cached_at = time.monotonic()
            except Exception as exc:
                logger.warning(f"Operational metrics unavailable: {exc}")
                return None
            return self._cached

    def describe(self) -> List[Any]:
        """Tell the registry nothing up front, so registration never queries the DB.

        Returns:
            An empty list.
        """
        return []

    def collect(self) -> Iterator[Any]:
        """Yield the gauge families for one scrape.

        Yields:
            ``GaugeMetricFamily`` objects.
        """
        data = self.snapshot()
        if data is None:
            return

        queues = GaugeMetricFamily(
            "anisakys_queue_depth", "Items waiting in each pipeline queue", labels=["queue"]
        )
        for name, value in data["queues"].items():
            queues.add_metric([name], value)
        yield queues

        durations = GaugeMetricFamily(
            "anisakys_pipeline_duration_hours",
            f"Pipeline durations over sites first seen in the last {self.days} days",
            labels=["metric", "stat"],
        )
        for metric, stats in data["durations_hours"].items():
            for stat in ("count", "median", "p90", "mean"):
                value = stats[stat]
                if value is not None:
                    durations.add_metric([metric, stat], value)
        yield durations

        reports = GaugeMetricFamily(
            "anisakys_abuse_reports_window",
            f"Abuse reports created in the last {self.days} days, by status",
            labels=["status"],
        )
        for status, count in data["reports"]["by_status"].items():
            reports.add_metric([status], count)
        yield reports


_registered: Optional[OperationalMetricsCollector] = None
_register_lock = threading.Lock()


def register_operational_collector(engine: Engine) -> OperationalMetricsCollector:
    """Register the collector with Prometheus once per process.

    Later calls point the existing collector at ``engine`` instead of
    registering a duplicate (the default registry rejects duplicates).

    Args:
        engine: Engine of the shared database.

    Returns:
        The process-wide collector.
    """
    global _registered
    with _register_lock:
        if _registered is None:
            _registered = OperationalMetricsCollector(engine)
            REGISTRY.register(_registered)
        else:
            _registered.engine = engine
            _registered._cached = None
        return _registered
