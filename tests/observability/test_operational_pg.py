"""Operational metrics measured from the database (src/observability/operational.py).

One synthetic site exercises every duration: registered 48 h before it was first
seen (TTD 48 h), first e-mail 6 h after first seen (TTR 6 h), confirmed down
24 h after that report, back up at 48 h and down again at 72 h (first outage
24 h, last outage 72 h, one re-emergence), and corroborated by a public feed 3 h
after Anisakys saw it (lead 3 h). A site first seen 100 days ago stays outside
the 30-day window.
"""

import datetime
import json
from typing import Iterator
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from src.observability.operational import (
    OperationalMetricsCollector,
    compute_operational_metrics,
    summarize,
)

NOW = datetime.datetime(2026, 10, 4, 12, 0, tzinfo=datetime.timezone.utc)
FIRST_SEEN = NOW - datetime.timedelta(days=10)
FIRST_SENT = FIRST_SEEN + datetime.timedelta(hours=6)
SITE_URL = "https://ops-measured.example/login"


def _naive(moment: datetime.datetime) -> datetime.datetime:
    """Legacy TIMESTAMP columns hold naive UTC (D16)."""
    return moment.astimezone(datetime.timezone.utc).replace(tzinfo=None)


@pytest.fixture(scope="module")
def engine(migrated_db_url: str) -> Iterator[Engine]:  # noqa: F811
    eng = create_engine(migrated_db_url)
    with eng.begin() as conn:
        site_id = conn.execute(
            text(
                "INSERT INTO phishing_sites (url, first_seen, registration_date, site_status, "
                "screenshot_taken) VALUES (:u, :fs, :reg, 'down', 1) RETURNING id"
            ),
            {
                "u": SITE_URL,
                "fs": _naive(FIRST_SEEN),
                "reg": _naive(FIRST_SEEN - datetime.timedelta(hours=48)),
            },
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO phishing_sites (url, first_seen, registration_date) "
                "VALUES ('https://old.example/', :fs, :reg)"
            ),
            {
                "fs": _naive(NOW - datetime.timedelta(days=100)),
                "reg": _naive(NOW - datetime.timedelta(days=101)),
            },
        )
        # Waiting for approval (queue) and reportable now (queue).
        conn.execute(
            text(
                "INSERT INTO phishing_sites (url, first_seen, approval_requested_at, manual_flag) "
                "VALUES ('https://awaiting.example/', :fs, :at, 0)"
            ),
            {"fs": _naive(NOW - datetime.timedelta(days=1)), "at": NOW},
        )
        conn.execute(
            text(
                "INSERT INTO phishing_sites (url, first_seen, manual_flag, site_status, "
                "abuse_report_sent) VALUES ('https://reportable.example/', :fs, 1, 'up', 0)"
            ),
            {"fs": _naive(NOW - datetime.timedelta(days=2))},
        )
        for report_id, status, response, shot in (
            ("OPS-1", "sent", 1, 1),
            ("OPS-2", "bounced", 0, 0),
            ("OPS-3", "pending_manual", 0, 0),
        ):
            conn.execute(
                text(
                    "INSERT INTO abuse_reports (site_url, recipients, report_id, status, "
                    "response_received, screenshot_included, created_at) "
                    "VALUES (:u, '[]', :r, :s, :resp, :shot, :c)"
                ),
                {
                    "u": SITE_URL,
                    "r": report_id,
                    "s": status,
                    "resp": response,
                    "shot": shot,
                    "c": _naive(FIRST_SENT),
                },
            )
        for report_id, channel, status, sent_at in (
            ("OPS-1", "email", "sent", FIRST_SENT),
            ("OPS-1", "email", "sent", FIRST_SENT + datetime.timedelta(hours=1)),
            ("OPS-2", "email", "failed", None),
            ("OPS-3", "manual_review", "pending_manual", None),
            ("OPS-4", "email", "pending", None),
        ):
            conn.execute(
                text(
                    "INSERT INTO abuse_report_outbox (report_id, site_url, channel, recipient, "
                    "status, sent_at, created_at, updated_at) "
                    "VALUES (:r, :u, :c, :rcpt, :s, :sent, :created, :created)"
                ),
                {
                    "r": report_id,
                    "u": SITE_URL,
                    "c": channel,
                    "rcpt": f"{report_id.lower()}-{status}-{sent_at}@desk.example",
                    "s": status,
                    "sent": sent_at,
                    "created": FIRST_SENT,
                },
            )
        for hours, old, new in ((24, "up", "down"), (48, "down", "up"), (72, "up", "down")):
            conn.execute(
                text(
                    "INSERT INTO site_status_events (site_id, site_url, old_status, new_status, "
                    "created_at) VALUES (:i, :u, :o, :n, :c)"
                ),
                {
                    "i": site_id,
                    "u": SITE_URL,
                    "o": old,
                    "n": new,
                    "c": FIRST_SENT + datetime.timedelta(hours=hours),
                },
            )
        thread_id = conn.execute(
            text(
                "INSERT INTO analysis_threads (thread_type, label, status) "
                "VALUES ('feed_intel', 'feeds', 'active') RETURNING id"
            )
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO thread_results (thread_id, result_type, found_url, source, "
                "first_detected_at, extra_data) VALUES (:t, 'feed_corroboration', :u, "
                "'openphish', :d, CAST(:x AS JSONB))"
            ),
            {
                "t": thread_id,
                "u": SITE_URL,
                "d": _naive(FIRST_SEEN + datetime.timedelta(hours=3)),
                "x": json.dumps({}),
            },
        )
        conn.execute(
            text(
                "INSERT INTO labels (site_id, url, registrable_domain, verdict, action, "
                "created_at) VALUES (:i, :u, 'ops-measured.example', 'phishing', 'report', :c)"
            ),
            {"i": site_id, "u": SITE_URL, "c": NOW - datetime.timedelta(days=1)},
        )
    yield eng
    eng.dispose()


def test_durations_are_measured_and_old_sites_excluded(engine):
    metrics = compute_operational_metrics(engine, days=30, now=NOW)

    durations = metrics["durations_hours"]
    assert durations["time_to_detect"] == {"count": 1, "median": 48.0, "p90": 48.0, "mean": 48.0}
    assert durations["time_to_report"]["median"] == 6.0
    assert durations["time_to_first_outage"]["median"] == 24.0
    assert durations["time_to_last_outage"]["median"] == 72.0
    assert durations["lead_over_feeds"]["median"] == 3.0
    assert metrics["re_emergence"] == {"sites": 1, "events": 1}
    assert metrics["sites_first_seen"] == 3  # the 100-day-old site is outside


def test_queues_outcomes_and_enrichment(engine):
    metrics = compute_operational_metrics(engine, days=30, now=NOW)

    queues = metrics["queues"]
    assert queues["outbox_pending"] == 1
    assert queues["analyst_tasks"] == 1
    assert queues["approvals_waiting"] == 1
    assert queues["reportable_now"] == 1
    assert metrics["deliveries"] == {"emails_sent": 2, "emails_failed": 1}
    reports = metrics["reports"]
    assert reports["by_status"] == {"sent": 1, "bounced": 1, "pending_manual": 1}
    assert reports["responses_received"] == 1
    assert reports["response_rate"] == 0.5  # 1 response over 2 delivered reports
    enrichment = metrics["enrichment"]
    assert enrichment["screenshot_rate"] == round(1 / 3, 4)
    assert enrichment["without_contact"] == 1
    assert enrichment["contact_rate"] == round(3 / 4, 4)
    assert metrics["labels"] == {"by_verdict": {"phishing": 1}, "by_action": {"report": 1}}


def test_window_is_validated(engine):
    with pytest.raises(ValueError):
        compute_operational_metrics(engine, days=0)


def test_summarize_ignores_missing_values():
    assert summarize([]) == {"count": 0, "median": None, "p90": None, "mean": None}
    assert summarize([1.0, 2.0, 3.0, 4.0]) == {"count": 4, "median": 2.5, "p90": 3.7, "mean": 2.5}


class TestCollector:
    def test_publishes_queue_depth_and_durations(self, engine):
        collector = OperationalMetricsCollector(engine)

        families = {family.name: family for family in collector.collect()}

        queue_samples = {
            s.labels["queue"]: s.value for s in families["anisakys_queue_depth"].samples
        }
        assert queue_samples["approvals_waiting"] == 1
        duration_samples = families["anisakys_pipeline_duration_hours"].samples
        assert any(
            s.labels == {"metric": "time_to_report", "stat": "count"} and s.value >= 1
            for s in duration_samples
        )

    def test_caches_between_scrapes(self, engine):
        collector = OperationalMetricsCollector(engine, ttl_seconds=60)
        with patch(
            "src.observability.operational.compute_operational_metrics",
            wraps=compute_operational_metrics,
        ) as compute:
            list(collector.collect())
            list(collector.collect())

        assert compute.call_count == 1

    def test_database_errors_yield_no_samples(self):
        broken = create_engine("postgresql://nobody@127.0.0.1:1/none")
        collector = OperationalMetricsCollector(broken)

        assert list(collector.collect()) == []
