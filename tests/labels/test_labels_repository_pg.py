"""Analyst labels on real PostgreSQL (src/labels.py).

Each test works on its own sites (unique URLs) inside the module's migrated
schema, so the tests do not depend on each other.
"""

import json
import uuid
from typing import Any, Dict, Optional

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Engine

from src.labels import (
    CANCELLED_BY_DISMISSAL,
    LabelAction,
    LabelRepository,
    SiteNotFoundError,
)
from src.reporting.site_queue import SiteQueue


def _url(prefix: str = "site") -> str:
    return f"https://{prefix}-{uuid.uuid4().hex[:10]}.example/login"


def _site(engine: Engine, url: Optional[str] = None, **columns: Any) -> int:
    values: Dict[str, Any] = {
        "url": url or _url(),
        "site_status": "up",
        "multi_api_threat_level": "high",
        "api_confidence_score": 90,
        "manual_flag": 0,
        "auto_report_eligible": 0,
        "requires_manual_review": 1,
        "abuse_report_sent": 0,
        "first_seen": "2026-10-01 10:00:00",
        **columns,
    }
    names = ", ".join(values)
    params = ", ".join(f":{name}" for name in values)
    with engine.begin() as conn:
        return int(
            conn.execute(
                text(f"INSERT INTO phishing_sites ({names}) VALUES ({params}) RETURNING id"),
                values,
            ).scalar_one()
        )


def _site_row(engine: Engine, site_id: int) -> Dict[str, Any]:
    with engine.connect() as conn:
        return dict(
            conn.execute(text("SELECT * FROM phishing_sites WHERE id = :i"), {"i": site_id})
            .mappings()
            .one()
        )


def _report(engine: Engine, url: str, status: str = "queued") -> str:
    report_id = f"ANISAKYS-TEST-{uuid.uuid4().hex[:8].upper()}"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO abuse_reports (site_url, recipients, report_id, status) "
                "VALUES (:u, '[]', :r, :s)"
            ),
            {"u": url, "r": report_id, "s": status},
        )
    return report_id


def _outbox(
    engine: Engine,
    report_id: str,
    url: str,
    status: str,
    channel: str = "email",
    recipient: Optional[str] = None,
) -> int:
    with engine.begin() as conn:
        return int(
            conn.execute(
                text(
                    "INSERT INTO abuse_report_outbox (report_id, site_url, channel, recipient, "
                    "status, payload) VALUES (:r, :u, :c, :rcpt, :s, CAST(:p AS JSONB)) "
                    "RETURNING id"
                ),
                {
                    "r": report_id,
                    "u": url,
                    "c": channel,
                    "rcpt": recipient or f"abuse-{uuid.uuid4().hex[:6]}@hoster.example",
                    "s": status,
                    "p": json.dumps({"subject": "s", "text": "t"}),
                },
            ).scalar_one()
        )


def _outbox_row(engine: Engine, row_id: int) -> Dict[str, Any]:
    with engine.connect() as conn:
        return dict(
            conn.execute(
                text("SELECT status, last_error, payload FROM abuse_report_outbox WHERE id = :i"),
                {"i": row_id},
            )
            .mappings()
            .one()
        )


class TestRecord:
    def test_confirm_stores_phishing_with_the_detector_snapshot(self, engine):
        site_id = _site(engine)

        outcome = LabelRepository(engine).record(
            site_id, LabelAction.CONFIRM, brand=" Nequi ", note="seen live", labeled_by="soc"
        )

        label = outcome.label
        assert (label.verdict, label.action, label.brand, label.labeled_by) == (
            "phishing",
            "confirm",
            "Nequi",
            "soc",
        )
        assert label.registrable_domain.endswith(".example")
        assert label.detector_snapshot["multi_api_threat_level"] == "high"
        assert label.detector_snapshot["api_confidence_score"] == 90
        assert label.detector_snapshot["first_seen"] == "2026-10-01T10:00:00+00:00"
        site = _site_row(engine, site_id)
        assert site["label_verdict"] == "phishing"
        assert site["labeled_at"] is not None
        assert site["requires_manual_review"] == 0
        assert site["manual_flag"] == 0  # confirming never queues a report

    def test_dismiss_marks_benign_and_keeps_the_site_out_of_reporting(self, engine):
        site_id = _site(engine, manual_flag=1, auto_report_eligible=1)

        outcome = LabelRepository(engine).record(site_id, LabelAction.DISMISS)

        assert outcome.label.verdict == "benign"
        site = _site_row(engine, site_id)
        assert (site["label_verdict"], site["auto_report_eligible"]) == ("benign", 0)
        claimed = SiteQueue(engine, worker_id="test").claim_batch(100)
        assert site_id not in {s.id for s in claimed}
        assert SiteQueue(engine, worker_id="test").claim_url(site["url"]) == (True, None)

    def test_dismiss_cancels_queued_emails_and_closes_tasks_of_that_site_only(self, engine):
        url = _url("dismissed")
        other = _url("other")
        site_id = _site(engine, url=url)
        _site(engine, url=other)
        report_id = _report(engine, url)
        pending = _outbox(engine, report_id, url, "pending")
        sending = _outbox(engine, report_id, url, "sending")
        task = _outbox(engine, report_id, url, "pending_manual", channel="web_form")
        untouched = _outbox(engine, _report(engine, other), other, "pending")

        outcome = LabelRepository(engine).record(
            site_id, LabelAction.DISMISS, note="legit", labeled_by="soc"
        )

        assert (outcome.cancelled_deliveries, outcome.closed_tasks) == (1, 1)
        assert _outbox_row(engine, pending)["status"] == "failed"
        assert _outbox_row(engine, pending)["last_error"] == CANCELLED_BY_DISMISSAL
        assert _outbox_row(engine, sending)["status"] == "sending"
        closed = _outbox_row(engine, task)
        assert closed["status"] == "failed"
        assert closed["payload"]["analyst"]["outcome"] == "not_applicable"
        assert closed["payload"]["analyst"]["completed_by"] == "soc"
        assert _outbox_row(engine, untouched)["status"] == "pending"
        with engine.connect() as conn:
            status = conn.execute(
                text("SELECT status FROM abuse_reports WHERE report_id = :r"), {"r": report_id}
            ).scalar()
        assert status == "queued"  # an e-mail is still being sent

    def test_dismiss_fails_a_report_that_loses_every_delivery(self, engine):
        url = _url("undeliverable")
        site_id = _site(engine, url=url)
        report_id = _report(engine, url)
        _outbox(engine, report_id, url, "pending")

        LabelRepository(engine).record(site_id, LabelAction.DISMISS)

        with engine.connect() as conn:
            status = conn.execute(
                text("SELECT status FROM abuse_reports WHERE report_id = :r"), {"r": report_id}
            ).scalar()
        assert status == "failed"

    def test_report_flags_the_site_and_releases_an_awaiting_submission(self, engine):
        site_id = _site(
            engine,
            requires_manual_review=1,
            auto_analysis_status="awaiting_approval",
            approval_requested_by="partner",
        )
        with engine.begin() as conn:
            conn.execute(
                text("UPDATE phishing_sites SET approval_requested_at = now() WHERE id = :i"),
                {"i": site_id},
            )

        outcome = LabelRepository(engine).record(site_id, LabelAction.REPORT)

        assert outcome.released_from_approval is True
        site = _site_row(engine, site_id)
        assert (site["manual_flag"], site["requires_manual_review"]) == (1, 0)
        assert site["auto_analysis_status"] is None
        approvals, _total = LabelRepository(engine).pending_approvals(limit=200)
        assert site_id not in {row["id"] for row in approvals}
        claimed = SiteQueue(engine, worker_id="test").claim_batch(100)
        assert site_id in {s.id for s in claimed}

    def test_report_of_an_unrequested_site_is_not_a_release(self, engine):
        site_id = _site(engine, auto_analysis_status="completed")

        outcome = LabelRepository(engine).record(site_id, LabelAction.REPORT)

        assert outcome.released_from_approval is False
        assert _site_row(engine, site_id)["auto_analysis_status"] == "completed"

    def test_unknown_site_raises(self, engine):
        with pytest.raises(SiteNotFoundError):
            LabelRepository(engine).record(987654321, LabelAction.CONFIRM)

    def test_relabelling_keeps_history_and_updates_the_verdict(self, engine):
        site_id = _site(engine)
        repo = LabelRepository(engine)
        first = repo.record(site_id, LabelAction.CONFIRM).label
        second = repo.record(site_id, LabelAction.DISMISS).label

        history = repo.history(site_id)

        assert [label.id for label in history] == [second.id, first.id]
        assert _site_row(engine, site_id)["label_verdict"] == "benign"
        latest = {label.url: label for label in repo.latest_per_url()}
        assert latest[first.url].id == second.id


class TestListing:
    def test_filters_by_verdict_and_action(self, engine):
        repo = LabelRepository(engine)
        benign_site = _site(engine)
        phishing_site = _site(engine)
        repo.record(benign_site, LabelAction.DISMISS)
        repo.record(phishing_site, LabelAction.REPORT)

        benign, benign_total = repo.list_labels(verdict="benign", limit=200)
        reported, _ = repo.list_labels(action="report", limit=200)

        assert benign_total == len(benign) >= 1
        assert all(label.verdict == "benign" for label in benign)
        assert all(label.action == "report" for label in reported)
        assert phishing_site in {label.site_id for label in reported}

    def test_pending_approvals_lists_open_requests_oldest_first(self, engine):
        repo = LabelRepository(engine)
        newer = _site(engine, approval_requested_by="partner-b")
        older = _site(engine, approval_requested_by="partner-a")
        decided = _site(engine)
        flagged = _site(engine, manual_flag=1)
        never_requested = _site(engine)
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE phishing_sites SET approval_requested_at = CASE id "
                    "WHEN :older THEN now() - interval '2 hours' "
                    "WHEN :newer THEN now() - interval '1 hour' ELSE now() END "
                    "WHERE id IN (:older, :newer, :decided, :flagged)"
                ),
                {"older": older, "newer": newer, "decided": decided, "flagged": flagged},
            )
        repo.record(decided, LabelAction.CONFIRM)

        rows, total = repo.pending_approvals(limit=200)

        ids = [row["id"] for row in rows]
        assert ids.index(older) < ids.index(newer)
        assert decided not in ids and flagged not in ids and never_requested not in ids
        assert total == len(rows)
        assert next(row for row in rows if row["id"] == older)["approval_requested_by"] == (
            "partner-a"
        )
