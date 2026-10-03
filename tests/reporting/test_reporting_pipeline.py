"""Reporting pipeline against the real test PostgreSQL (SMTP and network faked).

Regression tests for the old loop, which held one long transaction across
WHOIS/DNS/screenshots/SMTP for every site, had no row locking (every process
ran its own loop), let one SQL error roll back all ``abuse_report_sent``
marks, e-mailed form-only providers and CC'd escalation lists on the first
send, once per primary recipient.
"""

from __future__ import annotations

import smtplib
import threading
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text

from src import main  # noqa: F401 - seeds sys.modules to break the import cycle
from src.config import settings
from src.reporting.outbox import NewOutboxEntry, OutboxRepository
from src.reporting.report_tracker import calculate_sla_deadline
from src.reporting.site_queue import SiteQueue
from src.shutdown import reset_shutdown
from tests.reporting.pipeline_support import (
    FakeDetector,
    FakeMailer,
    FixedClock,
    cleanup_sites,
    fence_foreign_sites,
    insert_site,
    make_manager,
    make_site_url,
    network_patches,
    outbox_rows,
    report_rows,
    set_site_status,
    site_row,
    unfence_foreign_sites,
)

MONDAY = datetime(2026, 10, 5, 10, 0, tzinfo=timezone.utc)
SENDER = settings.ABUSE_EMAIL_SENDER.lower()


@pytest.fixture
def engine(db_engine):
    reset_shutdown()
    cleanup_sites(db_engine)
    fence_foreign_sites(db_engine)
    yield db_engine
    unfence_foreign_sites(db_engine)
    cleanup_sites(db_engine)


@pytest.fixture
def stack():
    with ExitStack() as exit_stack:
        yield exit_stack


@pytest.fixture
def no_default_ccs(monkeypatch):
    monkeypatch.setattr(settings, "DEFAULT_CC_EMAILS", None)
    monkeypatch.setattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL2", None)
    monkeypatch.setattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL3", None)
    monkeypatch.setattr(settings, "TEST_EMAIL", None)


@pytest.mark.usefixtures("no_default_ccs")
class TestScheduledReport:
    def test_report_is_sent_tracked_and_marked(self, engine, stack):
        url = make_site_url("tracked")
        insert_site(engine, url)
        mailer = FakeMailer()
        clock = FixedClock(MONDAY)
        manager = make_manager(engine, stack, mailer=mailer, clock=clock)
        network_patches(stack)

        assert manager.run_reporting_cycle() == 1

        (report,) = report_rows(engine, url)
        assert report["status"] == "sent"
        assert report["sla_deadline"] == calculate_sla_deadline(MONDAY)
        (primary,) = mailer.to("abuse@registrar-test.example")
        assert primary.subject.startswith(f"[{report['report_id']}] ")
        assert primary.recipients == ["abuse@registrar-test.example"]
        assert primary.cc_header is None
        site = site_row(engine, url)
        assert (site["abuse_report_sent"], site["reported"]) == (1, 1)
        assert site["report_claimed_by"] is None and site["report_lease_until"] is None
        assert manager.run_reporting_cycle() == 0, "a reported site must not be claimed again"
        assert len(mailer.to("abuse@registrar-test.example")) == 1

    def test_first_send_copies_default_ccs_once_and_never_escalation(
        self, engine, stack, monkeypatch
    ):
        monkeypatch.setattr(settings, "DEFAULT_CC_EMAILS", "cert@cc-test.example")
        monkeypatch.setattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL2", "l2@esc-test.example")
        monkeypatch.setattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL3", "l3@esc-test.example")
        url = make_site_url("ccs")
        insert_site(engine, url)
        mailer = FakeMailer()
        detector = FakeDetector(
            contacts=["abuse@registrar-test.example", "abuse@host-test.example"]
        )
        manager = make_manager(engine, stack, mailer=mailer, detector=detector, cc_emails=None)
        network_patches(stack)

        manager.run_reporting_cycle()

        assert len(mailer.to("abuse@registrar-test.example")) == 1
        assert len(mailer.to("abuse@host-test.example")) == 1
        assert len(mailer.to("cert@cc-test.example")) == 1
        assert len(mailer.to(SENDER)) == 1
        assert mailer.to("l2@esc-test.example") == [] and mailer.to("l3@esc-test.example") == []
        (copy,) = mailer.to("cert@cc-test.example")
        assert "abuse@registrar-test.example" in copy.text
        assert "abuse@host-test.example" in copy.text

    def test_form_only_provider_gets_an_analyst_task_not_an_email(self, engine, stack):
        url = make_site_url("cloudflare")
        insert_site(engine, url)
        mailer = FakeMailer()
        detector = FakeDetector(contacts=["abuse@cloudflare.com"], is_cloudflare=True)
        manager = make_manager(engine, stack, mailer=mailer, detector=detector)
        network_patches(stack)

        manager.run_reporting_cycle()

        assert mailer.sent == []
        (task,) = outbox_rows(engine, url)
        assert (task["channel"], task["status"]) == ("web_form", "pending_manual")
        assert task["form_url"] == "https://abuse.cloudflare.com/phishing"
        assert report_rows(engine, url)[0]["status"] == "pending_manual"
        assert site_row(engine, url)["abuse_report_sent"] == 1

    def test_site_without_contacts_gets_a_manual_review_task(self, engine, stack):
        url = make_site_url("nocontact")
        insert_site(engine, url)
        manager = make_manager(engine, stack, detector=FakeDetector(contacts=[]))
        network_patches(stack)

        manager.run_reporting_cycle()

        (task,) = outbox_rows(engine, url)
        assert (task["channel"], task["status"]) == ("manual_review", "pending_manual")

    def test_unresolvable_host_is_deferred_never_marked_down(self, engine, stack):
        """The old loop set site_status='down' itself whenever no IP came back
        (get_ip_info() also returns no IP when only RDAP fails), bypassing the
        takedown monitor's consecutive-failure rule."""
        url = make_site_url("noip")
        insert_site(engine, url)
        mailer = FakeMailer()
        manager = make_manager(
            engine, stack, mailer=mailer, detector=FakeDetector(resolved_ip=None)
        )
        network_patches(stack)

        manager.run_reporting_cycle()

        site = site_row(engine, url)
        assert site["site_status"] == "up"
        assert (site["abuse_report_sent"], site["report_attempts"]) == (0, 0)
        assert "does not resolve" in site["report_last_error"]
        assert site["report_lease_until"] is not None
        assert report_rows(engine, url) == [] and mailer.sent == []
        assert manager.run_reporting_cycle() == 0, "deferred until the next cycle"

    def test_screenshot_reaches_gsb(self, engine, stack, tmp_path):
        shot = tmp_path / "evidence.png"
        shot.write_bytes(b"\x89PNG screenshot")
        capture = {"success": True, "screenshot_path": str(shot), "filename": shot.name}
        url = make_site_url("gsb")
        insert_site(engine, url)
        manager = make_manager(engine, stack, screenshot=capture)
        gsb = network_patches(stack)

        manager.run_reporting_cycle()

        assert gsb.call_args.kwargs["screenshot_base64"] == "iVBORyBzY3JlZW5zaG90"

    def test_failure_is_recorded_on_the_site_and_retried_later(self, engine, stack):
        url = make_site_url("failing")
        insert_site(engine, url)
        detector = FakeDetector()
        detector.resolve_abuse_contacts = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("rdap exploded password=hunter2")
        )
        manager = make_manager(engine, stack, detector=detector)
        network_patches(stack)

        assert manager.run_reporting_cycle() == 1

        site = site_row(engine, url)
        assert site["abuse_report_sent"] == 0
        assert site["report_attempts"] == 1
        assert "password=***" in site["report_last_error"]
        assert "hunter2" not in site["report_last_error"]
        assert site["report_lease_until"] is not None, "back-off before the next attempt"
        assert manager.run_reporting_cycle() == 0


@pytest.mark.usefixtures("no_default_ccs")
class TestFollowUps:
    """Exit criterion: a sent report is tracked with an SLA deadline and is
    followed up after the deadline (clock mocked), without duplicates."""

    def test_follow_up_after_deadline_advances_sla_and_escalates_later(
        self, engine, stack, monkeypatch
    ):
        monkeypatch.setattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL2", "l2@esc-test.example")
        url = make_site_url("followup")
        insert_site(engine, url)
        mailer = FakeMailer()
        clock = FixedClock(MONDAY)
        manager = make_manager(engine, stack, mailer=mailer, clock=clock)
        network_patches(stack)
        manager.run_reporting_cycle()
        (report,) = report_rows(engine, url)
        deadline = report["sla_deadline"]

        clock.now = deadline - timedelta(minutes=1)
        assert manager.process_overdue_followups() == 0

        clock.now = deadline + timedelta(hours=1)
        assert manager.process_overdue_followups() == 1
        assert manager.process_overdue_followups() == 0, "same deadline must not repeat"

        followups = [m for m in mailer.sent if "Follow-up 1:" in m.subject]
        assert [m.recipients for m in followups] == [["abuse@registrar-test.example"], [SENDER]]
        assert report["report_id"] in followups[0].subject
        assert "VirusTotal: 9 of 70 engines" in followups[0].text
        assert mailer.to("l2@esc-test.example") == [], "no escalation on the first follow-up"
        (tracked,) = report_rows(engine, url)
        assert tracked["follow_up_count"] == 1
        assert tracked["sla_deadline"] == clock.now + timedelta(
            hours=settings.FOLLOWUP_INTERVAL_HOURS
        )
        assert tracked["last_follow_up_at"] == clock.now

        clock.now = tracked["sla_deadline"] + timedelta(minutes=5)
        assert manager.process_overdue_followups() == 1
        (escalated,) = mailer.to("l2@esc-test.example")
        assert "Follow-up 2:" in escalated.subject
        assert len([m for m in mailer.sent if "Follow-up 2:" in m.subject]) == 2

    def test_site_that_went_down_is_not_followed_up(self, engine, stack):
        url = make_site_url("down")
        insert_site(engine, url)
        clock = FixedClock(MONDAY)
        mailer = FakeMailer()
        manager = make_manager(engine, stack, mailer=mailer, clock=clock)
        network_patches(stack)
        manager.run_reporting_cycle()
        set_site_status(engine, url, "down")  # the takedown monitor confirmed it

        clock.now = MONDAY + timedelta(days=5)
        assert manager.process_overdue_followups() == 0
        assert report_rows(engine, url)[0]["follow_up_count"] == 0
        assert len(mailer.sent) == 2, "only the initial report and its CC copy"


@pytest.mark.usefixtures("no_default_ccs")
class TestConcurrency:
    def test_skip_locked_claims_do_not_block_or_overlap(self, engine, create_test_database):
        urls = [make_site_url(f"lock{i}") for i in range(4)]
        for url in urls:
            insert_site(engine, url)
        other_engine = create_engine(create_test_database)
        queue_a = SiteQueue(engine, worker_id="worker-a")
        queue_b = SiteQueue(other_engine, worker_id="worker-b")
        try:
            with engine.begin() as held:
                # Worker A's claim transaction is still open: its rows stay locked.
                claimed_a = queue_a.claim_batch(2, conn=held)
                claimed_b = queue_b.claim_batch(10)
        finally:
            other_engine.dispose()

        ours = set(urls)
        a_urls = {site.url for site in claimed_a} & ours
        b_urls = {site.url for site in claimed_b} & ours
        assert len(a_urls) == 2
        assert a_urls.isdisjoint(b_urls)
        assert a_urls | b_urls == ours

    def test_two_workers_report_each_site_exactly_once(self, engine, stack, create_test_database):
        urls = [make_site_url(f"race{i}") for i in range(6)]
        for url in urls:
            insert_site(engine, url)
        mailer = FakeMailer()
        bucket = "test-race-bucket"
        engines = [create_engine(create_test_database) for _ in range(2)]
        managers = [
            make_manager(eng, stack, mailer=mailer, bucket=bucket, worker_id=f"w{index}")
            for index, eng in enumerate(engines)
        ]
        network_patches(stack)
        barrier = threading.Barrier(2)
        processed = []

        def run(manager):
            barrier.wait()
            processed.append(manager.run_reporting_cycle())

        threads = [threading.Thread(target=run, args=(m,)) for m in managers]
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=60)
        finally:
            for eng in engines:
                eng.dispose()
            with engine.begin() as conn:
                conn.execute(text("DELETE FROM smtp_send_ledger WHERE bucket = :b"), {"b": bucket})

        assert sum(processed) >= len(urls)
        for url in urls:
            assert len(report_rows(engine, url)) == 1, url
        primaries = [m for m in mailer.sent if m.recipients == ["abuse@registrar-test.example"]]
        assert len(primaries) == len(urls)
        assert len({m.message_id for m in mailer.sent}) == len(mailer.sent)

    def test_outbox_row_is_delivered_once_by_competing_dispatchers(
        self, engine, stack, create_test_database
    ):
        url = make_site_url("outbox")
        insert_site(engine, url)
        repo = OutboxRepository(engine, worker_id="enqueuer")
        with engine.begin() as conn:
            repo.enqueue(
                conn,
                [
                    NewOutboxEntry(
                        report_id="ANISAKYS-TEST-OUTBOX",
                        site_url=url,
                        recipient=f"abuse{i}@desk-test.example",
                        payload={"subject": "s", "text": "t", "html": "<p>t</p>"},
                    )
                    for i in range(5)
                ],
            )
        mailer = FakeMailer()
        engines = [create_engine(create_test_database) for _ in range(2)]
        managers = [
            make_manager(eng, stack, mailer=mailer, worker_id=f"d{index}")
            for index, eng in enumerate(engines)
        ]
        barrier = threading.Barrier(2)

        def run(manager):
            barrier.wait()
            manager.dispatch_outbox(report_id="ANISAKYS-TEST-OUTBOX")

        threads = [threading.Thread(target=run, args=(m,)) for m in managers]
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=60)
        finally:
            for eng in engines:
                eng.dispose()

        assert sorted(r for m in mailer.sent for r in m.recipients) == [
            f"abuse{i}@desk-test.example" for i in range(5)
        ]
        assert {row["status"] for row in outbox_rows(engine, url)} == {"sent"}


@pytest.mark.usefixtures("no_default_ccs")
class TestDeliverySemantics:
    def _enqueue_one(self, engine, url):
        repo = OutboxRepository(engine, worker_id="enqueuer")
        with engine.begin() as conn:
            repo.enqueue(
                conn,
                [
                    NewOutboxEntry(
                        report_id="ANISAKYS-TEST-SEMANTICS",
                        site_url=url,
                        recipient="abuse@desk-test.example",
                        payload={"subject": "s", "text": "t", "html": "<p>t</p>"},
                    )
                ],
            )

    def test_enqueue_is_idempotent(self, engine):
        url = make_site_url("idem")
        self._enqueue_one(engine, url)
        self._enqueue_one(engine, url)

        assert len(outbox_rows(engine, url)) == 1

    def test_interrupted_attempt_is_retried_with_the_same_message_id(self, engine, stack):
        url = make_site_url("crash")
        self._enqueue_one(engine, url)
        crashed = OutboxRepository(engine, worker_id="crashed-worker")
        (row,) = crashed.claim_batch(1, report_id="ANISAKYS-TEST-SEMANTICS")
        with engine.begin() as conn:  # the worker died mid-send: its lease expires
            conn.execute(
                text(
                    "UPDATE abuse_report_outbox SET locked_until = now() - interval '1 second' "
                    "WHERE id = :id"
                ),
                {"id": row.id},
            )
        mailer = FakeMailer()
        manager = make_manager(engine, stack, mailer=mailer)

        manager.dispatch_outbox(report_id="ANISAKYS-TEST-SEMANTICS")

        (sent,) = mailer.sent
        (stored,) = outbox_rows(engine, url)
        assert stored["status"] == "sent"
        assert stored["attempts"] == 2
        assert sent.message_id == stored["message_id"]
        assert sent.message_id == f"<ANISAKYS-TEST-SEMANTICS.0.{row.id}@example.invalid>"

    def test_interrupted_row_without_attempts_left_is_failed_not_resent(self, engine, stack):
        url = make_site_url("exhausted")
        self._enqueue_one(engine, url)
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE abuse_report_outbox SET status = 'sending', attempts = max_attempts, "
                    "locked_by = 'dead', locked_until = now() - interval '1 minute' "
                    "WHERE site_url = :url"
                ),
                {"url": url},
            )
        mailer = FakeMailer()
        manager = make_manager(engine, stack, mailer=mailer)

        manager.dispatch_outbox()

        assert mailer.sent == []
        (stored,) = outbox_rows(engine, url)
        assert stored["status"] == "failed"
        assert "delivery state unknown" in stored["last_error"]

    def test_permanent_rejection_fails_the_row(self, engine, stack):
        url = make_site_url("reject")
        self._enqueue_one(engine, url)
        mailer = FakeMailer(fail=lambda rcpts: smtplib.SMTPResponseException(550, b"no such user"))
        manager = make_manager(engine, stack, mailer=mailer)

        manager.dispatch_outbox(report_id="ANISAKYS-TEST-SEMANTICS")

        (stored,) = outbox_rows(engine, url)
        assert (stored["status"], stored["attempts"]) == ("failed", 1)
        assert "550" in stored["last_error"]

    def test_transient_error_is_retried_later(self, engine, stack):
        url = make_site_url("transient")
        self._enqueue_one(engine, url)
        mailer = FakeMailer(fail=lambda rcpts: ConnectionRefusedError("relay down"))
        manager = make_manager(engine, stack, mailer=mailer)

        manager.dispatch_outbox(report_id="ANISAKYS-TEST-SEMANTICS")

        (stored,) = outbox_rows(engine, url)
        assert (stored["status"], stored["attempts"]) == ("pending", 1)
        assert "relay down" in stored["last_error"]

    def test_rate_limited_row_waits_without_using_an_attempt(self, engine, stack):
        url = make_site_url("ratelimited")
        self._enqueue_one(engine, url)
        mailer = FakeMailer()
        manager = make_manager(engine, stack, mailer=mailer, max_per_hour=0)

        result = manager.dispatch_outbox(report_id="ANISAKYS-TEST-SEMANTICS")

        assert result.deferred == 1 and mailer.attempts == 0
        (stored,) = outbox_rows(engine, url)
        assert (stored["status"], stored["attempts"]) == ("pending", 0)


@pytest.mark.usefixtures("no_default_ccs")
class TestExplicitSend:
    """send_abuse_report() is what the API and the analyzer call."""

    def test_explicit_send_claims_the_site_and_respects_the_cooldown(self, engine, stack):
        url = make_site_url("explicit")
        insert_site(engine, url)
        mailer = FakeMailer()
        manager = make_manager(engine, stack, mailer=mailer)
        network_patches(stack)

        first = manager.send_abuse_report(["abuse@registrar-test.example"], url, "whois")
        second = manager.send_abuse_report(["abuse@registrar-test.example"], url, "whois")

        assert (first, second) == (True, False)
        assert len(mailer.to("abuse@registrar-test.example")) == 1
        assert manager.run_reporting_cycle() == 0
        assert report_rows(engine, url)[0]["status"] == "sent"

    def test_explicit_send_skips_a_site_another_worker_holds(self, engine, stack):
        url = make_site_url("held")
        insert_site(engine, url)
        SiteQueue(engine, worker_id="scheduler").claim_url(url)
        mailer = FakeMailer()
        manager = make_manager(engine, stack, mailer=mailer)
        network_patches(stack)

        assert manager.send_abuse_report(["abuse@registrar-test.example"], url, "w") is False
        assert mailer.sent == []

    def test_explicit_send_routes_form_only_recipients(self, engine, stack):
        url = make_site_url("explicitform")
        mailer = FakeMailer()
        manager = make_manager(engine, stack, mailer=mailer)
        network_patches(stack)

        sent = manager.send_abuse_report(
            ["abuse@godaddy.com", "abuse@registrar-test.example"], url, "Registrar: GoDaddy"
        )

        assert sent is True
        assert mailer.to("abuse@godaddy.com") == []
        channels = sorted(row["channel"] for row in outbox_rows(engine, url))
        assert channels == ["email", "email", "web_form"]
