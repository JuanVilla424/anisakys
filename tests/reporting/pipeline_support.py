"""Shared helpers for the reporting-pipeline tests (real PostgreSQL, fake network)."""

from __future__ import annotations

import threading
import uuid
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import message_from_bytes
from types import SimpleNamespace
from typing import Callable, Dict, List, Optional
from unittest.mock import MagicMock, patch

from sqlalchemy import text

import src.reporting.abuse_manager as abuse_manager_module
from src.reporting.abuse_manager import AbuseReportManager
from src.reporting.email_detector import AbuseContactResolution, EnhancedAbuseEmailDetector
from src.reporting.smtp_rate_limiter import DatabaseSmtpRateLimiter

SITE_SUFFIX = ".pipeline-test.example"


@dataclass
class SentMessage:
    """One SMTP transaction captured by :class:`FakeMailer`."""

    recipients: List[str]
    subject: str
    message_id: str
    cc_header: Optional[str]
    text: str


class FakeMailer:
    """Thread-safe SMTP stand-in that records every message it accepts."""

    def __init__(self, fail: Optional[Callable[[List[str]], Optional[Exception]]] = None):
        self.sent: List[SentMessage] = []
        self.attempts = 0
        self._fail = fail
        self._lock = threading.Lock()

    def send(self, message, recipients):
        with self._lock:
            self.attempts += 1
        error = self._fail(list(recipients)) if self._fail else None
        if error is not None:
            raise error
        parsed = message_from_bytes(message.as_bytes())
        text_part = next(part for part in parsed.walk() if part.get_content_type() == "text/plain")
        with self._lock:
            self.sent.append(
                SentMessage(
                    recipients=list(recipients),
                    subject=str(message["Subject"]),
                    message_id=str(message["Message-ID"]),
                    cc_header=message["Cc"],
                    text=text_part.get_payload(decode=True).decode("utf-8"),
                )
            )
        return {}

    def to(self, address: str) -> List[SentMessage]:
        """Messages whose envelope included ``address``."""
        with self._lock:
            return [m for m in self.sent if address in m.recipients]


@dataclass
class FakeDetector:
    """Abuse-contact detector double with no network access."""

    contacts: List[str] = field(default_factory=lambda: ["abuse@registrar-test.example"])
    registrar: str = "Example Registrar Inc."
    resolved_ip: Optional[str] = "192.0.2.10"
    is_cloudflare: bool = False
    hosting_provider: Optional[str] = "Example Hosting"

    def get_enhanced_whois_info(self, domain: str) -> Dict:
        return {"registrar": self.registrar, "raw_whois": f"Domain Name: {domain}\n"}

    extract_registrar = staticmethod(EnhancedAbuseEmailDetector.extract_registrar)
    validate_abuse_email_domain = staticmethod(
        EnhancedAbuseEmailDetector.validate_abuse_email_domain
    )

    def resolve_abuse_contacts(self, domain, whois_info=None, registrar=None, site_content=None):
        return AbuseContactResolution(
            emails=list(self.contacts),
            resolved_ip=self.resolved_ip,
            is_cloudflare=self.is_cloudflare,
            hosting_provider=self.hosting_provider,
            asn="AS64500",
        )

    def get_enhanced_abuse_email(self, domain, whois_info=None, registrar=None):
        return list(self.contacts)

    def validate_email(self, email: str) -> bool:
        return "@" in email


class FixedClock:
    """Mutable clock returned to the manager instead of ``datetime.now``."""

    def __init__(self, now: datetime):
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def make_site_url(tag: str) -> str:
    """A unique URL under the test suffix (cleaned up by :func:`cleanup_sites`)."""
    return f"https://{tag}-{uuid.uuid4().hex[:8]}{SITE_SUFFIX}/login"


def insert_site(engine, url: str, **columns) -> int:
    """Insert a reportable phishing site and return its id."""
    values = {
        "manual_flag": 1,
        "site_status": "up",
        "abuse_report_sent": 0,
        "reported": 0,
        "priority": "high",
        "multi_api_threat_level": "high",
        "api_confidence_score": 92,
        "virustotal_result": '{"malicious": 9, "total_engines": 70}',
    }
    values.update(columns)
    names = ", ".join(values)
    binds = ", ".join(f":{name}" for name in values)
    with engine.begin() as conn:
        return conn.execute(
            text(
                f"INSERT INTO phishing_sites (url, first_seen, {names}) "
                f"VALUES (:url, now(), {binds}) RETURNING id"
            ),
            {"url": url, **values},
        ).scalar()


FENCE_OWNER = "pipeline-test-fence"


def fence_foreign_sites(engine) -> None:
    """Lease every reportable site that is not ours so counts stay deterministic.

    Rows left behind by other test modules would otherwise be claimed (and
    "reported" through the fake mailer) by these tests.
    """
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE phishing_sites SET report_claimed_by = :owner, "
                "report_lease_until = now() + interval '1 day' "
                "WHERE url NOT LIKE :like AND report_claimed_by IS NULL"
            ),
            {"owner": FENCE_OWNER, "like": f"%{SITE_SUFFIX}%"},
        )


def unfence_foreign_sites(engine) -> None:
    """Undo :func:`fence_foreign_sites`."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE phishing_sites SET report_claimed_by = NULL, report_lease_until = NULL "
                "WHERE report_claimed_by = :owner"
            ),
            {"owner": FENCE_OWNER},
        )


def cleanup_sites(engine) -> None:
    """Remove every row the pipeline tests created."""
    like = {"like": f"%{SITE_SUFFIX}%"}
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM abuse_report_outbox WHERE site_url LIKE :like"), like)
        conn.execute(text("DELETE FROM abuse_reports WHERE site_url LIKE :like"), like)
        conn.execute(text("DELETE FROM phishing_sites WHERE url LIKE :like"), like)


def make_manager(
    engine,
    stack: ExitStack,
    *,
    mailer: Optional[FakeMailer] = None,
    detector: Optional[FakeDetector] = None,
    clock: Optional[FixedClock] = None,
    bucket: Optional[str] = None,
    max_per_hour: int = 1000,
    cc_emails: Optional[List[str]] = (),
    screenshot: Optional[dict] = None,
    worker_id: Optional[str] = None,
) -> AbuseReportManager:
    """Build a manager on the real test database with every network edge faked."""
    screenshot_service = MagicMock()
    screenshot_service.capture_screenshot.return_value = screenshot or {"success": False}
    stack.enter_context(patch.object(abuse_manager_module, "MultiAPIValidator"))
    stack.enter_context(patch.object(abuse_manager_module, "GrinderReportClient"))
    stack.enter_context(
        patch.object(
            abuse_manager_module, "get_screenshot_service", return_value=screenshot_service
        )
    )
    manager = AbuseReportManager(
        SimpleNamespace(engine=engine),
        detector or FakeDetector(),
        cc_emails=None if cc_emails is None else list(cc_emails),
        timeout=5,
        clock=clock or FixedClock(datetime(2026, 10, 5, 10, 0, tzinfo=timezone.utc)),
        mailer=mailer or FakeMailer(),
        rate_limiter=DatabaseSmtpRateLimiter(
            engine, max_per_hour, bucket=bucket or f"test-{uuid.uuid4().hex[:10]}"
        ),
        worker_id=worker_id,
    )
    return manager


def network_patches(stack: ExitStack) -> MagicMock:
    """Patch attachments and the GSB submission; return the GSB mock.

    The pipeline itself never probes site liveness (the takedown monitor owns
    ``site_status``), so there is nothing else to fake.
    """
    stack.enter_context(
        patch.object(abuse_manager_module.AttachmentConfig, "get_all_attachments", return_value=[])
    )
    return stack.enter_context(
        patch.object(abuse_manager_module, "report_phishing_url", return_value={"success": True})
    )


def set_site_status(engine, url: str, status: str) -> None:
    """Simulate the takedown monitor recording a liveness change."""
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE phishing_sites SET site_status = :status WHERE url = :url"),
            {"status": status, "url": url},
        )


def report_rows(engine, url: str) -> List[dict]:
    """``abuse_reports`` rows of a site, oldest first, timestamps as UTC."""
    with engine.connect() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT report_id, status, recipients, follow_up_count, "
                    "CAST(sla_deadline AS timestamptz) AS sla_deadline, "
                    "CAST(report_date AS timestamptz) AS report_date, last_follow_up_at "
                    "FROM abuse_reports WHERE site_url = :url ORDER BY id"
                ),
                {"url": url},
            ).mappings()
        ]


def outbox_rows(engine, url: str) -> List[dict]:
    """Outbox rows of a site, in insertion order."""
    with engine.connect() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT id, report_id, channel, audience, followup_seq, recipient, cc, "
                    "form_url, status, attempts, last_error, message_id "
                    "FROM abuse_report_outbox WHERE site_url = :url ORDER BY id"
                ),
                {"url": url},
            ).mappings()
        ]


def site_row(engine, url: str) -> dict:
    """The phishing_sites row of ``url``."""
    with engine.connect() as conn:
        return dict(
            conn.execute(
                text(
                    "SELECT abuse_report_sent, reported, report_claimed_by, report_lease_until, "
                    "report_attempts, report_last_error, abuse_email, site_status "
                    "FROM phishing_sites WHERE url = :url"
                ),
                {"url": url},
            )
            .mappings()
            .one()
        )
