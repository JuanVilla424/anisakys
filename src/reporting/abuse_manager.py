"""
Abuse Report Manager for Anisakys Phishing Detection Engine.

Turns flagged phishing sites into abuse reports, delivers them and follows
them up. The pipeline is built so that any number of processes can run it
against one database without sending anything twice:

1. **Claim.** A worker claims a small batch of reportable sites with
   ``SELECT ... FOR UPDATE SKIP LOCKED`` and a lease, in a short committed
   transaction (:class:`~src.reporting.site_queue.SiteQueue`).
2. **Enrich, outside any transaction.** WHOIS/RDAP, DNS, hosting lookup, site
   status, screenshot, threat-intel side reports.
3. **Enqueue.** One short transaction records the tracked report
   (``abuse_reports``, status ``queued``), one outbox row per primary
   recipient, a single CC copy, analyst tasks for form-only providers, and
   marks the site as handled — only while the worker still owns the lease.
4. **Deliver.** Outbox rows are claimed (``SKIP LOCKED``), sent through the
   one SMTP path (:mod:`src.reporting.mailer`, TLS and auth) under the shared
   rate limit, and their outcome recorded in another short transaction. The
   first accepted primary e-mail moves the report to ``sent`` and starts its
   SLA clock. See :mod:`src.reporting.outbox` for the delivery semantics.

CC strategy: every primary recipient gets its own message with no ``Cc``
header, and the CC list (sender plus ``DEFAULT_CC_EMAILS``) gets exactly one
copy that names the recipients it went to. Escalation lists are never
copied on the first send.
"""

from __future__ import annotations

import base64
import datetime
import json
import logging
import os
import re
import smtplib
import threading
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Sequence

from sqlalchemy import text

from src.config import settings
from src.dns.network_utils import get_ip_info
from src.detection.utils import PhishingUtils
from src.intelligence import (
    GrinderReportClient,
    GRINDER_INTEGRATION_ENABLED,
    MultiAPIValidator,
    report_phishing_url,
    AUTO_ANALYSIS_ENABLED,
)
from src.logger import logger
from src.observability.structured_logger import log_error, log_with_context
from src.observability.metrics import (
    increment_counter,
    METRIC_REPORTS_SENT_TOTAL,
    METRIC_SMTP_RATE_LIMITED,
)
from src.models import AttachmentConfig
from src.reporting.abuse_contact_validator import AbuseContactValidator
from src.reporting.db import short_transaction, utc_now
from src.reporting.mailer import SmtpMailer
from src.reporting.message_builder import (
    build_email,
    build_evidence,
    message_id_for,
    render_initial_report,
    unique_preserving,
)
from src.reporting.outbox import (
    NewOutboxEntry,
    OutboxAudience,
    OutboxChannel,
    OutboxRepository,
    OutboxRow,
    default_worker_id,
    sanitize_error,
)
from src.reporting.recipient_policy import host_of, is_acceptable_recipient, normalize_email
from src.reporting.report_tracker import (
    ReportStatus,
    ReportTracker,
    create_report_record,
    generate_report_id,
)
from src.reporting.routing import DeliveryPlan, plan_delivery
from src.reporting.site_queue import ClaimedSite, SiteQueue
from src.reporting.smtp_rate_limiter import DatabaseSmtpRateLimiter
from src.screenshot_client import get_screenshot_service
from src.utils.serialization import serialize_for_json
from src.shutdown import is_shutdown_requested, wait_for_shutdown

if TYPE_CHECKING:
    from src.database import DatabaseManager
    from src.reporting.email_detector import EnhancedAbuseEmailDetector

# Testing mode flag - controls CC email suppression (default: False in production)
IS_TESTING_MODE = False

# Upper bound of sites one reporting cycle processes before yielding.
MAX_SITES_PER_CYCLE = 200
# Recipient recorded on analyst tasks for sites without a usable contact.
UNRESOLVED_CONTACT = "unresolved-contact"


class LeaseLostError(RuntimeError):
    """Another worker took over a site while this one was enriching it."""


def encode_screenshot_for_gsb(
    capture_result: Optional[Dict[str, Any]], max_bytes: Optional[int] = None
) -> Optional[str]:
    """Base64-encode the screenshot file of a capture result for GSB.

    The screenshot services return the file location (``screenshot_path``),
    never the image bytes, so the file has to be read here.

    Args:
        capture_result: Result of ``capture_screenshot()`` (may be ``None``).
        max_bytes: Larger files are not submitted; defaults to
            ``GSB_SCREENSHOT_MAX_BYTES``.

    Returns:
        The base64 text, or ``None`` when there is no usable screenshot.
    """
    if not capture_result or not capture_result.get("success"):
        return None
    path = capture_result.get("screenshot_path")
    if not path or not os.path.isfile(path):
        logger.warning("Screenshot file missing; submitting to GSB without it")
        return None
    limit = settings.GSB_SCREENSHOT_MAX_BYTES if max_bytes is None else max_bytes
    size = os.path.getsize(path)
    if limit and size > limit:
        logger.warning(f"Screenshot is {size} bytes (limit {limit}); not sent to GSB")
        return None
    with open(path, "rb") as handle:
        return base64.b64encode(handle.read()).decode("ascii")


def _split_addresses(value: Optional[str]) -> List[str]:
    """Split a comma-separated address setting.

    Args:
        value: Setting value.

    Returns:
        Normalised, non-empty addresses.
    """
    return unique_preserving(normalize_email(part) for part in (value or "").split(","))


def _is_retryable(error: BaseException) -> bool:
    """Whether a failed SMTP attempt may succeed later.

    Args:
        error: The exception raised by the send.

    Returns:
        ``False`` for permanent rejections (every recipient refused, 5xx) and
        for errors that are not SMTP/network errors.
    """
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        return False
    if isinstance(error, smtplib.SMTPResponseException):
        return error.smtp_code < 500
    return isinstance(error, (smtplib.SMTPException, OSError))


def _max_attachment_bytes() -> int:
    """Per-file attachment limit from ``MAX_ATTACHMENT_SIZE_MB`` (default 25 MB).

    Returns:
        Limit in bytes.
    """
    return int(settings.MAX_ATTACHMENT_SIZE_MB or 25) * 1024 * 1024


def _max_email_bytes() -> int:
    """Whole-message limit from ``MAX_EMAIL_SIZE_MB`` (default 50 MB).

    Returns:
        Limit in bytes.
    """
    return int(settings.MAX_EMAIL_SIZE_MB or 50) * 1024 * 1024


@dataclass
class SiteContext:
    """What the pipeline knows about a site when it builds a report."""

    url: str
    claim: Optional[ClaimedSite] = None
    origin: str = "automated"
    candidates: List[str] = field(default_factory=list)
    multi_api_results: Optional[Dict[str, Any]] = None
    detection_keywords: Optional[str] = None
    first_seen: Optional[datetime.datetime] = None
    whois_info: Any = None
    whois_text: str = ""
    registrar: Optional[str] = None
    resolved_ip: Optional[str] = None
    asn: Optional[str] = None
    hosting_provider: Optional[str] = None
    is_cloudflare: bool = False
    site_status: Optional[str] = None


@dataclass
class ReportOutcome:
    """Result of building and enqueueing one report."""

    report_id: str
    status: str
    emails: List[str] = field(default_factory=list)
    form_tasks: int = 0
    screenshot: Optional[Dict[str, Any]] = None


@dataclass
class DispatchResult:
    """Counters of one outbox dispatch pass."""

    sent: int = 0
    failed: int = 0
    deferred: int = 0
    sent_report_ids: List[str] = field(default_factory=list)


class AbuseReportManager:
    """Builds, delivers and follows up abuse reports (see the module docstring)."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        abuse_detector: EnhancedAbuseEmailDetector,
        cc_emails: Optional[List[str]],
        timeout: int,
        monitoring_event: threading.Event = None,
        clock: Optional[Callable[[], datetime.datetime]] = None,
        mailer: Optional[SmtpMailer] = None,
        rate_limiter: Optional[Any] = None,
        worker_id: Optional[str] = None,
    ):
        """Create a manager.

        Args:
            db_manager: Database manager (its engine backs every query).
            abuse_detector: Abuse contact detector.
            cc_emails: Addresses that receive the single CC copy of each
                report; ``None`` means ``DEFAULT_CC_EMAILS``.
            timeout: Network timeout in seconds for site checks/screenshots.
            monitoring_event: Set when the takedown monitor finished its first
                pass; the reporting loop waits for it.
            clock: Returns the current UTC time (injectable for tests).
            mailer: SMTP sender (defaults to the shared TLS-aware mailer).
            rate_limiter: Object with ``acquire()``; defaults to the
                database-backed limiter shared by every process.
            worker_id: Lease owner name; defaults to ``host:pid``.
        """
        self.db_manager = db_manager
        self.abuse_detector = abuse_detector
        self.multi_api_validator = MultiAPIValidator()
        self.grinder_client = GrinderReportClient()

        self.abuse_contact_validator = AbuseContactValidator(timeout=timeout)
        self.screenshot_service = get_screenshot_service(
            screenshots_dir=settings.SCREENSHOTS_DIR, timeout=timeout
        )
        self.report_tracker = ReportTracker(db_manager.engine)
        # Shared through the database: the cap holds across every process.
        self._smtp_rate_limiter = rate_limiter or DatabaseSmtpRateLimiter(
            db_manager.engine, settings.SMTP_RATE_LIMIT_PER_HOUR
        )
        self.mailer = mailer or SmtpMailer()
        self.clock = clock or utc_now
        self.worker_id = worker_id or default_worker_id()
        self.outbox = OutboxRepository(db_manager.engine, worker_id=self.worker_id)
        self.site_queue = SiteQueue(db_manager.engine, worker_id=self.worker_id)

        if cc_emails is None:
            self.cc_emails = _split_addresses(settings.DEFAULT_CC_EMAILS)
        else:
            self.cc_emails = unique_preserving(normalize_email(email) for email in cc_emails)
        self.timeout = timeout
        self.monitoring_event = monitoring_event

        # Initialize running flag for followup worker
        self.running = True

    @property
    def engine(self):
        """Database engine shared by the tracker, outbox and site queue.

        Returns:
            The SQLAlchemy engine.
        """
        return self.db_manager.engine

    # ------------------------------------------------------------------
    # Threat-intel side reports
    # ------------------------------------------------------------------

    def report_ip_to_grinder(
        self, ip_address: str, url: str, detection_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Report malicious IP to Grinder with comprehensive context.

        Args:
            ip_address (str): The malicious IP address
            url (str): The phishing URL associated with this IP
            detection_context (Dict[str, Any]): Detection context and metadata

        Returns:
            Dict[str, Any]: Report result
        """
        if not GRINDER_INTEGRATION_ENABLED:
            logger.debug("Grinder integration disabled, skipping IP report")
            return {"status": "disabled", "message": "Grinder integration not configured"}

        enhanced_context = detection_context.copy()
        enhanced_context.update(
            {
                "domains": enhanced_context.get("domains", []) + [host_of(url)],
                "source_url": url,
                "detection_timestamp": utc_now().isoformat(),
            }
        )

        confidence = enhanced_context.get("api_confidence", 0)
        if confidence == 0:
            threat_level = enhanced_context.get("threat_level", "").lower()
            if threat_level == "critical":
                confidence = 95
            elif threat_level == "high":
                confidence = 90
            elif threat_level == "medium":
                confidence = 75
            else:
                confidence = 60

        result = self.grinder_client.report_malicious_ip(
            ip_address, enhanced_context, confidence=confidence
        )

        if result.get("status") == "success":
            logger.info(f"Reported IP {ip_address} to Grinder for URL {url}")
        elif result.get("status") == "rate_limited":
            logger.warning(f"Rate limited when reporting IP {ip_address} to Grinder")
        else:
            logger.warning(f"Failed to report IP {ip_address} to Grinder: {result}")

        return result

    def _report_ip_side_channels(self, ctx: SiteContext) -> None:
        """Share the site's IP with Grinder (best effort, never blocks a report).

        Args:
            ctx: Site context.
        """
        if not GRINDER_INTEGRATION_ENABLED or IS_TESTING_MODE or not ctx.resolved_ip:
            return
        results = ctx.multi_api_results or {}
        context = {
            "method": "abuse_report_pipeline",
            "domains": [host_of(ctx.url)],
            "severity": "high",
            "threat_level": results.get("aggregated_threat_level", "high"),
            "keywords": ["phishing", "abuse_report"],
            "api_confidence": results.get("confidence_score", 0),
        }
        try:
            self.report_ip_to_grinder(ctx.resolved_ip, ctx.url, context)
        except Exception as e:
            logger.warning(f"Grinder IP report failed for {ctx.url}: {sanitize_error(e)}")

    def _submit_to_gsb(self, url: str, screenshot: Optional[Dict[str, Any]]) -> None:
        """Submit the URL (and its screenshot) to Google Safe Browsing.

        Args:
            url: Reported URL.
            screenshot: Capture result, if any.
        """
        if IS_TESTING_MODE:
            return
        try:
            result = report_phishing_url(
                url=url, screenshot_base64=encode_screenshot_for_gsb(screenshot)
            )
        except Exception as e:
            logger.warning(f"GSB submission error for {url}: {sanitize_error(e)}")
            return
        if result.get("success"):
            logger.info(f"Submitted {url} to GSB via {result.get('method')}")
        else:
            logger.warning(f"GSB submission failed for {url}: {result.get('message')}")

    # ------------------------------------------------------------------
    # Contact resolution helpers
    # ------------------------------------------------------------------

    def get_enhanced_abuse_emails(self, whois_info, domain: str) -> List[str]:
        """Abuse contacts for ``domain``: cached registrar contacts, else the detector's.

        Args:
            whois_info: Registration data of the domain.
            domain: Reported host name.

        Returns:
            Policy-checked contacts, most trusted first.
        """
        emails: List[str] = []
        registrar = self.abuse_detector.extract_registrar(whois_info) or ""
        if registrar:
            cached = self.db_manager.get_registrar_abuse_emails(registrar)
            if cached:
                logger.info(f"Cached registrar abuse contacts for {registrar}: {cached}")
                emails.extend(self._parse_stored(cached))
        if not emails:
            emails.extend(
                self.abuse_detector.get_enhanced_abuse_email(domain, whois_info, registrar) or []
            )
        normalised = unique_preserving(normalize_email(email) for email in emails)
        return [email for email in normalised if is_acceptable_recipient(email, domain)]

    @staticmethod
    def _parse_stored(value: Optional[str]) -> List[str]:
        """Parse a stored abuse-e-mail column (JSON list, list repr or CSV).

        Args:
            value: Stored value.

        Returns:
            The addresses.
        """
        from src.reporting.email_detector import EnhancedAbuseEmailDetector

        return EnhancedAbuseEmailDetector.parse_stored_abuse_emails(value or "")

    # ------------------------------------------------------------------
    # Reporting loop (scheduler role)
    # ------------------------------------------------------------------

    def report_phishing_sites(self) -> None:
        """Scheduler loop: report claimable sites every ``REPORT_INTERVAL`` seconds."""
        if self.monitoring_event:
            logger.info("Waiting for the takedown monitor's first pass before reporting")
            while not self.monitoring_event.wait(timeout=5):
                if is_shutdown_requested():
                    return
            logger.info("Takedown monitor ready; starting abuse reporting")

        while not is_shutdown_requested():
            try:
                processed = self.run_reporting_cycle()
                if processed:
                    logger.info(f"Reporting cycle processed {processed} site(s)")
            except Exception as e:
                log_error(
                    logger,
                    e,
                    {"operation": "reporting_cycle", "event_type": "reporting_cycle_failed"},
                )
            if wait_for_shutdown(settings.REPORT_INTERVAL):
                break

    def run_reporting_cycle(
        self, manual_only: bool = False, attachment_paths: Optional[List[str]] = None
    ) -> int:
        """Claim and report sites until none is left (or the cycle cap is hit).

        Args:
            manual_only: Only analyst-flagged sites not processed yet.
            attachment_paths: Extra files for every report; defaults to the
                configured attachments.

        Returns:
            Number of sites processed.
        """
        processed = 0
        while processed < MAX_SITES_PER_CYCLE and not is_shutdown_requested():
            sites = self.site_queue.claim_batch(settings.REPORT_CLAIM_BATCH_SIZE, manual_only)
            if not sites:
                break
            for site in sites:
                if is_shutdown_requested():
                    self.site_queue.release(site.id)
                    continue
                self._process_claimed_site(site, attachment_paths)
                processed += 1
        return processed

    def process_manual_reports(self, attachment_paths: Optional[List[str]] = None) -> int:
        """Report every analyst-flagged site that was never processed (CLI).

        Args:
            attachment_paths: Extra files for every report.

        Returns:
            Number of sites processed.
        """
        processed = self.run_reporting_cycle(manual_only=True, attachment_paths=attachment_paths)
        self.dispatch_outbox()
        logger.info(f"Processed {processed} flagged site(s)")
        return processed

    def _process_claimed_site(
        self, site: ClaimedSite, attachment_paths: Optional[List[str]] = None
    ) -> Optional[ReportOutcome]:
        """Enrich, report and deliver one claimed site; record any failure.

        Args:
            site: The claimed site.
            attachment_paths: Extra files for the report.

        Returns:
            The outcome, or ``None`` when nothing was reported.
        """
        try:
            ctx = self._enrich_claimed_site(site)
            if not ctx.resolved_ip:
                # Only the takedown monitor declares a site down (it needs several
                # consecutive failed probes); here the report is just postponed.
                reason = "host does not resolve; report deferred to the next cycle"
                logger.info(f"{site.url}: {reason}")
                self.site_queue.defer(site.id, reason)
                return None
            outcome = self._create_report(ctx, attachment_paths)
        except Exception as e:
            self.site_queue.release(site.id, error=e)
            log_error(
                logger,
                e,
                {
                    "url": site.url,
                    "operation": "report_site",
                    "attempt": site.report_attempts + 1,
                    "event_type": "abuse_report_site_failed",
                },
            )
            return None
        self.dispatch_outbox(report_id=outcome.report_id)
        self._submit_to_gsb(site.url, outcome.screenshot)
        return outcome

    def _enrich_claimed_site(self, site: ClaimedSite) -> SiteContext:
        """Gather everything a report needs; network I/O, no open transaction.

        Args:
            site: The claimed site.

        Returns:
            The site context.
        """
        domain = host_of(site.url)
        results = site.multi_api_results
        if site.manual_flag and not results and AUTO_ANALYSIS_ENABLED:
            results = self.multi_api_validator.comprehensive_scan(site.url)
            self._store_api_results(site.url, results)

        whois_info = self.abuse_detector.get_enhanced_whois_info(domain)
        registrar = self.abuse_detector.extract_registrar(whois_info)
        resolution = self.abuse_detector.resolve_abuse_contacts(domain, whois_info, registrar)

        stored = self._parse_stored(site.all_abuse_emails or site.abuse_email)
        if site.manual_emails:
            candidates = stored + list(resolution.emails)
        else:
            candidates = list(resolution.emails) or stored

        return SiteContext(
            url=site.url,
            claim=site,
            origin="analyst" if site.manual_flag else "automated",
            candidates=candidates,
            multi_api_results=results,
            detection_keywords=site.detection_keywords,
            first_seen=site.first_seen,
            whois_info=whois_info,
            whois_text=self._whois_text(whois_info),
            registrar=registrar,
            resolved_ip=resolution.resolved_ip,
            asn=resolution.asn,
            hosting_provider=resolution.hosting_provider,
            is_cloudflare=resolution.is_cloudflare,
            site_status=site.site_status,
        )

    @staticmethod
    def _whois_text(whois_info: Any) -> str:
        """Readable registration data for the report body.

        Args:
            whois_info: python-whois object, dict or text.

        Returns:
            Raw WHOIS text when available, else a JSON dump.
        """
        if not whois_info:
            return ""
        if isinstance(whois_info, str):
            return whois_info
        if isinstance(whois_info, dict) and isinstance(whois_info.get("raw_whois"), str):
            return whois_info["raw_whois"]
        raw = getattr(whois_info, "text", None)
        if isinstance(raw, str):
            return raw
        try:
            return json.dumps(serialize_for_json(whois_info), indent=2, default=str)
        except (TypeError, ValueError):
            return str(whois_info)

    def _store_api_results(self, url: str, results: Dict[str, Any]) -> None:
        """Persist fresh multi-API results for a site.

        Args:
            url: Site URL.
            results: Results from ``comprehensive_scan``.
        """
        with short_transaction(self.engine) as conn:
            conn.execute(
                text("""
                    UPDATE phishing_sites
                    SET virustotal_result = :vt, urlvoid_result = :uv, phishtank_result = :pt,
                        multi_api_threat_level = :threat_level,
                        api_confidence_score = :confidence
                    WHERE url = :url
                    """),
                {
                    "vt": json.dumps(results.get("virustotal", {})),
                    "uv": json.dumps(results.get("urlvoid", {})),
                    "pt": json.dumps(results.get("phishtank", {})),
                    "threat_level": results.get("aggregated_threat_level"),
                    "confidence": results.get("confidence_score"),
                    "url": url,
                },
            )

    # ------------------------------------------------------------------
    # Report creation (enqueue)
    # ------------------------------------------------------------------

    def _plan(self, ctx: SiteContext) -> DeliveryPlan:
        """Decide recipients and analyst tasks for a site.

        Args:
            ctx: Site context.

        Returns:
            The delivery plan.
        """
        test_email = normalize_email(settings.TEST_EMAIL or "")
        if test_email and test_email in (normalize_email(e) for e in ctx.candidates):
            logger.warning("Development mode: report redirected to TEST_EMAIL only")
            return DeliveryPlan(emails=[test_email])
        plan = plan_delivery(
            ctx.candidates,
            ctx.url,
            registrar=ctx.registrar,
            hosting_provider=ctx.hosting_provider,
            is_cloudflare=ctx.is_cloudflare,
            max_recipients=settings.REPORT_MAX_PRIMARY_RECIPIENTS,
            validate_email=self.abuse_detector.validate_email,
        )
        for email, reason in plan.rejected:
            logger.warning(f"Not e-mailing {email} about {ctx.url}: {reason}")
        for task in plan.form_tasks:
            logger.warning(
                f"Analyst task: report {ctx.url} through the {task.provider} web form "
                f"({task.form_url}): {task.reason}"
            )
        return plan

    def _cc_copy_recipients(self, primaries: Sequence[str], extra: Sequence[str] = ()) -> List[str]:
        """Who gets the single CC copy of a message.

        Args:
            primaries: Primary recipients (never copied twice).
            extra: Additional addresses (escalation contacts).

        Returns:
            The sender, configured CCs and ``extra``, minus the primaries; empty
            in testing mode, when there are no primaries, or in development
            mode (``TEST_EMAIL`` as recipient).
        """
        test_email = normalize_email(settings.TEST_EMAIL or "")
        if IS_TESTING_MODE or not primaries or (test_email and test_email in primaries):
            return []
        sender = normalize_email(settings.ABUSE_EMAIL_SENDER)
        candidates = unique_preserving([sender, *self.cc_emails, *extra])
        return [address for address in candidates if address and address not in primaries]

    def _capture_screenshot(self, url: str) -> Optional[Dict[str, Any]]:
        """Capture visual evidence; a failure only means no screenshot.

        Args:
            url: Site URL.

        Returns:
            The capture result, or ``None``.
        """
        if not getattr(self, "screenshot_service", None):
            return None
        try:
            result = self.screenshot_service.capture_screenshot(url, use_async=True)
        except Exception as e:
            logger.warning(f"Screenshot capture failed for {url}: {sanitize_error(e)}")
            return None
        if isinstance(result, dict) and result.get("success"):
            return result
        reason = result.get("error", "unknown error") if isinstance(result, dict) else "none"
        logger.warning(f"No screenshot for {url}: {reason}")
        return None

    def _create_report(
        self, ctx: SiteContext, attachment_paths: Optional[List[str]] = None
    ) -> ReportOutcome:
        """Render a report and enqueue its deliveries in one short transaction.

        Args:
            ctx: Site context (from a claim or an explicit send).
            attachment_paths: Extra files; defaults to the configured ones.

        Returns:
            The outcome (report id, status, recipients).

        Raises:
            LeaseLostError: The site's lease was taken over meanwhile.
        """
        plan = self._plan(ctx)
        screenshot = self._capture_screenshot(ctx.url)
        attachments = list(
            AttachmentConfig.get_all_attachments() if attachment_paths is None else attachment_paths
        )
        if screenshot:
            attachments.append(screenshot["screenshot_path"])
        self._report_ip_side_channels(ctx)

        report_id = generate_report_id()
        now = self.clock()
        evidence = build_evidence(
            ctx.url,
            origin=ctx.origin,
            brand_name=settings.REPORT_BRAND_NAME,
            multi_api_results=ctx.multi_api_results,
            detection_keywords=ctx.detection_keywords,
            first_seen=ctx.first_seen,
            resolved_ip=ctx.resolved_ip,
            asn=ctx.asn,
            hosting_provider=ctx.hosting_provider,
            registrar=ctx.registrar,
            whois_text=ctx.whois_text,
            attachments=attachments,
            reproduction_note=settings.REPORT_REPRODUCTION_NOTE,
        )
        sender = normalize_email(settings.ABUSE_EMAIL_SENDER)
        cc_list = self._cc_copy_recipients(plan.emails)
        common: Dict[str, Any] = dict(
            report_id=report_id,
            report_time=now,
            subject_base=settings.ABUSE_EMAIL_SUBJECT,
            organization=settings.REPORT_ORGANIZATION,
            followup_hours=settings.FOLLOWUP_INTERVAL_HOURS,
            cc_disclosure=[address for address in cc_list if address != sender],
        )
        rendered = render_initial_report(evidence, **common)

        entries = [
            NewOutboxEntry(
                report_id=report_id,
                site_url=ctx.url,
                recipient=email,
                payload=rendered.to_payload(attachments),
            )
            for email in plan.emails
        ]
        if cc_list:
            copy = render_initial_report(evidence, notified_recipients=plan.emails, **common)
            entries.append(
                NewOutboxEntry(
                    report_id=report_id,
                    site_url=ctx.url,
                    recipient=cc_list[0],
                    cc=cc_list[1:],
                    audience=OutboxAudience.CC,
                    payload=copy.to_payload(attachments),
                )
            )
        for task in plan.form_tasks:
            entries.append(
                NewOutboxEntry(
                    report_id=report_id,
                    site_url=ctx.url,
                    recipient=task.provider,
                    channel=OutboxChannel.WEB_FORM,
                    form_url=task.form_url,
                    payload={
                        "subject": rendered.subject,
                        "text": rendered.text,
                        "reason": task.reason,
                    },
                )
            )
        if plan.is_empty:
            logger.warning(f"No usable abuse contact for {ctx.url}; analyst review task created")
            entries.append(
                NewOutboxEntry(
                    report_id=report_id,
                    site_url=ctx.url,
                    recipient=UNRESOLVED_CONTACT,
                    channel=OutboxChannel.MANUAL_REVIEW,
                    payload={
                        "subject": rendered.subject,
                        "text": rendered.text,
                        "reason": "no usable abuse contact",
                        "rejected": [list(item) for item in plan.rejected],
                    },
                )
            )

        status = ReportStatus.QUEUED if plan.emails else ReportStatus.PENDING_MANUAL
        record = create_report_record(
            site_url=ctx.url,
            recipients=plan.emails,
            subject=rendered.subject,
            cc_recipients=cc_list or None,
            multi_api_results=ctx.multi_api_results,
            screenshot_included=bool(screenshot),
            report_id=report_id,
            status=status.value,
        )
        record.evidence = evidence.to_dict()
        record.screenshot_path = screenshot["screenshot_path"] if screenshot else None
        record.attachment_count = len(attachments)

        with short_transaction(self.engine) as conn:
            if ctx.claim is not None:
                updated = self.site_queue.complete(
                    conn,
                    ctx.claim.id,
                    {
                        "whois_info": (
                            json.dumps(serialize_for_json(ctx.whois_info), default=str)
                            if ctx.whois_info
                            else None
                        ),
                        "resolved_ip": ctx.resolved_ip,
                        "asn_provider": ctx.hosting_provider,
                        "is_cloudflare": int(ctx.is_cloudflare) if ctx.resolved_ip else None,
                        "abuse_email": json.dumps(plan.emails) if plan.emails else None,
                    },
                )
                if not updated:
                    raise LeaseLostError(f"lease on {ctx.url} was taken over by another worker")
            self.report_tracker.insert_report(conn, record)
            self.outbox.enqueue(conn, entries)

        log_with_context(
            logger,
            logging.INFO,
            "Abuse report queued",
            url=ctx.url,
            report_id=report_id,
            status=status.value,
            recipients=len(plan.emails),
            form_tasks=len(plan.form_tasks),
            event_type="abuse_report_queued",
        )
        return ReportOutcome(
            report_id=report_id,
            status=status.value,
            emails=list(plan.emails),
            form_tasks=len(plan.form_tasks),
            screenshot=screenshot,
        )

    # ------------------------------------------------------------------
    # Explicit sends (API, analyzer, CLI)
    # ------------------------------------------------------------------

    def send_abuse_report(
        self,
        abuse_emails: List[str],
        site_url: str,
        whois_str: str,
        attachment_paths: Optional[List[str]] = None,
        test_mode: bool = False,
        multi_api_results: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Report ``site_url`` to the given contacts now, through the outbox.

        The site row (when it exists) is claimed first, so a concurrent
        scheduler or API worker never reports it twice, and a site reported
        within ``REPORT_RESEND_COOLDOWN_HOURS`` is skipped. Recipients go
        through the same policy and form routing as scheduled reports.

        Args:
            abuse_emails (List[str]): Abuse contacts chosen by the caller
            site_url (str): URL of the phishing site
            whois_str (str): Registration data to include
            attachment_paths (Optional[List[str]]): Files to attach
            test_mode (bool): Send a marked test message straight to the given
                addresses (no tracking, CC, GSB or Grinder)
            multi_api_results (Optional[Dict[str, Any]]): Multi-API validation results

        Returns:
            bool: True if at least one abuse desk accepted the report
        """
        if test_mode:
            return self._send_test_report(abuse_emails, site_url, whois_str, attachment_paths)

        tracked, claim = self.site_queue.claim_url(site_url)
        if tracked and claim is None:
            logger.info(
                f"Skipping report for {site_url}: another worker holds it or it was "
                "reported within the resend cool-down"
            )
            return False
        if claim is not None and not multi_api_results:
            multi_api_results = claim.multi_api_results

        ctx = SiteContext(
            url=site_url,
            claim=claim,
            origin="analyst" if claim is None or claim.manual_flag else "automated",
            candidates=list(abuse_emails or []),
            multi_api_results=multi_api_results,
            detection_keywords=claim.detection_keywords if claim else None,
            first_seen=claim.first_seen if claim else None,
            whois_text=whois_str or "",
            registrar=self.abuse_detector.extract_registrar(whois_str or ""),
        )
        try:
            outcome = self._create_report(ctx, attachment_paths)
        except Exception as e:
            if claim is not None:
                self.site_queue.release(claim.id, error=e)
            log_error(
                logger,
                e,
                {"url": site_url, "operation": "send_abuse_report", "event_type": "report_failed"},
            )
            return False

        result = self.dispatch_outbox(report_id=outcome.report_id)
        self._submit_to_gsb(site_url, outcome.screenshot)
        return outcome.report_id in result.sent_report_ids

    def _send_test_report(
        self,
        abuse_emails: Sequence[str],
        site_url: str,
        whois_str: str,
        attachment_paths: Optional[List[str]],
    ) -> bool:
        """Send a marked test report directly to ``abuse_emails`` (CLI and tests).

        Uses the same templates, SMTP path and rate limit as real reports but
        no tracking, outbox, CC, GSB or Grinder.

        Args:
            abuse_emails: Test recipients.
            site_url: URL shown in the report.
            whois_str: Registration data shown in the report.
            attachment_paths: Files to attach; defaults to the configured ones.

        Returns:
            ``True`` if at least one message was accepted.
        """
        attachments = list(
            AttachmentConfig.get_all_attachments() if attachment_paths is None else attachment_paths
        )
        report_id = generate_report_id()
        sender = settings.ABUSE_EMAIL_SENDER
        try:
            evidence = build_evidence(
                site_url,
                origin="analyst",
                brand_name=settings.REPORT_BRAND_NAME,
                multi_api_results=None,
                whois_text=whois_str,
                attachments=attachments,
                reproduction_note=settings.REPORT_REPRODUCTION_NOTE,
            )
            rendered = render_initial_report(
                evidence,
                report_id=report_id,
                report_time=self.clock(),
                subject_base=settings.ABUSE_EMAIL_SUBJECT,
                organization=settings.REPORT_ORGANIZATION,
                followup_hours=settings.FOLLOWUP_INTERVAL_HOURS,
                is_test=True,
            )
        except Exception as e:
            logger.error(f"Template rendering failed for the test report: {sanitize_error(e)}")
            return False

        sent = 0
        for index, email in enumerate(unique_preserving(abuse_emails or []), start=1):
            if not self.abuse_detector.validate_email(email):
                logger.warning(f"Invalid test recipient skipped: {email}")
                continue
            if not self.abuse_detector.validate_abuse_email_domain(email, host_of(site_url)):
                logger.warning(f"Test recipient {email} is on the reported domain; skipped")
                continue
            try:
                if not self._smtp_rate_limiter.acquire():
                    increment_counter(METRIC_SMTP_RATE_LIMITED)
                    logger.warning(f"SMTP rate limit reached; test report to {email} not sent")
                    continue
                message, _ = build_email(
                    rendered.to_payload(attachments),
                    sender=sender,
                    to_addrs=[email],
                    message_id=message_id_for(report_id, 0, index, sender),
                    max_attachment_bytes=_max_attachment_bytes(),
                    max_total_bytes=_max_email_bytes(),
                )
                self.mailer.send(message, [email])
                sent += 1
            except Exception as e:
                log_error(
                    logger,
                    e,
                    {
                        "recipient": email,
                        "url": site_url,
                        "operation": "send_test_report",
                        "event_type": "test_report_send_failed",
                    },
                )
        return sent > 0

    def send_test_report(self, test_email: str, attachment_paths: Optional[List[str]] = None):
        """Send a test abuse report to ``test_email`` (``--test-report``).

        Args:
            test_email: Recipient.
            attachment_paths: Files to attach; defaults to the configured ones.
        """
        logger.info("Sending test abuse report")
        if self.send_abuse_report(
            [test_email],
            "https://test.phishing-site.com",
            "This is a test WHOIS information for a test phishing site.",
            attachment_paths=attachment_paths,
            test_mode=True,
        ):
            logger.info("Test report sent.")
        else:
            logger.error("Failed to send test report.")

    # ------------------------------------------------------------------
    # Outbox delivery
    # ------------------------------------------------------------------

    def dispatch_outbox(
        self, report_id: Optional[str] = None, limit: Optional[int] = None
    ) -> DispatchResult:
        """Deliver due outbox e-mails, claimed by this worker.

        Args:
            report_id: Only deliver this report's rows.
            limit: Maximum rows to claim in this pass.

        Returns:
            Counters of the pass.
        """
        result = DispatchResult()
        if report_id is None:
            expired = self.outbox.expire_interrupted()
            if expired:
                logger.error(f"{expired} interrupted outbox row(s) had no attempts left: failed")
        rows = self.outbox.claim_batch(limit or settings.OUTBOX_DISPATCH_BATCH_SIZE, report_id)
        touched_reports = set()
        for row in rows:
            touched_reports.add(row.report_id)
            if is_shutdown_requested():
                self.outbox.release(row, 0, "shutdown before send")
                result.deferred += 1
                continue
            try:
                allowed = self._smtp_rate_limiter.acquire()
            except Exception as e:
                self.outbox.mark_failed(row, e, retryable=True)
                result.failed += 1
                continue
            if not allowed:
                increment_counter(METRIC_SMTP_RATE_LIMITED)
                self.outbox.release(
                    row,
                    settings.OUTBOX_RATE_LIMIT_DEFER_SECONDS,
                    f"SMTP rate limit reached ({settings.SMTP_RATE_LIMIT_PER_HOUR}/h)",
                )
                result.deferred += 1
                continue
            self._deliver(row, result)

        for touched in touched_reports:
            with short_transaction(self.engine) as conn:
                if self.report_tracker.mark_report_failed_if_undeliverable(conn, touched):
                    logger.error(f"Report {touched}: no primary e-mail could be delivered")
        return result

    def _deliver(self, row: OutboxRow, result: DispatchResult) -> None:
        """Send one claimed outbox row and record the outcome.

        Args:
            row: Claimed row (status ``sending``).
            result: Counters to update.
        """
        sender = settings.ABUSE_EMAIL_SENDER
        message_id = message_id_for(row.report_id, row.followup_seq, row.id, sender)
        recipients = row.envelope_recipients
        try:
            message, _ = build_email(
                row.payload,
                sender=sender,
                to_addrs=recipients,
                message_id=message_id,
                max_attachment_bytes=_max_attachment_bytes(),
                max_total_bytes=_max_email_bytes(),
            )
            refused = self.mailer.send(message, recipients)
        except Exception as e:
            status = self.outbox.mark_failed(row, e, retryable=_is_retryable(e))
            result.failed += 1
            log_with_context(
                logger,
                logging.ERROR if status == "failed" else logging.WARNING,
                "Abuse report delivery attempt failed",
                report_id=row.report_id,
                recipient=row.recipient,
                attempt=row.attempts,
                outcome=status,
                error=sanitize_error(e),
                event_type="abuse_report_send_failed",
            )
            return

        sent_at = self.clock()
        with short_transaction(self.engine) as conn:
            owned = self.outbox.mark_sent(
                row,
                message_id,
                conn,
                note=f"refused by server: {sorted(refused)}" if refused else None,
            )
            if owned and row.audience == OutboxAudience.PRIMARY.value and not row.followup_seq:
                self.report_tracker.mark_report_sent(conn, row.report_id, sent_at)
        if not owned:
            logger.warning(
                f"Outbox row {row.id} was sent after its lease expired; the newer claim "
                "owns the row"
            )
        result.sent += 1
        if row.audience == OutboxAudience.PRIMARY.value:
            result.sent_report_ids.append(row.report_id)
            increment_counter(METRIC_REPORTS_SENT_TOTAL)
        suffix = f" (+{len(row.cc)} CC)" if row.cc else ""
        if row.followup_seq:
            suffix += f" [follow-up {row.followup_seq}]"
        logger.info(f"Report {row.report_id} delivered to {row.recipient}{suffix}")

    def outbox_worker(self) -> None:
        """Scheduler loop: deliver due and retried outbox rows."""
        while not is_shutdown_requested():
            try:
                self.dispatch_outbox()
            except Exception as e:
                log_error(
                    logger, e, {"operation": "outbox_dispatch", "event_type": "outbox_failed"}
                )
            if wait_for_shutdown(settings.OUTBOX_DISPATCH_INTERVAL_SECONDS):
                break

    # ------------------------------------------------------------------
    # Follow-ups
    # ------------------------------------------------------------------

    def process_overdue_followups(self):
        """Process overdue reports and send follow-up emails every 2 days per ICANN compliance"""
        logger.info("🔄 Starting overdue follow-up processing...")

        try:
            # Get overdue reports from report tracker
            overdue_reports = self.report_tracker.get_overdue_reports()

            if not overdue_reports:
                logger.info("✅ No overdue reports found")
                return

            logger.info(f"📋 Found {len(overdue_reports)} overdue reports requiring follow-up")

            for report in overdue_reports:
                try:
                    site_url = report["site_url"]
                    report_id = report["report_id"]
                    overdue_hours = report.get("overdue_hours", 0)

                    logger.info(
                        f"⚠️  Processing overdue report: {report_id} for {site_url} ({overdue_hours}h overdue)"
                    )

                    # Double-check if site is still up before sending follow-up
                    domain = re.sub(r"^https?://", "", site_url).strip().split("/")[0]
                    resolved_ip, _ = get_ip_info(domain)
                    current_status, _ = PhishingUtils.determine_site_status(
                        site_url,
                        resolved_ip,
                        None,
                        None,
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        self.timeout,
                    )

                    # Update site status in database regardless of status
                    try:
                        with self.db_manager.engine.begin() as conn:
                            conn.execute(
                                text("""UPDATE phishing_sites
                                    SET site_status = :status,
                                        last_seen = CURRENT_TIMESTAMP,
                                        takedown_date = CASE
                                            WHEN :status = 'down' THEN CURRENT_TIMESTAMP
                                            ELSE takedown_date
                                        END
                                    WHERE url = :url"""),
                                {"status": current_status, "url": site_url},
                            )
                            logger.info(
                                f"✅ Updated site status to {current_status} for {site_url}"
                            )
                    except Exception as e:
                        logger.error(f"❌ Error updating site status: {e}")

                    # Skip follow-up if site is down
                    if current_status in ["down", "timeout", "resolved"]:
                        logger.info(
                            f"🎯 Site {site_url} is now {current_status}, skipping follow-up"
                        )
                        continue

                    # Get original recipients
                    recipients = json.loads(report["recipients"]) if report["recipients"] else []

                    if not recipients:
                        logger.warning(f"⚠️  No recipients found for {report_id}, skipping")
                        continue

                    # Prepare follow-up email subject with site URL
                    follow_up_subject = f"FOLLOW-UP: Phishing Report {report_id} for {site_url} - Response Required (ICANN Compliance)"

                    # Add escalation CCs for overdue reports
                    escalation_cc = self.cc_emails.copy() if self.cc_emails else []

                    # Always include sender email in CC for follow-ups
                    sender_email = getattr(settings, "ABUSE_EMAIL_SENDER")
                    if sender_email and sender_email not in escalation_cc:
                        escalation_cc.append(sender_email)

                    # Add escalation based on how overdue
                    if overdue_hours > 72:  # 3+ days overdue - Level 2 escalation
                        escalation_level2 = (
                            getattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL2")
                            if hasattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL2")
                            else None
                        )
                        if escalation_level2:
                            for email in escalation_level2.split(","):
                                email = email.strip()
                                if email and email not in escalation_cc:
                                    escalation_cc.append(email)

                    if overdue_hours > 96:  # 4+ days overdue - Level 3 escalation
                        escalation_level3 = (
                            getattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL3")
                            if hasattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL3")
                            else None
                        )
                        if escalation_level3:
                            for email in escalation_level3.split(","):
                                email = email.strip()
                                if email and email not in escalation_cc:
                                    escalation_cc.append(email)

                    # Create follow-up whois context
                    followup_context = f"""FOLLOW-UP NOTICE - ICANN COMPLIANCE

Original Report ID: {report_id}
Site: {site_url}
Original Report Date: {report.get('report_date', 'Unknown')}
Hours Overdue: {overdue_hours}

This is a follow-up to our previous phishing report. ICANN policies require registrars to respond to abuse reports within 2 business days. Please provide an update on the status of this case.

If the reported site has been taken down, please confirm. If not, please provide expected timeline for resolution.
"""

                    # Send follow-up (don't create new screenshot to save time)
                    logger.info(f"📤 Sending follow-up report for {site_url}...")

                    success = self._send_followup_email(
                        site_url=site_url,
                        recipients=recipients,
                        escalation_cc=escalation_cc,
                        subject=follow_up_subject,
                        followup_context=followup_context,
                        report_id=report_id,
                    )

                    if success:
                        # Mark as follow-up sent and update status
                        self.report_tracker.mark_report_for_followup(
                            report_id, reason=f"Follow-up sent after {overdue_hours}h overdue"
                        )
                        logger.info(f"✅ Follow-up sent successfully for {report_id}")
                    else:
                        logger.error(f"❌ Failed to send follow-up for {report_id}")

                except Exception as e:
                    logger.error(
                        f"❌ Error processing overdue report {report.get('report_id', 'unknown')}: {e}"
                    )
                    continue

            logger.info(f"🏁 Completed processing {len(overdue_reports)} overdue reports")

        except Exception as e:
            logger.error(f"❌ Error in overdue follow-up processing: {e}")

    def _send_followup_email(
        self,
        site_url: str,
        recipients: List[str],
        escalation_cc: List[str],
        subject: str,
        followup_context: str,
        report_id: str,
    ) -> bool:
        """Send a follow-up email for overdue reports"""
        try:
            # Use simplified email sending for follow-ups
            smtp_host = getattr(settings, "SMTP_HOST")
            smtp_port = getattr(settings, "SMTP_PORT")
            sender_email = getattr(settings, "ABUSE_EMAIL_SENDER")

            success_count = 0

            for recipient in recipients:
                try:
                    msg = MIMEMultipart()
                    msg["From"] = sender_email
                    msg["To"] = recipient
                    msg["Subject"] = subject

                    # Add CCs
                    if escalation_cc:
                        msg["Cc"] = ", ".join(escalation_cc)

                    # Simple text body for follow-up
                    body = f"""Dear Registrar Abuse Team,

{followup_context}

Please respond to this follow-up as required by ICANN policies.

Thank you for your cooperation.

Best regards,
Phishing Detection Team
"""

                    msg.attach(MIMEText(body, "plain"))

                    # Send email
                    if not self._smtp_rate_limiter.acquire():
                        logger.warning(
                            f"⏰ SMTP rate limit reached "
                            f"({settings.SMTP_RATE_LIMIT_PER_HOUR}/hr), skipping follow-up to {recipient}"
                        )
                        increment_counter(METRIC_SMTP_RATE_LIMITED)
                        continue

                    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
                        all_recipients = [recipient] + escalation_cc
                        server.send_message(msg, to_addrs=all_recipients)

                    logger.info(f"✅ Follow-up sent to {recipient}")
                    success_count += 1

                except Exception as e:
                    logger.error(f"❌ Failed to send follow-up to {recipient}: {e}")
                    continue

            return success_count > 0

        except Exception as e:
            logger.error(f"❌ Error in follow-up email sending: {e}")
            return False

    def followup_worker(self):
        """Background worker that checks for overdue reports every 48 hours"""
        logger.info("🚀 Starting follow-up worker for ICANN compliance (checks every 48 hours)...")

        # Check last follow-up time from database
        last_followup_time = self._get_last_followup_time()

        if last_followup_time:
            hours_since_last = (datetime.datetime.now() - last_followup_time).total_seconds() / 3600
            if hours_since_last < 48:
                wait_hours = 48 - hours_since_last
                logger.info(
                    f"⏰ Last follow-up was {hours_since_last:.1f} hours ago. Waiting {wait_hours:.1f} hours before first check."
                )
                # Wait until 48 hours have passed since last follow-up
                for _ in range(int(wait_hours * 60)):  # Convert hours to minutes
                    if not self.running or wait_for_shutdown(60):
                        return

        while self.running and not is_shutdown_requested():
            try:
                # Process overdue reports
                self.process_overdue_followups()
                # Save the time of this follow-up run
                self._save_followup_time()

                # Wait 48 hours before next check
                for _ in range(2880):  # 2880 minutes = 48 hours
                    if not self.running or wait_for_shutdown(60):
                        break

            except Exception as e:
                logger.error(f"❌ Error in follow-up worker: {e}")
                wait_for_shutdown(300)  # Wait 5 minutes before retrying on error

    def stop_followup_worker(self):
        """Stop the follow-up worker gracefully"""
        self.running = False
        logger.info("🛑 Follow-up worker stopped")

    def _get_last_followup_time(self) -> Optional[datetime.datetime]:
        """Get the last follow-up time from database"""
        try:
            with self.db_manager.engine.begin() as conn:
                result = conn.execute(
                    text("SELECT last_run FROM system_status WHERE task_name = 'followup_worker'")
                ).fetchone()

                if result and result[0]:
                    return result[0]
                return None
        except Exception as e:
            logger.debug(f"No previous follow-up time found: {e}")
            return None

    def _save_followup_time(self):
        """Save the current time as last follow-up time"""
        try:
            with self.db_manager.engine.begin() as conn:
                # Create table if not exists
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS system_status (
                        task_name VARCHAR(100) PRIMARY KEY,
                        last_run TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))

                # Upsert the follow-up time
                conn.execute(
                    text("""
                    INSERT INTO system_status (task_name, last_run, updated_at)
                    VALUES ('followup_worker', :last_run, :updated_at)
                    ON CONFLICT (task_name)
                    DO UPDATE SET last_run = :last_run, updated_at = :updated_at
                """),
                    {"last_run": datetime.datetime.now(), "updated_at": datetime.datetime.now()},
                )

                logger.debug("✅ Saved follow-up run time")
        except Exception as e:
            logger.error(f"❌ Failed to save follow-up time: {e}")
