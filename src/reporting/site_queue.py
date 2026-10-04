"""Claim phishing sites for reporting, one worker per site.

The reporting loop used to read every reportable site and do WHOIS, DNS,
screenshots and SMTP for all of them inside one long transaction, so two
processes running the loop reported the same site twice, and one SQL error
rolled back every ``abuse_report_sent`` mark and caused re-sends.

Now a worker claims a small batch with ``SELECT ... FOR UPDATE SKIP LOCKED``
and stamps a lease (``report_lease_until``/``report_claimed_by``) in a short
transaction that commits immediately. The slow network work happens outside
any transaction; the outcome is written in another short transaction that
only succeeds while the worker still owns the lease. A worker that crashes
leaves a lease that simply expires.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from src.config import settings
from src.reporting.db import short_transaction
from src.reporting.outbox import default_worker_id, sanitize_error

_CLAIM_COLUMNS = """
    ps.id, ps.url, ps.abuse_email, ps.all_abuse_emails,
    COALESCE(ps.manual_emails, 0) AS manual_emails,
    COALESCE(ps.manual_flag, 0) AS manual_flag,
    COALESCE(ps.auto_detected, 0) AS auto_detected,
    COALESCE(ps.auto_report_eligible, 0) AS auto_report_eligible,
    ps.priority, ps.site_status, ps.takedown_date, ps.source,
    CAST(ps.first_seen AS timestamptz) AS first_seen,
    ps.virustotal_result, ps.urlvoid_result, ps.phishtank_result,
    ps.multi_api_threat_level, ps.api_confidence_score, ps.detection_keywords,
    COALESCE(ps.report_attempts, 0) AS report_attempts
"""

_PRIORITY_ORDER = (
    "CASE ps_inner.priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 " "WHEN 'low' THEN 3 ELSE 2 END"
)


def _load_json(value: Any) -> Dict[str, Any]:
    """Decode a JSON text column, tolerating bad or empty values.

    Args:
        value: Stored value.

    Returns:
        The decoded dict (empty on failure).
    """
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


@dataclass
class ClaimedSite:
    """A phishing site this worker currently holds the reporting lease for."""

    id: int
    url: str
    abuse_email: Optional[str]
    all_abuse_emails: Optional[str]
    manual_emails: bool
    manual_flag: bool
    auto_detected: bool
    auto_report_eligible: bool
    priority: Optional[str]
    site_status: Optional[str]
    takedown_date: Any
    source: Optional[str]
    first_seen: Optional[datetime]
    multi_api_results: Optional[Dict[str, Any]]
    detection_keywords: Optional[str]
    report_attempts: int

    @classmethod
    def from_mapping(cls, row: Any) -> "ClaimedSite":
        """Build from a row returned by a claim query.

        Args:
            row: Row mapping with the claim columns.

        Returns:
            The claimed site.
        """
        results = None
        virustotal = _load_json(row["virustotal_result"])
        if virustotal or row["multi_api_threat_level"]:
            results = {
                "aggregated_threat_level": row["multi_api_threat_level"] or "unknown",
                "confidence_score": row["api_confidence_score"] or 0,
                "virustotal": virustotal,
                "urlvoid": _load_json(row["urlvoid_result"]),
                "phishtank": _load_json(row["phishtank_result"]),
                "recommendations": [],
            }
        return cls(
            id=int(row["id"]),
            url=row["url"],
            abuse_email=row["abuse_email"],
            all_abuse_emails=row["all_abuse_emails"],
            manual_emails=bool(row["manual_emails"]),
            manual_flag=bool(row["manual_flag"]),
            auto_detected=bool(row["auto_detected"]),
            auto_report_eligible=bool(row["auto_report_eligible"]),
            priority=row["priority"],
            site_status=row["site_status"],
            takedown_date=row["takedown_date"],
            source=row["source"],
            first_seen=row["first_seen"],
            multi_api_results=results,
            detection_keywords=row["detection_keywords"],
            report_attempts=int(row["report_attempts"]),
        )


class SiteQueue:
    """Lease-based claiming of ``phishing_sites`` rows for the reporting loop."""

    def __init__(
        self,
        engine: Engine,
        worker_id: Optional[str] = None,
        lease_seconds: Optional[int] = None,
        max_attempts: Optional[int] = None,
        cooldown_hours: Optional[int] = None,
    ) -> None:
        """Create a queue view over ``phishing_sites``.

        Args:
            engine: Database engine.
            worker_id: Owner written to ``report_claimed_by``.
            lease_seconds: How long a claim protects a site.
            max_attempts: Failed reporting attempts before a site is left for
                an analyst.
            cooldown_hours: Minimum time between two reports of one site.
        """
        self.engine = engine
        self.worker_id = worker_id or default_worker_id()
        self.lease_seconds = lease_seconds or settings.REPORT_CLAIM_LEASE_SECONDS
        self.max_attempts = max_attempts or settings.REPORT_SITE_MAX_ATTEMPTS
        self.cooldown_hours = (
            settings.REPORT_RESEND_COOLDOWN_HOURS if cooldown_hours is None else cooldown_hours
        )

    def claim_batch(
        self, limit: int, manual_only: bool = False, conn: Optional[Connection] = None
    ) -> List[ClaimedSite]:
        """Claim up to ``limit`` reportable sites, skipping rows others hold.

        Args:
            limit: Batch size.
            manual_only: Only analyst-flagged sites not yet processed
                (``--process-reports``); otherwise flagged or auto-eligible.
            conn: Run inside this open transaction instead of a new one (the
                caller commits); used to observe ``SKIP LOCKED`` in tests.

        Returns:
            The claimed sites, highest priority first.
        """
        eligibility = (
            "ps_inner.manual_flag = 1 AND COALESCE(ps_inner.reported, 0) = 0"
            if manual_only
            else "(ps_inner.manual_flag = 1 OR ps_inner.auto_report_eligible = 1)"
        )
        statement = text(f"""
            WITH picked AS (
                SELECT ps_inner.id FROM phishing_sites AS ps_inner
                WHERE {eligibility}
                  AND ps_inner.site_status = 'up'
                  AND COALESCE(ps_inner.abuse_report_sent, 0) = 0
                  AND (ps_inner.last_report_sent IS NULL
                       OR ps_inner.last_report_sent
                          < now() - make_interval(hours => :cooldown))
                  AND (ps_inner.report_lease_until IS NULL
                       OR ps_inner.report_lease_until < now())
                  AND COALESCE(ps_inner.report_attempts, 0) < :max_attempts
                ORDER BY {_PRIORITY_ORDER}, ps_inner.first_seen ASC NULLS LAST, ps_inner.id
                LIMIT :limit
                FOR UPDATE SKIP LOCKED
            )
            UPDATE phishing_sites AS ps
            SET report_lease_until = now() + make_interval(secs => :lease),
                report_claimed_by = :worker
            FROM picked
            WHERE ps.id = picked.id
            RETURNING {_CLAIM_COLUMNS}
            """)
        params = {
            "cooldown": self.cooldown_hours,
            "max_attempts": self.max_attempts,
            "limit": limit,
            "lease": self.lease_seconds,
            "worker": self.worker_id,
        }
        if conn is not None:
            rows = conn.execute(statement, params).mappings().all()
        else:
            with short_transaction(self.engine) as own:
                rows = own.execute(statement, params).mappings().all()
        sites = [ClaimedSite.from_mapping(row) for row in rows]
        priority = {"high": 1, "medium": 2, "low": 3}
        return sorted(sites, key=lambda s: (priority.get(s.priority or "", 2), s.id))

    def claim_url(self, url: str) -> Tuple[bool, Optional[ClaimedSite]]:
        """Claim one specific site for an explicit report.

        Args:
            url: Site URL.

        Returns:
            ``(tracked, claim)``: ``tracked`` is whether a ``phishing_sites``
            row exists; ``claim`` is ``None`` when it does not exist, when
            another worker holds it, or when it was reported within the
            cooldown.
        """
        with short_transaction(self.engine) as conn:
            row = (
                conn.execute(
                    text(f"""
                        UPDATE phishing_sites AS ps
                        SET report_lease_until = now() + make_interval(secs => :lease),
                            report_claimed_by = :worker
                        WHERE ps.id = (
                            SELECT id FROM phishing_sites
                            WHERE url = :url
                              AND (report_lease_until IS NULL OR report_lease_until < now())
                              AND (last_report_sent IS NULL
                                   OR last_report_sent
                                      < now() - make_interval(hours => :cooldown))
                            ORDER BY id
                            LIMIT 1
                            FOR UPDATE SKIP LOCKED
                        )
                        RETURNING {_CLAIM_COLUMNS}
                        """),
                    {
                        "lease": self.lease_seconds,
                        "worker": self.worker_id,
                        "url": url,
                        "cooldown": self.cooldown_hours,
                    },
                )
                .mappings()
                .first()
            )
            if row is not None:
                return True, ClaimedSite.from_mapping(row)
            tracked = conn.execute(
                text("SELECT 1 FROM phishing_sites WHERE url = :url LIMIT 1"), {"url": url}
            ).first()
            return tracked is not None, None

    def complete(self, conn: Connection, site_id: int, updates: Dict[str, Any]) -> bool:
        """Record a finished report on the site and drop the lease.

        Runs inside the caller's transaction (the one that also writes the
        report and its outbox rows) and only while this worker owns the lease.

        Args:
            conn: Connection inside an open transaction.
            site_id: Claimed site id.
            updates: Enrichment values (``whois_info``, ``resolved_ip``,
                ``asn_provider``, ``is_cloudflare``, ``abuse_email``). Liveness
                columns (``site_status``, ``takedown_date``, ``last_seen``) are
                never written here: the takedown monitor owns them.

        Returns:
            ``False`` when the lease was lost (nothing was written).
        """
        result = conn.execute(
            text("""
                UPDATE phishing_sites
                SET whois_info = COALESCE(:whois_info, whois_info),
                    resolved_ip = COALESCE(:resolved_ip, resolved_ip),
                    asn_provider = COALESCE(:asn_provider, asn_provider),
                    is_cloudflare = COALESCE(:is_cloudflare, is_cloudflare),
                    abuse_email = CASE WHEN COALESCE(manual_emails, 0) = 1 THEN abuse_email
                                       ELSE COALESCE(:abuse_email, abuse_email) END,
                    last_report_sent = now(),
                    reported = 1, abuse_report_sent = 1,
                    report_lease_until = NULL, report_claimed_by = NULL,
                    report_last_error = NULL
                WHERE id = :id AND report_claimed_by = :worker
                """),
            {
                "whois_info": updates.get("whois_info"),
                "resolved_ip": updates.get("resolved_ip"),
                "asn_provider": updates.get("asn_provider"),
                "is_cloudflare": updates.get("is_cloudflare"),
                "abuse_email": updates.get("abuse_email"),
                "id": site_id,
                "worker": self.worker_id,
            },
        )
        return bool(result.rowcount)

    def release(
        self, site_id: int, error: Any = None, backoff_seconds: Optional[int] = None
    ) -> None:
        """Give a claimed site back without reporting it.

        With ``error`` the attempt counts as failed: ``report_attempts`` is
        incremented, the sanitised error is stored and the site is not claimed
        again before the backoff. Without it the lease is simply dropped.

        Args:
            site_id: Claimed site id.
            error: Why reporting failed, if it did.
            backoff_seconds: Delay before the site can be claimed again after
                an error; defaults to ``OUTBOX_RETRY_BACKOFF_SECONDS``.
        """
        backoff = backoff_seconds or settings.OUTBOX_RETRY_BACKOFF_SECONDS
        with short_transaction(self.engine) as conn:
            conn.execute(
                text("""
                    UPDATE phishing_sites
                    SET report_claimed_by = NULL,
                        report_lease_until = CASE WHEN :failed
                            THEN now() + make_interval(secs => :backoff) ELSE NULL END,
                        report_attempts = COALESCE(report_attempts, 0)
                            + CASE WHEN :failed THEN 1 ELSE 0 END,
                        report_last_error = CASE WHEN :failed THEN :error
                            ELSE report_last_error END
                    WHERE id = :id AND report_claimed_by = :worker
                    """),
                {
                    "failed": error is not None,
                    "backoff": backoff,
                    "error": sanitize_error(error) if error is not None else None,
                    "id": site_id,
                    "worker": self.worker_id,
                },
            )

    def defer(self, site_id: int, reason: str, delay_seconds: Optional[int] = None) -> None:
        """Postpone a claimed site without counting a failed attempt.

        Used when a report cannot be built yet (e.g. the host does not resolve
        right now). The site's liveness is not touched: only the takedown
        monitor decides that a site is down.

        Args:
            site_id: Claimed site id.
            reason: Why the report was deferred (stored in ``report_last_error``).
            delay_seconds: How long before the site can be claimed again;
                defaults to ``REPORT_INTERVAL``.
        """
        delay = delay_seconds or settings.REPORT_INTERVAL
        with short_transaction(self.engine) as conn:
            conn.execute(
                text("""
                    UPDATE phishing_sites
                    SET report_claimed_by = NULL,
                        report_lease_until = now() + make_interval(secs => :delay),
                        report_last_error = :reason
                    WHERE id = :id AND report_claimed_by = :worker
                    """),
                {
                    "delay": delay,
                    "reason": sanitize_error(reason),
                    "id": site_id,
                    "worker": self.worker_id,
                },
            )
