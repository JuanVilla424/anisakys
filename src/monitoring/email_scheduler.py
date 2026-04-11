"""
Background scheduler for email threat monitoring threads.

Runs independently from ImageTrackingScheduler to avoid coupling Gmail API
with SerpApi operations, and to allow a shorter poll interval (default 15 min).

Supports two modes per thread:

  Single-mailbox mode (legacy):
    thread_type = 'email_monitor'
    details JSONB: {
      "target_mailbox": "abuse@domain.com",
      "last_history_id": "12345",
      "last_poll_timestamp": "1712700000",
      "exclude_domains": ["trusted.com"]
    }

  Domain-wide mode (enumerates all users via Directory API):
    thread_type = 'email_monitor'
    details JSONB: {
      "domain": "company.com",
      "admin_email": "admin@company.com",   (optional — falls back to scheduler config)
      "exclude_domains": ["trusted.com"],
      "exclude_users": ["sa@company.com"],
      "last_history_ids": {"user@company.com": "12345", ...}
    }
"""

import hashlib
import json
import threading
import time
from typing import Optional

from sqlalchemy import text

from src.database.manager import db_engine
from src.intelligence.email_analyzer import EmailAnalyzer
from src.intelligence.email_reputation import SenderReputationTracker
from src.intelligence.gmail_client import GmailClient
from src.logger import logger

STALE_EXECUTION_MINUTES = 40
MIN_THREAT_SCORE_FOR_URL_SCAN = 30
GSUITE_SYSTEM_DOMAINS = {"google.com", "googlemail.com"}


class EmailMonitorScheduler:
    def __init__(
        self,
        service_account_file: str,
        domain: str,
        block_threshold: int = 5,
        vt_api_key: Optional[str] = None,
        poll_interval_minutes: int = 15,
        admin_email: Optional[str] = None,
    ):
        self._running = False
        self._thread = None
        self.check_interval = poll_interval_minutes * 60
        self.admin_email = admin_email

        self.gmail_client = GmailClient(service_account_file, domain)
        self.email_analyzer = EmailAnalyzer()
        self.reputation_tracker = SenderReputationTracker(block_threshold=block_threshold)

        self.vt_client = None
        if vt_api_key:
            from src.intelligence.virustotal import VirusTotalIntegration

            self.vt_client = VirusTotalIntegration(api_key=vt_api_key)

        self.url_analyzer = None
        try:
            from src.detection.url_analyzer import url_analyzer

            self.url_analyzer = url_analyzer
        except Exception as exc:
            logger.warning(f"email_scheduler: url_analyzer not available — {exc}")

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("Email threat monitoring scheduler started")

    def stop(self):
        self._running = False
        logger.info("Email threat monitoring scheduler stopped")

    def _run(self):
        while self._running:
            try:
                self._process_due_threads()
            except Exception as exc:
                logger.error(f"email_scheduler error: {exc}")
            time.sleep(self.check_interval)

    def _cleanup_stale_executions(self, conn):
        result = conn.execute(
            text(
                "UPDATE thread_executions SET status='failed', "
                "error_message='Stale execution (40+ min)', completed_at=NOW() "
                "WHERE status='running' "
                "AND execution_type='email_scan' "
                "AND started_at < NOW() - make_interval(mins => :minutes)"
            ),
            {"minutes": STALE_EXECUTION_MINUTES},
        )
        if result.rowcount > 0:
            logger.warning(f"email_scheduler: cleaned up {result.rowcount} stale execution(s)")

    def _process_due_threads(self):
        # Phase 1: quick transaction — cleanup stale + fetch due threads
        with db_engine.begin() as conn:
            self._cleanup_stale_executions(conn)
            rows = conn.execute(
                text(
                    """
                    SELECT id, details FROM analysis_threads
                    WHERE thread_type = 'email_monitor'
                      AND status = 'active'
                      AND search_interval_hours IS NOT NULL
                      AND (
                          last_searched_at IS NULL
                          OR last_searched_at < NOW() - (search_interval_hours || ' hours')::INTERVAL
                      )
                    """
                )
            ).fetchall()

        # Phase 2: each thread runs its own transactions — data visible in real-time
        for row in rows:
            self._run_email_monitor(row.id, row.details)

    # ── Public entry point (called by scheduler loop and manual trigger) ─────

    def _run_email_monitor(self, thread_id: int, details):
        """Dispatch to domain-wide or single-mailbox mode based on details."""
        try:
            if isinstance(details, str):
                details = json.loads(details)
            elif details is None:
                details = {}

            if details.get("domain"):
                self._run_domain_wide(thread_id, details)
            elif details.get("target_mailbox"):
                self._run_single_mailbox(thread_id, details)
            else:
                raise ValueError(
                    "email_monitor thread missing both 'domain' and 'target_mailbox' in details"
                )
        except Exception as exc:
            logger.error(f"email_scheduler: failed thread {thread_id}: {exc}")

    # ── Domain-wide mode ─────────────────────────────────────────────────────

    def _run_domain_wide(self, thread_id: int, details: dict):
        """Enumerate all domain users via Directory API and scan each inbox.

        Uses per-user transactions so data is visible in real-time on the dashboard.
        Each user's results commit immediately — no single long-running transaction.
        """
        execution_id = None
        domain = details.get("domain", "")
        try:
            admin_email = details.get("admin_email") or self.admin_email
            if not admin_email:
                raise ValueError(
                    "Domain-wide scan requires admin_email in thread details or GOOGLE_ADMIN_EMAIL config"
                )

            exclude_domains = set(d.lower() for d in (details.get("exclude_domains") or []))
            exclude_users = set(u.lower() for u in (details.get("exclude_users") or []))
            last_history_ids = dict(details.get("last_history_ids") or {})

            # Commit #1 — create execution record, visible immediately on dashboard
            with db_engine.begin() as conn:
                exec_result = conn.execute(
                    text(
                        "INSERT INTO thread_executions (thread_id, execution_type, status) "
                        "VALUES (:tid, 'email_scan', 'running') RETURNING id"
                    ),
                    {"tid": thread_id},
                )
                execution_id = exec_result.scalar()

            # Enumerate users (cached 1h in gmail_client module)
            users = self.gmail_client.list_domain_users(domain, admin_email)
            total_users = len(users)
            total_new = 0
            users_scanned = 0

            for user_email in users:
                if user_email in exclude_users:
                    continue
                try:
                    history_id = last_history_ids.get(user_email)
                    after_ts = None
                    if not history_id:
                        # New user: limit first poll to last 24h to avoid full-inbox scan
                        after_ts = str(int(time.time()) - 86400)

                    message_ids, new_history_id = self.gmail_client.list_new_messages(
                        user_email,
                        history_id=history_id,
                        after_timestamp=after_ts,
                    )
                    last_history_ids[user_email] = new_history_id
                    user_new = 0
                    users_scanned += 1

                    # Commit #2..N — one transaction per user, results visible immediately
                    with db_engine.begin() as conn:
                        for msg_id in message_ids:
                            try:
                                user_new += self._process_message(
                                    conn,
                                    thread_id,
                                    execution_id,
                                    user_email,
                                    msg_id,
                                    exclude_domains,
                                )
                            except Exception as exc:
                                logger.error(
                                    f"email_scheduler: failed msg {msg_id} for "
                                    f"{user_email} in thread {thread_id}: {exc}"
                                )

                        # Update details + progress incrementally (visible on dashboard)
                        updated_details = {
                            **details,
                            "last_history_ids": last_history_ids,
                            "scan_progress": {
                                "current_user": user_email,
                                "users_scanned": users_scanned,
                                "users_total": total_users,
                                "messages_checked": len(message_ids),
                            },
                        }
                        conn.execute(
                            text(
                                "UPDATE analysis_threads "
                                "SET results_count = (SELECT COUNT(*) FROM thread_results WHERE thread_id = :tid), "
                                "    details = CAST(:det AS JSONB) "
                                "WHERE id = :tid"
                            ),
                            {"tid": thread_id, "det": json.dumps(updated_details)},
                        )

                    total_new += user_new

                except Exception as exc:
                    logger.error(
                        f"email_scheduler: failed scanning {user_email} "
                        f"in thread {thread_id}: {exc}"
                    )
                    # Continue with next user — don't abort the domain scan

            # Final commit — mark scan complete with timestamp
            with db_engine.begin() as conn:
                final_details = {**details, "last_history_ids": last_history_ids}
                conn.execute(
                    text(
                        "UPDATE analysis_threads "
                        "SET last_searched_at = NOW(), "
                        "    results_count = (SELECT COUNT(*) FROM thread_results WHERE thread_id = :tid), "
                        "    details = CAST(:det AS JSONB) "
                        "WHERE id = :tid"
                    ),
                    {"tid": thread_id, "det": json.dumps(final_details)},
                )
                conn.execute(
                    text(
                        "UPDATE thread_executions SET status='completed', completed_at=NOW(), "
                        "results_count=:count WHERE id=:eid"
                    ),
                    {"count": total_new, "eid": execution_id},
                )
            logger.info(
                f"email_monitor thread {thread_id}: domain-wide scan of {domain} — "
                f"{total_new} new threats from {len(users)} users (execution {execution_id})"
            )

        except Exception as exc:
            if execution_id is not None:
                try:
                    with db_engine.begin() as conn:
                        conn.execute(
                            text(
                                "UPDATE thread_executions SET status='failed', completed_at=NOW(), "
                                "error_message=:err WHERE id=:eid"
                            ),
                            {"err": str(exc), "eid": execution_id},
                        )
                except Exception:
                    pass
            logger.error(f"email_scheduler: failed domain-wide thread {thread_id}: {exc}")

    # ── Single-mailbox mode (legacy, backward-compatible) ────────────────────

    def _run_single_mailbox(self, thread_id: int, details: dict):
        """Scan a single configured mailbox (original behavior)."""
        execution_id = None
        try:
            target_mailbox = details.get("target_mailbox", "")
            if not target_mailbox:
                raise ValueError("email_monitor thread missing target_mailbox in details")

            history_id = details.get("last_history_id")
            last_poll_ts = details.get("last_poll_timestamp")
            exclude_domains = set(d.lower() for d in (details.get("exclude_domains") or []))

            with db_engine.begin() as conn:
                exec_result = conn.execute(
                    text(
                        "INSERT INTO thread_executions (thread_id, execution_type, status) "
                        "VALUES (:tid, 'email_scan', 'running') RETURNING id"
                    ),
                    {"tid": thread_id},
                )
                execution_id = exec_result.scalar()

            message_ids, new_history_id = self.gmail_client.list_new_messages(
                target_mailbox,
                history_id=history_id,
                after_timestamp=last_poll_ts,
            )

            new_count = 0
            with db_engine.begin() as conn:
                for msg_id in message_ids:
                    try:
                        new_count += self._process_message(
                            conn,
                            thread_id,
                            execution_id,
                            target_mailbox,
                            msg_id,
                            exclude_domains,
                        )
                    except Exception as exc:
                        logger.error(
                            f"email_scheduler: failed to process message {msg_id} "
                            f"in thread {thread_id}: {exc}"
                        )

                updated_details = {**details, "last_history_id": new_history_id}
                conn.execute(
                    text(
                        "UPDATE analysis_threads "
                        "SET last_searched_at = NOW(), "
                        "    results_count = (SELECT COUNT(*) FROM thread_results WHERE thread_id = :tid), "
                        "    details = CAST(:det AS JSONB) "
                        "WHERE id = :tid"
                    ),
                    {"tid": thread_id, "det": json.dumps(updated_details)},
                )
                conn.execute(
                    text(
                        "UPDATE thread_executions SET status='completed', completed_at=NOW(), "
                        "results_count=:count WHERE id=:eid"
                    ),
                    {"count": new_count, "eid": execution_id},
                )
            logger.info(
                f"email_monitor thread {thread_id}: {new_count} new threats from "
                f"{len(message_ids)} messages (execution {execution_id})"
            )

        except Exception as exc:
            if execution_id is not None:
                try:
                    with db_engine.begin() as conn:
                        conn.execute(
                            text(
                                "UPDATE thread_executions SET status='failed', completed_at=NOW(), "
                                "error_message=:err WHERE id=:eid"
                            ),
                            {"err": str(exc), "eid": execution_id},
                        )
                except Exception:
                    pass
            logger.error(f"email_scheduler: failed thread {thread_id}: {exc}")

    # ── Per-message processing (shared by both modes) ────────────────────────

    def _process_message(
        self,
        conn,
        thread_id: int,
        execution_id: int,
        mailbox: str,
        message_id: str,
        exclude_domains: set,
    ) -> int:
        """
        Analyze a single email and store result. Returns 1 if a new result was inserted, 0 otherwise.
        Deduplicates by message_id in extra_data.
        """
        existing = conn.execute(
            text(
                "SELECT id FROM thread_results "
                "WHERE thread_id = :tid AND extra_data->>'message_id' = :mid"
            ),
            {"tid": thread_id, "mid": message_id},
        ).fetchone()
        if existing:
            return 0

        parsed = self.gmail_client.get_message(mailbox, message_id)
        if not parsed:
            return 0

        sender_email = parsed.get("from_email", "")
        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

        if (
            sender_domain in exclude_domains
            or sender_domain == self.gmail_client.domain
            or sender_domain in GSUITE_SYSTEM_DOMAINS
        ):
            return 0

        if self.reputation_tracker.is_whitelisted(conn, sender_email):
            return 0

        assessment = self.email_analyzer.analyze(parsed)
        threat_score = assessment["threat_score"]

        url_results = []
        if threat_score >= MIN_THREAT_SCORE_FOR_URL_SCAN and self.url_analyzer:
            for url in assessment.get("urls_extracted", [])[:10]:
                try:
                    r = self.url_analyzer.analyze(url)
                    url_results.append({"url": url, "risk_score": r.get("risk_score", 0)})
                except Exception:
                    pass

        attachment_results = []
        for att in parsed.get("attachments", []):
            if not att.get("attachment_id"):
                continue
            if not att.get("filename", "").endswith(
                tuple([".exe", ".js", ".vbs", ".bat", ".ps1", ".jar", ".scr", ".lnk"])
            ):
                continue
            data = self.gmail_client.get_attachment_data(mailbox, message_id, att["attachment_id"])
            if data:
                file_hash = hashlib.sha256(data).hexdigest()
                vt_result = self.vt_client.lookup_file_hash(file_hash) if self.vt_client else {}
                attachment_results.append(
                    {
                        "filename": att["filename"],
                        "hash_sha256": file_hash,
                        "vt": vt_result,
                        "flagged": vt_result.get("found")
                        and vt_result.get("threat_level") in ("high", "medium"),
                    }
                )
                if vt_result.get("threat_level") == "high":
                    threat_score = min(threat_score + 20, 100)
                    assessment["risk_factors"].append("vt_file_high")
                elif vt_result.get("threat_level") == "medium":
                    threat_score = min(threat_score + 10, 100)
                    assessment["risk_factors"].append("vt_file_medium")

        extra_data = {
            "message_id": message_id,
            "inbox": mailbox,
            "sender": sender_email,
            "sender_domain": sender_domain,
            "display_name": parsed.get("from_name", ""),
            "subject": parsed.get("subject", ""),
            "threat_score": threat_score,
            "risk_factors": assessment["risk_factors"],
            "auth_results": assessment["auth_results"],
            "reply_to": parsed.get("reply_to") or "",
            "urgency_keywords": assessment["content_analysis"].get("urgency_keywords_matched", []),
            "urls_found": assessment["content_analysis"].get("total_urls", 0),
            "urls_suspicious": len([u for u in url_results if u.get("risk_score", 0) >= 40]),
            "url_analysis": url_results,
            "attachments": attachment_results,
            "all_attachments": [
                {"filename": a.get("filename", ""), "mime_type": a.get("mime_type", "")}
                for a in parsed.get("attachments", [])
            ],
            "received_at": parsed.get("date", ""),
        }

        if threat_score >= 20:
            conn.execute(
                text(
                    "INSERT INTO thread_results "
                    "(thread_id, result_type, found_url, title, source, "
                    "execution_id, extra_data, source_type, status) "
                    "VALUES (:tid, 'email_threat', :url, :title, :source, "
                    ":eid, CAST(:extra AS JSONB), 'automated_scan', 'threat')"
                ),
                {
                    "tid": thread_id,
                    "url": f"mailto:{sender_email}",
                    "title": parsed.get("subject", ""),
                    "source": sender_domain,
                    "eid": execution_id,
                    "extra": json.dumps(extra_data),
                },
            )

            rep = self.reputation_tracker.update(
                conn,
                sender_email=sender_email,
                sender_domain=sender_domain,
                display_name=parsed.get("from_name", ""),
                threat_score=threat_score,
                source_type="automated_scan",
            )

            if rep.get("should_block"):
                self.reputation_tracker.mark_blocked(
                    conn,
                    sender_email,
                    reason=f"Auto-block: effective_score={rep['effective_score']} "
                    f"(threshold={self.reputation_tracker.block_threshold})",
                )

            return 1

        return 0
