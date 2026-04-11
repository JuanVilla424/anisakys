"""
Email sender and domain reputation tracker.

Tracks per-sender and per-domain reputation scores using weighted signals:
  - user_report (Flujo A — explicit human report)  weight: 3
  - automated_scan (Flujo B — automated heuristic)  weight: 1

Auto-block threshold is evaluated on the weighted effective_score:
  effective_score = (report_count * 3) + (automated_count * 1)
  block when effective_score >= block_threshold
"""

from sqlalchemy import text

from src.logger import logger


class SenderReputationTracker:
    def __init__(self, block_threshold: int = 5):
        self.block_threshold = block_threshold

    def update(
        self,
        conn,
        sender_email: str,
        sender_domain: str,
        display_name: str,
        threat_score: float,
        source_type: str = "automated_scan",
    ) -> dict:
        """
        UPSERT sender reputation. Returns current state including should_block flag.

        Args:
            source_type: 'user_report' (weight 3) or 'automated_scan' (weight 1).
        """
        is_user_report = source_type == "user_report"

        # Upsert sender
        conn.execute(
            text(
                """
                INSERT INTO email_sender_reputation
                    (sender_email, sender_domain, display_name,
                     report_count, automated_count,
                     threat_score_avg, threat_score_max, last_seen_at)
                VALUES
                    (:email, :domain, :dname,
                     :rc, :ac,
                     :score, :score, NOW())
                ON CONFLICT (sender_email) DO UPDATE SET
                    report_count    = email_sender_reputation.report_count
                                    + EXCLUDED.report_count,
                    automated_count = email_sender_reputation.automated_count
                                    + EXCLUDED.automated_count,
                    threat_score_avg = (
                        email_sender_reputation.threat_score_avg
                        * (email_sender_reputation.report_count + email_sender_reputation.automated_count)
                        + EXCLUDED.threat_score_avg
                    ) / (
                        email_sender_reputation.report_count + email_sender_reputation.automated_count + 1
                    ),
                    threat_score_max = GREATEST(
                        email_sender_reputation.threat_score_max, EXCLUDED.threat_score_max
                    ),
                    display_name    = COALESCE(EXCLUDED.display_name, email_sender_reputation.display_name),
                    last_seen_at    = NOW()
                """
            ),
            {
                "email": sender_email.lower(),
                "domain": sender_domain.lower(),
                "dname": display_name or None,
                "rc": 1 if is_user_report else 0,
                "ac": 0 if is_user_report else 1,
                "score": float(threat_score),
            },
        )

        # Upsert domain
        conn.execute(
            text(
                """
                INSERT INTO email_domain_reputation
                    (domain, sender_count, report_count, automated_count,
                     threat_score_avg, last_seen_at)
                VALUES
                    (:domain, 1, :rc, :ac, :score, NOW())
                ON CONFLICT (domain) DO UPDATE SET
                    report_count    = email_domain_reputation.report_count
                                    + EXCLUDED.report_count,
                    automated_count = email_domain_reputation.automated_count
                                    + EXCLUDED.automated_count,
                    threat_score_avg = (
                        email_domain_reputation.threat_score_avg
                        * (email_domain_reputation.report_count + email_domain_reputation.automated_count)
                        + EXCLUDED.threat_score_avg
                    ) / (
                        email_domain_reputation.report_count + email_domain_reputation.automated_count + 1
                    ),
                    last_seen_at    = NOW()
                """
            ),
            {
                "domain": sender_domain.lower(),
                "rc": 1 if is_user_report else 0,
                "ac": 0 if is_user_report else 1,
                "score": float(threat_score),
            },
        )

        row = conn.execute(
            text(
                "SELECT report_count, automated_count, threat_score_avg, threat_score_max, blocked "
                "FROM email_sender_reputation WHERE sender_email = :email"
            ),
            {"email": sender_email.lower()},
        ).fetchone()

        if row:
            effective_score = row.report_count * 3 + row.automated_count
            return {
                "report_count": row.report_count,
                "automated_count": row.automated_count,
                "effective_score": effective_score,
                "threat_score_avg": float(row.threat_score_avg),
                "threat_score_max": float(row.threat_score_max),
                "blocked": bool(row.blocked),
                "should_block": not bool(row.blocked) and effective_score >= self.block_threshold,
            }
        return {"should_block": False}

    def check_block(self, conn, sender_email: str) -> bool:
        """Return True if sender's weighted effective_score has reached the threshold."""
        row = conn.execute(
            text(
                "SELECT report_count, automated_count, blocked "
                "FROM email_sender_reputation WHERE sender_email = :email"
            ),
            {"email": sender_email.lower()},
        ).fetchone()
        if not row or row.blocked:
            return False
        return (row.report_count * 3 + row.automated_count) >= self.block_threshold

    def mark_blocked(self, conn, sender_email: str, reason: str):
        """Mark sender as blocked in DB (admin reviews and blocks in Google Workspace)."""
        conn.execute(
            text(
                "UPDATE email_sender_reputation "
                "SET blocked = TRUE, blocked_at = NOW(), block_reason = :reason "
                "WHERE sender_email = :email"
            ),
            {"email": sender_email.lower(), "reason": reason},
        )
        logger.info(f"email_reputation: sender {sender_email} marked as blocked — {reason}")

    def mark_unblocked(self, conn, sender_email: str):
        """Remove block flag from sender."""
        conn.execute(
            text(
                "UPDATE email_sender_reputation "
                "SET blocked = FALSE, blocked_at = NULL, block_reason = NULL "
                "WHERE sender_email = :email"
            ),
            {"email": sender_email.lower()},
        )
        logger.info(f"email_reputation: sender {sender_email} unblocked")

    def mark_whitelisted(self, conn, sender_email: str, reason: str):
        """Mark sender as whitelisted (trusted). Also clears any existing block."""
        conn.execute(
            text(
                "UPDATE email_sender_reputation "
                "SET whitelisted = TRUE, whitelisted_at = NOW(), whitelist_reason = :reason, "
                "    blocked = FALSE, blocked_at = NULL, block_reason = NULL "
                "WHERE sender_email = :email"
            ),
            {"email": sender_email.lower(), "reason": reason},
        )
        logger.info(f"email_reputation: sender {sender_email} whitelisted — {reason}")

    def is_whitelisted(self, conn, sender_email: str) -> bool:
        """Return True if sender is in the local whitelist."""
        row = conn.execute(
            text("SELECT whitelisted FROM email_sender_reputation WHERE sender_email = :email"),
            {"email": sender_email.lower()},
        ).fetchone()
        return bool(row and row.whitelisted)

    def mark_domain_blocked(self, conn, domain: str, reason: str):
        """Mark entire domain as blocked."""
        conn.execute(
            text(
                "UPDATE email_domain_reputation "
                "SET blocked = TRUE, blocked_at = NOW(), block_reason = :reason "
                "WHERE domain = :domain"
            ),
            {"domain": domain.lower(), "reason": reason},
        )
        logger.info(f"email_reputation: domain {domain} marked as blocked — {reason}")

    def get_reputation(self, conn, sender_email: str) -> dict:
        """Fetch full reputation record for a sender."""
        row = conn.execute(
            text(
                "SELECT id, sender_email, sender_domain, display_name, "
                "report_count, automated_count, threat_score_avg, threat_score_max, "
                "first_seen_at, last_seen_at, blocked, blocked_at, block_reason, "
                "whitelisted, whitelisted_at, whitelist_reason "
                "FROM email_sender_reputation WHERE sender_email = :email"
            ),
            {"email": sender_email.lower()},
        ).fetchone()
        if not row:
            return {}
        return self._row_to_dict(row)

    def list_senders(
        self,
        conn,
        blocked_only: bool = False,
        whitelisted_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """Return (items, total) for sender reputation list with pagination."""
        if blocked_only:
            where = "WHERE blocked = TRUE"
        elif whitelisted_only:
            where = "WHERE whitelisted = TRUE"
        else:
            where = ""
        total = (
            conn.execute(text(f"SELECT COUNT(*) FROM email_sender_reputation {where}")).scalar()
            or 0
        )
        rows = conn.execute(
            text(
                f"SELECT id, sender_email, sender_domain, display_name, "
                f"report_count, automated_count, threat_score_avg, threat_score_max, "
                f"first_seen_at, last_seen_at, blocked, blocked_at, block_reason, "
                f"whitelisted, whitelisted_at, whitelist_reason "
                f"FROM email_sender_reputation {where} "
                f"ORDER BY (report_count * 3 + automated_count) DESC, last_seen_at DESC "
                f"LIMIT :lim OFFSET :off"
            ),
            {"lim": limit, "off": offset},
        ).fetchall()
        return [self._row_to_dict(r) for r in rows], int(total)

    def list_domains(
        self,
        conn,
        blocked_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """Return (items, total) for domain reputation list with pagination."""
        where = "WHERE blocked = TRUE" if blocked_only else ""
        total = (
            conn.execute(text(f"SELECT COUNT(*) FROM email_domain_reputation {where}")).scalar()
            or 0
        )
        rows = conn.execute(
            text(
                f"SELECT id, domain, sender_count, report_count, automated_count, "
                f"threat_score_avg, first_seen_at, last_seen_at, blocked, blocked_at, block_reason "
                f"FROM email_domain_reputation {where} "
                f"ORDER BY (report_count * 3 + automated_count) DESC "
                f"LIMIT :lim OFFSET :off"
            ),
            {"lim": limit, "off": offset},
        ).fetchall()
        return [dict(zip(r._fields, r)) for r in rows], int(total)

    @staticmethod
    def _row_to_dict(row) -> dict:
        d = dict(zip(row._fields, row))
        for k in ("first_seen_at", "last_seen_at", "blocked_at", "whitelisted_at"):
            if d.get(k):
                d[k] = str(d[k])
        d["effective_score"] = d.get("report_count", 0) * 3 + d.get("automated_count", 0)
        return d
