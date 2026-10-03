"""Transactional outbox for abuse-report deliveries.

Every outbound message — an initial report to one abuse desk, the single CC
copy, a follow-up — is a row in ``abuse_report_outbox`` (migration 004), and
so is every analyst task (a form-only provider, or a site with no usable
contact). Rows are written in the same short transaction that creates the
tracked report, then delivered by whichever worker claims them.

Lifecycle::

    pending ──claim──▶ sending ──SMTP ok──▶ sent
       ▲                  │
       └──retryable error─┤ (attempts < max_attempts, with backoff)
                          └──permanent error or attempts exhausted──▶ failed

    pending_manual  (web_form / manual_review tasks; an analyst closes them)

Delivery semantics (at most once per attempt):

* A row is claimed with ``SELECT ... FOR UPDATE SKIP LOCKED`` and moved to
  ``sending`` — with ``attempts`` incremented and a lease (``locked_until``)
  — in its own committed transaction *before* the SMTP conversation starts.
  Concurrent workers skip locked or leased rows, so one attempt is made by
  exactly one worker and performs at most one SMTP transaction.
* The outcome is recorded in a second short transaction, guarded by
  ``locked_by`` so a worker that lost its lease cannot overwrite a newer
  outcome.
* If the process dies between the SMTP ``DATA`` acceptance and that second
  transaction, the row stays ``sending`` until its lease expires. It is then
  treated as an interrupted attempt: re-claimed as a *new* attempt while
  ``attempts < max_attempts``, otherwise marked ``failed`` with "delivery
  state unknown". A recipient can therefore receive at most ``max_attempts``
  copies, never more, and every copy carries the same ``Message-ID`` so the
  duplicate is recognisable. Enqueueing is idempotent too:
  ``UNIQUE (report_id, recipient, followup_seq)`` with ``ON CONFLICT DO
  NOTHING``.
* A rate-limited row goes back to ``pending`` without consuming an attempt.

``last_error`` only ever stores a sanitised, truncated message.
"""

from __future__ import annotations

import json
import os
import re
import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from src.config import settings
from src.reporting.db import short_transaction

MAX_ERROR_LENGTH = 500
_URL_CREDENTIALS_RE = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@")
_SECRET_PAIR_RE = re.compile(
    r"(?P<key>password|passwd|pass|secret|token|api[_-]?key|auth)(?P<sep>\s*[=:]\s*)\S+",
    re.IGNORECASE,
)


class OutboxStatus(str, Enum):
    """Lifecycle states of an outbox row."""

    PENDING = "pending"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"
    PENDING_MANUAL = "pending_manual"


class OutboxChannel(str, Enum):
    """How a row is delivered."""

    EMAIL = "email"
    WEB_FORM = "web_form"
    MANUAL_REVIEW = "manual_review"


class OutboxAudience(str, Enum):
    """Whom an e-mail row addresses."""

    PRIMARY = "primary"
    CC = "cc"


def default_worker_id() -> str:
    """Identify this process in ``locked_by``/``report_claimed_by`` columns.

    Returns:
        ``<hostname>:<pid>``.
    """
    return f"{socket.gethostname()}:{os.getpid()}"


def sanitize_error(error: Any, max_length: int = MAX_ERROR_LENGTH) -> str:
    """Make an exception or message safe to persist and log.

    Strips control characters, masks URL credentials and ``key=value``
    secrets, and truncates.

    Args:
        error: Exception or message.
        max_length: Maximum length of the result.

    Returns:
        The sanitised message, prefixed with the exception type when known.
    """
    if isinstance(error, BaseException):
        message = f"{type(error).__name__}: {error}"
    else:
        message = str(error)
    message = re.sub(r"[\x00-\x1f\x7f]+", " ", message)
    message = _URL_CREDENTIALS_RE.sub(lambda m: f"{m.group('scheme')}***@", message)
    message = _SECRET_PAIR_RE.sub(lambda m: f"{m.group('key')}{m.group('sep')}***", message)
    message = re.sub(r"\s+", " ", message).strip()
    if len(message) > max_length:
        message = message[: max_length - 3] + "..."
    return message


@dataclass
class NewOutboxEntry:
    """A row to enqueue."""

    report_id: str
    site_url: str
    recipient: str
    channel: OutboxChannel = OutboxChannel.EMAIL
    audience: OutboxAudience = OutboxAudience.PRIMARY
    followup_seq: int = 0
    cc: Sequence[str] = ()
    form_url: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)

    @property
    def initial_status(self) -> OutboxStatus:
        """Status the row is created with.

        Returns:
            ``pending`` for e-mail, ``pending_manual`` for analyst tasks.
        """
        if self.channel == OutboxChannel.EMAIL:
            return OutboxStatus.PENDING
        return OutboxStatus.PENDING_MANUAL


@dataclass
class OutboxRow:
    """A claimed (or listed) outbox row."""

    id: int
    report_id: str
    site_url: str
    channel: str
    audience: str
    followup_seq: int
    recipient: str
    cc: List[str]
    form_url: Optional[str]
    status: str
    attempts: int
    max_attempts: int
    payload: Dict[str, Any]
    last_error: Optional[str] = None
    message_id: Optional[str] = None

    @property
    def envelope_recipients(self) -> List[str]:
        """Every address this row's message is delivered to.

        Returns:
            ``recipient`` followed by the ``cc`` addresses.
        """
        return [self.recipient, *self.cc]

    @classmethod
    def from_mapping(cls, row: Any) -> "OutboxRow":
        """Build from a SQLAlchemy row mapping.

        Args:
            row: Row with the outbox columns.

        Returns:
            The row object.
        """
        payload = row["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload or "{}")
        cc_value = row["cc"] or ""
        return cls(
            id=int(row["id"]),
            report_id=row["report_id"],
            site_url=row["site_url"],
            channel=row["channel"],
            audience=row["audience"],
            followup_seq=int(row["followup_seq"]),
            recipient=row["recipient"],
            cc=[address for address in cc_value.split(",") if address],
            form_url=row["form_url"],
            status=row["status"],
            attempts=int(row["attempts"]),
            max_attempts=int(row["max_attempts"]),
            payload=payload or {},
            last_error=row["last_error"],
            message_id=row["message_id"],
        )


_ROW_COLUMNS = (
    "id, report_id, site_url, channel, audience, followup_seq, recipient, cc, form_url, "
    "status, attempts, max_attempts, payload, last_error, message_id"
)


class OutboxRepository:
    """Database access for ``abuse_report_outbox``; every call is one short transaction."""

    def __init__(
        self,
        engine: Engine,
        worker_id: Optional[str] = None,
        lease_seconds: Optional[int] = None,
        max_attempts: Optional[int] = None,
        retry_backoff_seconds: Optional[int] = None,
    ) -> None:
        """Create a repository.

        Args:
            engine: Database engine.
            worker_id: Owner written to ``locked_by``; defaults to host:pid.
            lease_seconds: How long a claim protects a ``sending`` row.
            max_attempts: Attempts per row before it is marked failed.
            retry_backoff_seconds: Base delay before a retry (multiplied by the
                attempt number).
        """
        self.engine = engine
        self.worker_id = worker_id or default_worker_id()
        self.lease_seconds = lease_seconds or settings.REPORT_CLAIM_LEASE_SECONDS
        self.max_attempts = max_attempts or settings.OUTBOX_MAX_ATTEMPTS
        self.retry_backoff_seconds = retry_backoff_seconds or settings.OUTBOX_RETRY_BACKOFF_SECONDS

    def enqueue(self, conn: Connection, entries: Iterable[NewOutboxEntry]) -> List[int]:
        """Insert rows inside the caller's transaction; duplicates are ignored.

        Args:
            conn: Connection inside an open transaction.
            entries: Rows to insert.

        Returns:
            Ids of the rows actually inserted.
        """
        inserted: List[int] = []
        for entry in entries:
            row_id = conn.execute(
                text("""
                    INSERT INTO abuse_report_outbox
                        (report_id, site_url, channel, audience, followup_seq, recipient,
                         cc, form_url, status, max_attempts, payload)
                    VALUES
                        (:report_id, :site_url, :channel, :audience, :followup_seq, :recipient,
                         :cc, :form_url, :status, :max_attempts, CAST(:payload AS JSONB))
                    ON CONFLICT (report_id, recipient, followup_seq) DO NOTHING
                    RETURNING id
                    """),
                {
                    "report_id": entry.report_id,
                    "site_url": entry.site_url,
                    "channel": entry.channel.value,
                    "audience": entry.audience.value,
                    "followup_seq": entry.followup_seq,
                    "recipient": entry.recipient,
                    "cc": ",".join(entry.cc),
                    "form_url": entry.form_url,
                    "status": entry.initial_status.value,
                    "max_attempts": self.max_attempts,
                    "payload": json.dumps(entry.payload),
                },
            ).scalar()
            if row_id is not None:
                inserted.append(int(row_id))
        return inserted

    def claim_batch(self, limit: int, report_id: Optional[str] = None) -> List[OutboxRow]:
        """Claim deliverable e-mail rows for this worker.

        Picks ``pending`` rows that are due and ``sending`` rows whose lease
        expired (interrupted attempts) with attempts left, skipping rows other
        workers have locked.

        Args:
            limit: Maximum number of rows.
            report_id: Restrict to one report (used right after enqueueing).

        Returns:
            The claimed rows, now ``sending`` with ``attempts`` incremented.
        """
        report_filter = "AND report_id = :report_id" if report_id else ""
        with short_transaction(self.engine) as conn:
            rows = (
                conn.execute(
                    text(f"""
                        WITH picked AS (
                            SELECT id FROM abuse_report_outbox
                            WHERE channel = 'email'
                              AND (
                                    (status = 'pending' AND next_attempt_at <= now())
                                 OR (status = 'sending' AND locked_until < now()
                                     AND attempts < max_attempts)
                              )
                              {report_filter}
                            ORDER BY next_attempt_at, id
                            LIMIT :limit
                            FOR UPDATE SKIP LOCKED
                        )
                        UPDATE abuse_report_outbox AS o
                        SET status = 'sending',
                            attempts = o.attempts + 1,
                            locked_by = :worker,
                            locked_until = now() + make_interval(secs => :lease),
                            updated_at = now()
                        FROM picked
                        WHERE o.id = picked.id
                        RETURNING {", ".join("o." + c.strip() for c in _ROW_COLUMNS.split(","))}
                        """),
                    {
                        "limit": limit,
                        "worker": self.worker_id,
                        "lease": self.lease_seconds,
                        "report_id": report_id,
                    },
                )
                .mappings()
                .all()
            )
        return sorted((OutboxRow.from_mapping(row) for row in rows), key=lambda r: r.id)

    def expire_interrupted(self) -> int:
        """Fail ``sending`` rows whose lease expired with no attempts left.

        Returns:
            Number of rows marked ``failed``.
        """
        with short_transaction(self.engine) as conn:
            result = conn.execute(text("""
                    UPDATE abuse_report_outbox
                    SET status = 'failed',
                        last_error = 'Attempt interrupted before its outcome was recorded; '
                                     || 'delivery state unknown',
                        locked_by = NULL, locked_until = NULL, updated_at = now()
                    WHERE status = 'sending' AND locked_until < now()
                      AND attempts >= max_attempts
                    """))
            return int(result.rowcount or 0)

    def mark_sent(
        self, row: OutboxRow, message_id: str, conn: Connection, note: Optional[str] = None
    ) -> bool:
        """Record a successful delivery inside the caller's transaction.

        Args:
            row: The claimed row.
            message_id: ``Message-ID`` that was sent.
            conn: Connection inside an open transaction.
            note: Kept in ``last_error`` (e.g. some CC addresses were refused).

        Returns:
            ``False`` when this worker no longer owns the row (lease lost).
        """
        result = conn.execute(
            text("""
                UPDATE abuse_report_outbox
                SET status = 'sent', sent_at = now(), message_id = :message_id,
                    last_error = :note, locked_by = NULL, locked_until = NULL, updated_at = now()
                WHERE id = :id AND status = 'sending' AND locked_by = :worker
                """),
            {
                "id": row.id,
                "message_id": message_id,
                "worker": self.worker_id,
                "note": sanitize_error(note) if note else None,
            },
        )
        return bool(result.rowcount)

    def mark_failed(self, row: OutboxRow, error: Any, retryable: bool) -> str:
        """Record a failed attempt; retry later when allowed.

        Args:
            row: The claimed row.
            error: Exception or message (sanitised before storing).
            retryable: Whether another attempt may succeed.

        Returns:
            The resulting status (``pending`` or ``failed``).
        """
        retry = retryable and row.attempts < row.max_attempts
        status = OutboxStatus.PENDING if retry else OutboxStatus.FAILED
        with short_transaction(self.engine) as conn:
            conn.execute(
                text("""
                    UPDATE abuse_report_outbox
                    SET status = :status, last_error = :error,
                        next_attempt_at = now() + make_interval(secs => :delay),
                        locked_by = NULL, locked_until = NULL, updated_at = now()
                    WHERE id = :id AND status = 'sending' AND locked_by = :worker
                    """),
                {
                    "status": status.value,
                    "error": sanitize_error(error),
                    "delay": self.retry_backoff_seconds * max(1, row.attempts),
                    "id": row.id,
                    "worker": self.worker_id,
                },
            )
        return status.value

    def release(self, row: OutboxRow, delay_seconds: int, reason: str) -> None:
        """Return a claimed row to ``pending`` without consuming the attempt.

        Used when the shared rate limit is reached or a shutdown starts.

        Args:
            row: The claimed row.
            delay_seconds: How long to wait before it is due again.
            reason: Why it was released (stored as ``last_error``).
        """
        with short_transaction(self.engine) as conn:
            conn.execute(
                text("""
                    UPDATE abuse_report_outbox
                    SET status = 'pending', attempts = GREATEST(attempts - 1, 0),
                        last_error = :reason,
                        next_attempt_at = now() + make_interval(secs => :delay),
                        locked_by = NULL, locked_until = NULL, updated_at = now()
                    WHERE id = :id AND status = 'sending' AND locked_by = :worker
                    """),
                {
                    "reason": sanitize_error(reason),
                    "delay": delay_seconds,
                    "id": row.id,
                    "worker": self.worker_id,
                },
            )

    def rows_for_report(self, report_id: str) -> List[OutboxRow]:
        """List every row of a report (analyst views, tests).

        Args:
            report_id: Tracked report id.

        Returns:
            Rows ordered by id.
        """
        with short_transaction(self.engine) as conn:
            rows = (
                conn.execute(
                    text(
                        f"SELECT {_ROW_COLUMNS} FROM abuse_report_outbox "
                        "WHERE report_id = :report_id ORDER BY id"
                    ),
                    {"report_id": report_id},
                )
                .mappings()
                .all()
            )
        return [OutboxRow.from_mapping(row) for row in rows]

    def pending_manual_tasks(self, limit: int = 100) -> List[OutboxRow]:
        """List open analyst tasks (web forms, sites without contacts).

        Args:
            limit: Maximum number of rows.

        Returns:
            Oldest tasks first.
        """
        with short_transaction(self.engine) as conn:
            rows = (
                conn.execute(
                    text(
                        f"SELECT {_ROW_COLUMNS} FROM abuse_report_outbox "
                        "WHERE status = 'pending_manual' ORDER BY created_at, id LIMIT :limit"
                    ),
                    {"limit": limit},
                )
                .mappings()
                .all()
            )
        return [OutboxRow.from_mapping(row) for row in rows]
