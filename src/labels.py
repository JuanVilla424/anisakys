"""Analyst labels: the ground truth that detection quality is measured against.

An analyst confirms, dismisses or reports a site. Every decision is a row in
``labels`` (migration 006), written in the same short transaction that updates
the site's denormalised ``label_verdict``/``labeled_at`` and, depending on the
action, its review and reporting flags:

========  ========  =========================================================
Action    Verdict   Effect on the site
========  ========  =========================================================
confirm   phishing  leaves the review and approval queues; nothing is sent
dismiss   benign    leaves the queues and the reporting loop; queued e-mails of
                    the site are cancelled and its analyst tasks closed
report    phishing  flagged for reporting (``manual_flag = 1``); a submission
                    waiting for approval is released to the pipeline
========  ========  =========================================================

``detector_snapshot`` keeps what the detector had concluded when the label was
written, so the evaluation harness (:mod:`src.eval`) scores the prediction the
analyst actually saw instead of a later re-scan.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from src.reporting.db import short_transaction
from src.reporting.recipient_policy import registrable_domain
from src.reporting.report_tracker import ReportTracker

MAX_NOTE_LENGTH = 1000
MAX_TAG_LENGTH = 100
CANCELLED_BY_DISMISSAL = "Cancelled: an analyst labelled the site benign"


class LabelAction(str, Enum):
    """What the analyst decided."""

    CONFIRM = "confirm"
    DISMISS = "dismiss"
    REPORT = "report"


class LabelVerdict(str, Enum):
    """Ground-truth class of a labelled site."""

    PHISHING = "phishing"
    BENIGN = "benign"


VERDICT_BY_ACTION: Dict[LabelAction, LabelVerdict] = {
    LabelAction.CONFIRM: LabelVerdict.PHISHING,
    LabelAction.DISMISS: LabelVerdict.BENIGN,
    LabelAction.REPORT: LabelVerdict.PHISHING,
}

# Detector outputs copied into ``detector_snapshot`` (all phishing_sites columns).
SNAPSHOT_COLUMNS: Tuple[str, ...] = (
    "multi_api_threat_level",
    "api_confidence_score",
    "auto_report_eligible",
    "requires_manual_review",
    "auto_analysis_status",
    "auto_analysis_timestamp",
    "detection_keywords",
    "detected_kit_type",
    "kit_confidence",
    "gsb_threat_type",
    "gsb_safe",
    "gsb_last_check",
    "source",
    "priority",
    "manual_flag",
    "auto_detected",
    "abuse_report_sent",
    "site_status",
    "first_seen",
)

_LABEL_COLUMNS = (
    "id, site_id, url, registrable_domain, verdict, action, brand, kit, note, "
    "labeled_by, detector_snapshot, created_at"
)

_SITE_STATE_COLUMNS = (
    "id, url, label_verdict, labeled_at, manual_flag, requires_manual_review, "
    "auto_report_eligible, auto_analysis_status, site_status, abuse_report_sent"
)

# Per-action changes to the site, on top of label_verdict/labeled_at.
_SITE_UPDATES: Dict[LabelAction, str] = {
    LabelAction.CONFIRM: "requires_manual_review = 0",
    LabelAction.DISMISS: "requires_manual_review = 0, auto_report_eligible = 0",
    LabelAction.REPORT: (
        "requires_manual_review = 0, manual_flag = 1, "
        "auto_analysis_status = CASE WHEN auto_analysis_status = 'awaiting_approval' "
        "THEN NULL ELSE auto_analysis_status END"
    ),
}


class SiteNotFoundError(LookupError):
    """No ``phishing_sites`` row has the requested id."""


def _json_safe(value: Any) -> Any:
    """Convert a column value into something ``json.dumps`` accepts.

    Args:
        value: Raw column value.

    Returns:
        ISO-8601 for datetimes (naive legacy values are UTC), the value itself
        for JSON scalars, ``str()`` for anything else.
    """
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value.astimezone(datetime.timezone.utc).isoformat()
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def detector_snapshot(row: Mapping[Any, Any]) -> Dict[str, Any]:
    """Pick the detector outputs of a site row.

    Args:
        row: Mapping with the :data:`SNAPSHOT_COLUMNS`.

    Returns:
        JSON-safe ``{column: value}`` for every snapshot column present.
    """
    return {column: _json_safe(row[column]) for column in SNAPSHOT_COLUMNS if column in row}


def clean_tag(value: Optional[str]) -> Optional[str]:
    """Normalise an optional brand/kit tag.

    Args:
        value: Raw tag.

    Returns:
        The stripped tag, or ``None`` when empty.
    """
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


@dataclass(frozen=True)
class Label:
    """One analyst decision."""

    id: int
    site_id: Optional[int]
    url: str
    registrable_domain: str
    verdict: str
    action: str
    brand: Optional[str]
    kit: Optional[str]
    note: Optional[str]
    labeled_by: Optional[str]
    detector_snapshot: Dict[str, Any]
    created_at: Optional[datetime.datetime]

    @classmethod
    def from_mapping(cls, row: Mapping[Any, Any]) -> "Label":
        """Build from a row of ``labels``.

        Args:
            row: Mapping with the label columns.

        Returns:
            The label.
        """
        snapshot = row["detector_snapshot"]
        if isinstance(snapshot, str):
            snapshot = json.loads(snapshot or "{}")
        return cls(
            id=int(row["id"]),
            site_id=row["site_id"],
            url=row["url"],
            registrable_domain=row["registrable_domain"],
            verdict=row["verdict"],
            action=row["action"],
            brand=row["brand"],
            kit=row["kit"],
            note=row["note"],
            labeled_by=row["labeled_by"],
            detector_snapshot=snapshot or {},
            created_at=row["created_at"],
        )


@dataclass(frozen=True)
class LabelOutcome:
    """Result of recording a label."""

    label: Label
    site: Dict[str, Any]
    released_from_approval: bool
    cancelled_deliveries: int
    closed_tasks: int


class LabelRepository:
    """Database access for ``labels``; each public call is one short transaction."""

    def __init__(self, engine: Engine) -> None:
        """Create a repository.

        Args:
            engine: Database engine.
        """
        self.engine = engine
        self.tracker = ReportTracker(engine)

    def record(
        self,
        site_id: int,
        action: LabelAction,
        *,
        brand: Optional[str] = None,
        kit: Optional[str] = None,
        note: Optional[str] = None,
        labeled_by: Optional[str] = None,
    ) -> LabelOutcome:
        """Record an analyst decision about a site and apply its effect.

        Args:
            site_id: ``phishing_sites.id``.
            action: The decision.
            brand: Impersonated brand, when the analyst names it.
            kit: Phishing kit, when known.
            note: Free-text note.
            labeled_by: Who decided (API key name, or ``master``).

        Returns:
            The stored label and the site's state after the change.

        Raises:
            SiteNotFoundError: No site has that id.
        """
        with short_transaction(self.engine) as conn:
            return self.record_in(
                conn, site_id, action, brand=brand, kit=kit, note=note, labeled_by=labeled_by
            )

    def record_in(
        self,
        conn: Connection,
        site_id: int,
        action: LabelAction,
        *,
        brand: Optional[str] = None,
        kit: Optional[str] = None,
        note: Optional[str] = None,
        labeled_by: Optional[str] = None,
    ) -> LabelOutcome:
        """Same as :meth:`record`, inside the caller's open transaction.

        Args:
            conn: Connection inside an open transaction.
            site_id: ``phishing_sites.id``.
            action: The decision.
            brand: Impersonated brand.
            kit: Phishing kit.
            note: Free-text note.
            labeled_by: Who decided.

        Returns:
            The stored label and the site's state after the change.

        Raises:
            SiteNotFoundError: No site has that id.
        """
        site = (
            conn.execute(
                text(
                    f"SELECT id, url, approval_requested_at, {', '.join(SNAPSHOT_COLUMNS)} "
                    "FROM phishing_sites WHERE id = :id FOR UPDATE"
                ),
                {"id": site_id},
            )
            .mappings()
            .first()
        )
        if site is None:
            raise SiteNotFoundError(site_id)

        verdict = VERDICT_BY_ACTION[action]
        label_row = (
            conn.execute(
                text(f"""
                    INSERT INTO labels
                        (site_id, url, registrable_domain, verdict, action, brand, kit, note,
                         labeled_by, detector_snapshot)
                    VALUES
                        (:site_id, :url, :domain, :verdict, :action, :brand, :kit, :note,
                         :labeled_by, CAST(:snapshot AS JSONB))
                    RETURNING {_LABEL_COLUMNS}
                    """),
                {
                    "site_id": site_id,
                    "url": site["url"],
                    "domain": registrable_domain(site["url"]),
                    "verdict": verdict.value,
                    "action": action.value,
                    "brand": clean_tag(brand),
                    "kit": clean_tag(kit),
                    "note": clean_tag(note),
                    "labeled_by": labeled_by,
                    "snapshot": json.dumps(detector_snapshot(site)),
                },
            )
            .mappings()
            .one()
        )
        site_state = (
            conn.execute(
                text(f"""
                    UPDATE phishing_sites
                    SET label_verdict = :verdict, labeled_at = now(), {_SITE_UPDATES[action]}
                    WHERE id = :id
                    RETURNING {_SITE_STATE_COLUMNS}
                    """),
                {"verdict": verdict.value, "id": site_id},
            )
            .mappings()
            .one()
        )

        cancelled = closed = 0
        if action == LabelAction.DISMISS:
            cancelled, closed = self._stop_deliveries(conn, site["url"], labeled_by, note)

        released = (
            action == LabelAction.REPORT
            and site["approval_requested_at"] is not None
            and not site["manual_flag"]
        )
        return LabelOutcome(
            label=Label.from_mapping(label_row),
            site=dict(site_state),
            released_from_approval=released,
            cancelled_deliveries=cancelled,
            closed_tasks=closed,
        )

    def _stop_deliveries(
        self, conn: Connection, url: str, labeled_by: Optional[str], note: Optional[str]
    ) -> Tuple[int, int]:
        """Cancel the queued e-mails and close the analyst tasks of a benign site.

        Rows already being sent (``sending``) or delivered are left alone. The
        reports that lose every delivery settle like a closed analyst task
        would (``failed`` when nothing was delivered).

        Args:
            conn: Connection inside an open transaction.
            url: Site URL (outbox rows are keyed by it).
            labeled_by: Who dismissed the site.
            note: The analyst's note.

        Returns:
            ``(cancelled e-mail rows, closed analyst tasks)``.
        """
        cancelled_rows = conn.execute(
            text("""
                UPDATE abuse_report_outbox
                SET status = 'failed', last_error = :reason,
                    locked_by = NULL, locked_until = NULL, updated_at = now()
                WHERE site_url = :url AND channel = 'email' AND status = 'pending'
                RETURNING report_id
                """),
            {"url": url, "reason": CANCELLED_BY_DISMISSAL},
        ).fetchall()
        analyst = {
            "outcome": "not_applicable",
            "note": clean_tag(note),
            "completed_by": labeled_by,
            "reason": "site labelled benign",
        }
        closed_rows = conn.execute(
            text("""
                UPDATE abuse_report_outbox
                SET status = 'failed', last_error = :reason,
                    payload = payload || jsonb_build_object(
                        'analyst',
                        CAST(:analyst AS JSONB) || jsonb_build_object('completed_at', now())
                    ),
                    updated_at = now()
                WHERE site_url = :url AND status = 'pending_manual'
                RETURNING report_id
                """),
            {"url": url, "reason": CANCELLED_BY_DISMISSAL, "analyst": json.dumps(analyst)},
        ).fetchall()
        for report_id in sorted({row[0] for row in (*cancelled_rows, *closed_rows)}):
            self.tracker.settle_manual_report(conn, report_id)
            self.tracker.mark_report_failed_if_undeliverable(conn, report_id)
        return len(cancelled_rows), len(closed_rows)

    def history(self, site_id: int) -> List[Label]:
        """Every label of a site, newest first.

        Args:
            site_id: ``phishing_sites.id``.

        Returns:
            The labels.
        """
        with short_transaction(self.engine) as conn:
            rows = (
                conn.execute(
                    text(
                        f"SELECT {_LABEL_COLUMNS} FROM labels WHERE site_id = :id "
                        "ORDER BY created_at DESC, id DESC"
                    ),
                    {"id": site_id},
                )
                .mappings()
                .all()
            )
        return [Label.from_mapping(row) for row in rows]

    def list_labels(
        self,
        *,
        verdict: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Label], int]:
        """List labels, newest first.

        Args:
            verdict: Only this verdict.
            action: Only this action.
            limit: Page size.
            offset: Rows to skip.

        Returns:
            ``(labels, total matching)``.
        """
        clauses: List[str] = []
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if verdict:
            clauses.append("verdict = :verdict")
            params["verdict"] = verdict
        if action:
            clauses.append("action = :action")
            params["action"] = action
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with short_transaction(self.engine) as conn:
            total = conn.execute(text(f"SELECT COUNT(*) FROM labels {where}"), params).scalar()
            rows = (
                conn.execute(
                    text(
                        f"SELECT {_LABEL_COLUMNS} FROM labels {where} "
                        "ORDER BY created_at DESC, id DESC LIMIT :limit OFFSET :offset"
                    ),
                    params,
                )
                .mappings()
                .all()
            )
        return [Label.from_mapping(row) for row in rows], int(total or 0)

    def latest_per_url(self) -> List[Label]:
        """The current label of every labelled URL (the evaluation ground truth).

        Returns:
            One label per URL: the newest.
        """
        with short_transaction(self.engine, statement_timeout_ms=60_000) as conn:
            rows = (
                conn.execute(
                    text(
                        f"SELECT DISTINCT ON (url) {_LABEL_COLUMNS} FROM labels "
                        "ORDER BY url, created_at DESC, id DESC"
                    )
                )
                .mappings()
                .all()
            )
        return [Label.from_mapping(row) for row in rows]

    def pending_approvals(
        self, *, limit: int = 50, offset: int = 0
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Submissions waiting for an analyst decision, oldest request first.

        A site is listed while a ``POST /report`` without ``report_send``
        requested it, nobody flagged it for reporting and no label decided it.

        Args:
            limit: Page size.
            offset: Rows to skip.

        Returns:
            ``(sites, total waiting)``.
        """
        where = (
            "WHERE approval_requested_at IS NOT NULL AND COALESCE(manual_flag, 0) = 0 "
            "AND label_verdict IS NULL"
        )
        with short_transaction(self.engine) as conn:
            total = conn.execute(text(f"SELECT COUNT(*) FROM phishing_sites {where}")).scalar()
            rows = (
                conn.execute(
                    text(f"""
                        SELECT id, url, source, priority, description, abuse_email,
                               site_status, first_seen, last_seen,
                               approval_requested_at, approval_requested_by
                        FROM phishing_sites {where}
                        ORDER BY approval_requested_at, id
                        LIMIT :limit OFFSET :offset
                        """),
                    {"limit": limit, "offset": offset},
                )
                .mappings()
                .all()
            )
        return [dict(row) for row in rows], int(total or 0)
