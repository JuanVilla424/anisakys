"""Analyst tasks of the reporting outbox on real PostgreSQL.

GET /api/v1/reports/tasks lists ``pending_manual`` outbox rows (web forms,
sites without a usable contact); POST /api/v1/reports/tasks/<id>/complete
closes one and settles a report that only had analyst tasks.
"""

import hashlib
import json
import uuid
from typing import Any, Dict, Optional
from unittest.mock import patch

from sqlalchemy import text


def _report(db_manager, status: str = "pending_manual") -> str:
    report_id = f"ANISAKYS-20261004-{uuid.uuid4().hex[:8].upper()}"
    with db_manager.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO abuse_reports (site_url, recipients, report_id, status) "
                "VALUES (:url, '[]', :rid, :status)"
            ),
            {"url": f"https://{report_id.lower()}.example/", "rid": report_id, "status": status},
        )
    return report_id


def _task(
    db_manager,
    report_id: str,
    *,
    channel: str = "web_form",
    recipient: str = "Example Hosting",
    form_url: Optional[str] = "https://hoster.example/abuse-form",
    status: str = "pending_manual",
) -> int:
    payload = {"subject": f"Phishing report {report_id}", "text": "Evidence...", "reason": "form"}
    with db_manager.engine.begin() as conn:
        return int(
            conn.execute(
                text(
                    "INSERT INTO abuse_report_outbox (report_id, site_url, channel, recipient, "
                    "form_url, status, payload, created_at) VALUES (:rid, :url, :channel, "
                    ":recipient, :form_url, :status, CAST(:payload AS JSONB), "
                    "'2026-10-04 08:00:00+00') RETURNING id"
                ),
                {
                    "rid": report_id,
                    "url": f"https://{report_id.lower()}.example/",
                    "channel": channel,
                    "recipient": recipient,
                    "form_url": form_url,
                    "status": status,
                    "payload": json.dumps(payload),
                },
            ).scalar_one()
        )


def _report_status(db_manager, report_id: str) -> str:
    with db_manager.engine.begin() as conn:
        return conn.execute(
            text("SELECT status FROM abuse_reports WHERE report_id = :r"), {"r": report_id}
        ).scalar_one()


def _complete(client, headers, task_id: int, body: Any):
    return client.post(f"/api/v1/reports/tasks/{task_id}/complete", json=body, headers=headers)


def _all_tasks(client, headers) -> Dict[int, Dict[str, Any]]:
    body = client.get("/api/v1/reports/tasks?limit=200", headers=headers).get_json()
    return {t["id"]: t for t in body["items"]}


class TestListTasks:
    def test_open_tasks_are_listed_with_what_the_analyst_needs(self, pg_api):
        client, db_manager, headers = pg_api
        report_id = _report(db_manager)
        form = _task(db_manager, report_id)
        review = _task(
            db_manager,
            report_id,
            channel="manual_review",
            recipient="unresolved-contact",
            form_url=None,
        )
        email = _task(
            db_manager, report_id, channel="email", recipient="abuse@x.example", status="pending"
        )

        resp = client.get("/api/v1/reports/tasks?limit=200", headers=headers)

        assert resp.status_code == 200
        body = resp.get_json()
        tasks = {t["id"]: t for t in body["items"]}
        assert email not in tasks
        assert tasks[form] == {
            "id": form,
            "report_id": report_id,
            "site_url": f"https://{report_id.lower()}.example/",
            "channel": "web_form",
            "provider": "Example Hosting",
            "form_url": "https://hoster.example/abuse-form",
            "reason": "form",
            "subject": f"Phishing report {report_id}",
            "text": "Evidence...",
            "status": "pending_manual",
            "created_at": "2026-10-04T08:00:00+00:00",
            "outcome": None,
            "note": None,
            "completed_by": None,
            "completed_at": None,
        }
        assert tasks[review]["provider"] is None
        assert body["total"] >= 2
        assert (body["limit"], body["offset"]) == (200, 0)

    def test_pagination_reports_the_real_total(self, pg_api):
        client, db_manager, headers = pg_api
        report_id = _report(db_manager)
        for i in range(3):
            _task(db_manager, report_id, recipient=f"Provider {i}")

        everything = client.get("/api/v1/reports/tasks?limit=200", headers=headers).get_json()
        page = client.get("/api/v1/reports/tasks?limit=1&offset=1", headers=headers).get_json()

        assert page["total"] == everything["total"] == len(everything["items"])
        assert [t["id"] for t in page["items"]] == [everything["items"][1]["id"]]


class TestCompleteTask:
    def test_submitting_the_last_task_marks_the_report_sent(self, pg_api):
        client, db_manager, headers = pg_api
        report_id = _report(db_manager)
        form = _task(db_manager, report_id)
        review = _task(db_manager, report_id, channel="manual_review", recipient="unresolved")

        first = _complete(client, headers, form, {"outcome": "submitted", "note": "Ticket #42"})
        assert first.status_code == 200, first.get_json()
        task = first.get_json()["task"]
        assert task["status"] == "sent"
        assert task["outcome"] == "submitted"
        assert task["note"] == "Ticket #42"
        assert task["completed_by"] == "master"
        assert task["completed_at"].endswith("+00:00")
        # Another task of the report is still open: the report waits.
        assert first.get_json()["report_status"] is None
        assert _report_status(db_manager, report_id) == "pending_manual"
        assert form not in _all_tasks(client, headers)

        second = _complete(client, headers, review, {"outcome": "not_applicable"})
        assert second.get_json()["task"]["status"] == "failed"
        assert second.get_json()["report_status"] == "sent"
        assert _report_status(db_manager, report_id) == "sent"

    def test_report_with_only_not_applicable_tasks_fails(self, pg_api):
        client, db_manager, headers = pg_api
        report_id = _report(db_manager)
        task = _task(db_manager, report_id)

        resp = _complete(client, headers, task, {"outcome": "not_applicable", "note": "gone"})

        assert resp.get_json()["report_status"] == "failed"
        assert _report_status(db_manager, report_id) == "failed"

    def test_report_with_e_mail_deliveries_is_left_to_the_pipeline(self, pg_api):
        client, db_manager, headers = pg_api
        report_id = _report(db_manager, status="queued")
        task = _task(db_manager, report_id)

        resp = _complete(client, headers, task, {"outcome": "submitted"})

        assert resp.status_code == 200
        assert resp.get_json()["report_status"] is None
        assert _report_status(db_manager, report_id) == "queued"

    def test_closing_twice_is_a_conflict(self, pg_api):
        client, db_manager, headers = pg_api
        task = _task(db_manager, _report(db_manager))
        _complete(client, headers, task, {"outcome": "submitted"})

        again = _complete(client, headers, task, {"outcome": "not_applicable"})

        assert again.status_code == 409
        assert again.get_json() == {"error": "Task is already closed", "status": "sent"}

    def test_e_mail_rows_are_not_tasks(self, pg_api):
        client, db_manager, headers = pg_api
        row = _task(
            db_manager,
            _report(db_manager, status="queued"),
            channel="email",
            recipient="abuse@x.example",
            status="pending",
        )

        assert _complete(client, headers, row, {"outcome": "submitted"}).status_code == 409

    def test_unknown_task_is_404(self, pg_api):
        client, _, headers = pg_api

        resp = _complete(client, headers, 987654321, {"outcome": "submitted"})

        assert resp.status_code == 404

    def test_invalid_bodies_are_400(self, pg_api):
        client, db_manager, headers = pg_api
        task = _task(db_manager, _report(db_manager))

        for body in (None, [], {"outcome": "done"}, {"outcome": "submitted", "note": 3}):
            if body is None:
                resp = client.post(
                    f"/api/v1/reports/tasks/{task}/complete",
                    data="x",
                    content_type="text/plain",
                    headers=headers,
                )
            else:
                resp = _complete(client, headers, task, body)
            assert resp.status_code == 400, body
            assert resp.get_json()["error"]
        too_long = _complete(client, headers, task, {"outcome": "submitted", "note": "x" * 1001})
        assert too_long.status_code == 400
        assert too_long.get_json()["parameter"] == "note"
        assert task in _all_tasks(client, headers)

    def test_requires_report_scope_and_records_the_key_name(self, pg_api):
        client, db_manager, _ = pg_api
        task = _task(db_manager, _report(db_manager))
        key_hash = hashlib.sha256(b"k").hexdigest()

        def as_key(scopes: str):
            row = {"scopes": scopes, "allowed_ips": None, "key_hash": key_hash, "name": "analyst"}
            return (
                patch("src.auth._lookup_db_key", return_value=row),
                patch("src.auth._update_last_used"),
            )

        bearer = {"Authorization": "Bearer db-key"}
        lookup, touch = as_key("read")
        with lookup, touch:
            assert client.get("/api/v1/reports/tasks", headers=bearer).status_code == 200
            assert _complete(client, bearer, task, {"outcome": "submitted"}).status_code == 403
        lookup, touch = as_key("report")
        with lookup, touch:
            resp = _complete(client, bearer, task, {"outcome": "submitted"})
        assert resp.status_code == 200
        assert resp.get_json()["task"]["completed_by"] == "analyst"


class TestDeliveryState:
    def test_stats_report_real_delivery_state(self, pg_api):
        client, db_manager, headers = pg_api
        before = client.get("/api/v1/stats", headers=headers).get_json()
        queued = _report(db_manager, status="queued")
        _report(db_manager, status="pending_manual")
        _task(db_manager, queued, channel="email", recipient="abuse@x.example", status="sent")
        _task(db_manager, queued)

        after = client.get("/api/v1/stats", headers=headers).get_json()

        assert "reports_sent" in after  # kept for compatibility
        reports, outbox = after["reports_by_status"], after["outbox_by_status"]
        for status in ("queued", "sent", "failed", "pending_manual", "timeout"):
            assert status in reports
        assert reports["queued"] == before["reports_by_status"]["queued"] + 1
        assert reports["pending_manual"] == before["reports_by_status"]["pending_manual"] + 1
        assert set(outbox) == {"pending", "sending", "sent", "failed", "pending_manual"}
        assert outbox["sent"] == before["outbox_by_status"]["sent"] + 1
        assert outbox["pending_manual"] == before["outbox_by_status"]["pending_manual"] + 1

    def test_reports_can_be_filtered_by_pipeline_statuses(self, pg_api):
        client, db_manager, headers = pg_api
        report_id = _report(db_manager, status="pending_manual")

        resp = client.get("/api/v1/reports?status=pending_manual&limit=500", headers=headers)

        assert resp.status_code == 200
        assert report_id in {r["report_id"] for r in resp.get_json()["items"]}

    def test_pipeline_statuses_cannot_be_set_by_hand(self, pg_api):
        client, db_manager, headers = pg_api
        report_id = _report(db_manager, status="sent")

        resp = client.patch(
            f"/api/v1/reports/{report_id}", json={"status": "queued"}, headers=headers
        )

        assert resp.status_code == 400
        assert _report_status(db_manager, report_id) == "sent"

    def test_null_report_status_is_null_not_sent(self, pg_api):
        client, db_manager, headers = pg_api
        report_id = _report(db_manager)
        with db_manager.engine.begin() as conn:
            conn.execute(
                text("UPDATE abuse_reports SET status = NULL WHERE report_id = :r"),
                {"r": report_id},
            )

        items = client.get("/api/v1/reports?limit=500", headers=headers).get_json()["items"]

        assert next(r for r in items if r["report_id"] == report_id)["status"] is None
