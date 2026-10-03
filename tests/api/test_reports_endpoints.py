"""Integration tests for the ``/api/v1/reports`` endpoints against real PostgreSQL.

The schema comes from ``alembic upgrade head`` (see ``tests/api/conftest.py``),
so the SQL issued by the API is checked against the real column types.
"""

import uuid

import pytest

from sqlalchemy import text


def _insert_report(db_manager, *, recipients: str = '["abuse@registrar.example"]') -> str:
    """Insert one abuse report row and return its report_id.

    Args:
        db_manager: DatabaseManager bound to the migrated schema.
        recipients: Raw value stored in ``abuse_reports.recipients``.

    Returns:
        The generated report_id.
    """
    report_id = f"RPT-{uuid.uuid4().hex[:10]}"
    with db_manager.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO abuse_reports (site_url, recipients, report_id, status) "
                "VALUES (:url, :recipients, :rid, 'sent')"
            ),
            {
                "url": f"https://{report_id.lower()}.example/",
                "recipients": recipients,
                "rid": report_id,
            },
        )
    return report_id


class TestPatchReport:
    """PATCH /api/v1/reports/<report_id> used to 500 on every call on PostgreSQL."""

    def test_resolving_a_report_sets_response_fields(self, pg_api):
        client, db_manager, headers = pg_api
        report_id = _insert_report(db_manager)

        resp = client.patch(
            f"/api/v1/reports/{report_id}", json={"status": "resolved"}, headers=headers
        )

        assert resp.status_code == 200, resp.get_json()
        assert resp.get_json() == {"report_id": report_id, "status": "resolved"}
        with db_manager.engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT status, response_received, response_date FROM abuse_reports "
                    "WHERE report_id = :rid"
                ),
                {"rid": report_id},
            ).one()
        assert row.status == "resolved"
        assert row.response_received == 1
        assert row.response_date is not None

    def test_other_statuses_keep_response_fields(self, pg_api):
        client, db_manager, headers = pg_api
        report_id = _insert_report(db_manager)

        resp = client.patch(
            f"/api/v1/reports/{report_id}", json={"status": "in_progress"}, headers=headers
        )

        assert resp.status_code == 200, resp.get_json()
        with db_manager.engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT response_received, response_date FROM abuse_reports "
                    "WHERE report_id = :rid"
                ),
                {"rid": report_id},
            ).one()
        assert row.response_received == 0
        assert row.response_date is None

    def test_unknown_report_returns_404(self, pg_api):
        client, _, headers = pg_api

        resp = client.patch(
            "/api/v1/reports/RPT-does-not-exist", json={"status": "resolved"}, headers=headers
        )

        assert resp.status_code == 404


class TestListReportsRecipients:
    """GET /api/v1/reports used to split the JSON-encoded column on commas."""

    def test_json_encoded_recipients_are_decoded(self, pg_api):
        client, db_manager, headers = pg_api
        report_id = _insert_report(
            db_manager, recipients='["abuse@registrar.example", "abuse@host.example"]'
        )

        resp = client.get("/api/v1/reports?limit=500", headers=headers)

        assert resp.status_code == 200, resp.get_json()
        item = next(i for i in resp.get_json()["items"] if i["report_id"] == report_id)
        assert item["recipients"] == ["abuse@registrar.example", "abuse@host.example"]

    def test_legacy_comma_separated_recipients_still_work(self, pg_api):
        client, db_manager, headers = pg_api
        report_id = _insert_report(
            db_manager, recipients="abuse@registrar.example, abuse@host.example"
        )

        resp = client.get("/api/v1/reports?limit=500", headers=headers)

        item = next(i for i in resp.get_json()["items"] if i["report_id"] == report_id)
        assert item["recipients"] == ["abuse@registrar.example", "abuse@host.example"]


class TestParseRecipients:
    """Unit tests for the recipients decoder."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            (None, []),
            ("", []),
            ('["a@x.example", " b@y.example "]', ["a@x.example", "b@y.example"]),
            ('"a@x.example"', ["a@x.example"]),
            ("a@x.example,b@y.example", ["a@x.example", "b@y.example"]),
            ("a@x.example", ["a@x.example"]),
            ('["a@x.example", 3, ""]', ["a@x.example"]),
            ('{"to": "a@x.example"}', []),
        ],
    )
    def test_decodes_json_and_legacy_formats(self, raw, expected):
        from src.api.phishing_api import parse_recipients

        assert parse_recipients(raw) == expected
