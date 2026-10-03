"""Integration tests for the ``/api/v1/reports`` endpoints against real PostgreSQL.

The schema comes from ``alembic upgrade head`` (see ``tests/api/conftest.py``),
so the SQL issued by the API is checked against the real column types.
"""

import uuid

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
