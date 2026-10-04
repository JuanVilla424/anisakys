"""/api/v1/reports/stats against the migrated schema."""

from sqlalchemy import text


def test_empty_history_reports_unknown_response_rate(pg_api):
    """With no reports the response rate is unknown (null), not 0 %."""
    client, db_manager, headers = pg_api
    with db_manager.engine.begin() as conn:
        conn.execute(text("DELETE FROM abuse_reports"))

    response = client.get("/api/v1/reports/stats", headers=headers)

    assert response.status_code == 200
    body = response.get_json()
    assert body["response_rate"] is None
    assert body["generated_at"].endswith("+00:00")
