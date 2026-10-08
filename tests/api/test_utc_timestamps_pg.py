"""Every timestamp the API returns carries an explicit UTC offset (D16)."""

import datetime

from sqlalchemy import text


def test_health_timestamp_has_utc_offset(pg_api):
    client, _db_manager, _headers = pg_api

    body = client.get("/api/v1/health").get_json()

    assert body["timestamp"].endswith("+00:00")


def test_report_dates_have_utc_offset_and_null_status_is_labelled(pg_api):
    client, db_manager, headers = pg_api
    sent = datetime.datetime(2026, 10, 1, 12, 0, 0)
    with db_manager.engine.begin() as conn:
        conn.execute(text("DELETE FROM abuse_reports"))
        conn.execute(
            text(
                "INSERT INTO abuse_reports (site_url, recipients, report_id, status, "
                "report_date, sla_deadline) VALUES (:url, :rcpt, :rid, NULL, :sent, :sla)"
            ),
            {
                "url": "https://phish.example/login",
                "rcpt": '["abuse@registrar.example"]',
                "rid": "ANISAKYS-TEST-UTC",
                "sent": sent,
                "sla": sent + datetime.timedelta(days=2),
            },
        )

    listing = client.get("/api/v1/reports", headers=headers).get_json()
    item = next(r for r in listing["items"] if r["report_id"] == "ANISAKYS-TEST-UTC")
    assert item["report_date"] == "2026-10-01T12:00:00+00:00"
    assert item["sla_deadline"] == "2026-10-03T12:00:00+00:00"

    stats = client.get("/api/v1/reports/stats", headers=headers).get_json()
    assert "null" not in stats["status_breakdown"]
    assert stats["status_breakdown"].get("unknown") == 1
