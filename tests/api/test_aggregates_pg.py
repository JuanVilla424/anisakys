"""Integration tests for aggregate endpoints (graph, campaigns) on real PostgreSQL."""

import uuid
from typing import Optional

from sqlalchemy import text


def _insert_site(
    db_manager,
    url: str,
    *,
    registrar: Optional[str] = None,
    ip: Optional[str] = None,
    status: str = "up",
    last_seen: str = "2026-01-02 00:00:00",
) -> None:
    """Insert one phishing_sites row into the migrated schema.

    Args:
        db_manager: DatabaseManager bound to the isolated schema.
        url: Site URL (unique).
        registrar: Registrar name.
        ip: Resolved IP address.
        status: site_status value.
        last_seen: last_seen timestamp literal.
    """
    with db_manager.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO phishing_sites (url, registrar_name, resolved_ip, site_status, "
                "first_seen, last_seen, api_confidence_score, multi_api_threat_level) "
                "VALUES (:url, :reg, :ip, :status, '2026-01-01', :last_seen, 80, 'high')"
            ),
            {"url": url, "reg": registrar, "ip": ip, "status": status, "last_seen": last_seen},
        )


class TestGraphFocusOnPostgres:
    def test_registrar_focus_finds_rows_beyond_the_limit(self, pg_api):
        client, db_manager, headers = pg_api
        tag = uuid.uuid4().hex[:8]
        registrar = f"Mixed Case Registrar {tag}"
        _insert_site(
            db_manager, f"https://old-{tag}.example/", registrar=registrar, last_seen="2020-01-01"
        )
        for i in range(3):
            _insert_site(db_manager, f"https://new-{i}-{tag}.example/", last_seen="2026-06-01")

        resp = client.get(
            "/api/v1/graph",
            query_string={"focus": f"registrar:{registrar.upper()}", "limit": 1},
            headers=headers,
        )

        assert resp.status_code == 200, resp.get_json()
        ids = {n["id"] for n in resp.get_json()["nodes"]}
        assert ids == {f"registrar:{registrar}", f"domain:old-{tag}.example"}
