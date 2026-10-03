"""Console read endpoints on real PostgreSQL: unknown values stay unknown.

Every test runs against the isolated, migrated schema of ``pg_api`` (see
``tests/api/conftest.py``); rows are tagged with a random token so tests in
this module do not see each other's data.
"""

import uuid
from typing import Any, Dict

from sqlalchemy import text


def _tag() -> str:
    return uuid.uuid4().hex[:8]


def _insert(db_manager, table: str, values: Dict[str, Any]) -> int:
    """Insert one row and return its id.

    Args:
        db_manager: DatabaseManager bound to the isolated schema.
        table: Table name (a constant in these tests).
        values: Column -> value.

    Returns:
        The new row's ``id``.
    """
    columns = ", ".join(values)
    placeholders = ", ".join(f":{name}" for name in values)
    with db_manager.engine.begin() as conn:
        return int(
            conn.execute(
                text(f"INSERT INTO {table} ({columns}) VALUES ({placeholders}) RETURNING id"),
                values,
            ).scalar_one()
        )


def _site(db_manager, url: str, **columns: Any) -> int:
    values: Dict[str, Any] = {
        "url": url,
        "first_seen": "2026-01-01 10:00:00",
        "last_seen": "2026-01-02 10:00:00",
    }
    values.update(columns)
    return _insert(db_manager, "phishing_sites", values)


def _sites_by_url(client, headers, search: str) -> Dict[str, Dict[str, Any]]:
    resp = client.get("/api/v1/sites", query_string={"search": search}, headers=headers)
    assert resp.status_code == 200, resp.get_json()
    return {item["url"]: item for item in resp.get_json()["items"]}


class TestSites:
    def test_takedown_date_and_timestamps_carry_a_utc_offset(self, pg_api):
        client, db_manager, headers = pg_api
        tag = _tag()
        _site(
            db_manager,
            f"https://down-{tag}.example/",
            site_status="down",
            takedown_date="2026-02-03 04:05:06",
        )
        _site(db_manager, f"https://up-{tag}.example/")

        items = _sites_by_url(client, headers, tag)

        down = items[f"https://down-{tag}.example/"]
        assert down["takedown_date"] == "2026-02-03T04:05:06+00:00"
        assert down["first_seen"] == "2026-01-01T10:00:00+00:00"
        assert down["last_seen"] == "2026-01-02T10:00:00+00:00"
        assert items[f"https://up-{tag}.example/"]["takedown_date"] is None

    def test_null_columns_are_null_not_invented_defaults(self, pg_api):
        client, db_manager, headers = pg_api
        tag = _tag()
        _site(
            db_manager,
            f"https://nulls-{tag}.example/",
            source=None,
            priority=None,
            is_cloudflare=None,
        )

        item = _sites_by_url(client, headers, tag)[f"https://nulls-{tag}.example/"]

        assert item["source"] is None  # was "manual"
        assert item["priority"] is None  # was "medium"
        assert item["is_cloudflare"] is None  # was false
        # gsb_safe defaults to 1 in the schema, but GSB never checked the site.
        assert item["gsb_safe"] is None  # was true

    def test_stored_values_are_returned_as_stored(self, pg_api):
        client, db_manager, headers = pg_api
        tag = _tag()
        _site(
            db_manager,
            f"https://known-{tag}.example/",
            source="certstream",
            priority="high",
            is_cloudflare=0,
            gsb_safe=0,
            gsb_last_check="2026-01-05 00:00:00",
        )

        item = _sites_by_url(client, headers, tag)[f"https://known-{tag}.example/"]

        assert item["source"] == "certstream"
        assert item["priority"] == "high"
        assert item["is_cloudflare"] is False
        assert item["gsb_safe"] is False


class TestSiteSources:
    def test_counts_per_source_include_null(self, pg_api):
        client, db_manager, headers = pg_api
        tag = _tag()
        before = client.get("/api/v1/sites/sources", headers=headers).get_json()
        null_before = next((s["count"] for s in before if s["source"] is None), 0)
        for i in range(2):
            _site(db_manager, f"https://src-{i}-{tag}.example/", source=f"feed-{tag}")
        _site(db_manager, f"https://nosrc-{tag}.example/", source=None)

        resp = client.get("/api/v1/sites/sources", headers=headers)

        assert resp.status_code == 200
        body = resp.get_json()
        assert {"source": f"feed-{tag}", "count": 2} in body
        assert {"source": None, "count": null_before + 1} in body
        assert all(set(entry) == {"source", "count"} for entry in body)
        counts = [entry["count"] for entry in body]
        assert counts == sorted(counts, reverse=True)

    def test_requires_read_scope(self, pg_api):
        client, _, _ = pg_api

        assert client.get("/api/v1/sites/sources").status_code == 401
