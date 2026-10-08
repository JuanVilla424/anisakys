"""Brand catalogue through the API (/api/v1/brands), on real PostgreSQL."""

import hashlib
import io
from contextlib import contextmanager
from typing import Iterator
from unittest.mock import patch

import pytest
from PIL import Image, ImageDraw
from sqlalchemy import text

DB_KEY = "ank_brands-api-tests"
DB_HEADERS = {"Authorization": f"Bearer {DB_KEY}"}
BRAND = {
    "slug": "acme-bank",
    "name": "ACME Bank",
    "priority": 1,
    "aliases": ["acmeonline"],
    "domains": ["acmebank-demo.com"],
}


@contextmanager
def key_with(scopes: str) -> Iterator[None]:
    """Authenticate DB_KEY as a database key holding ``scopes``."""
    row = {
        "scopes": scopes,
        "allowed_ips": None,
        "key_hash": hashlib.sha256(DB_KEY.encode()).hexdigest(),
        "name": "brands-key",
        "key_prefix": "ank_brand",
    }
    with (
        patch("src.auth._lookup_db_key", return_value=row),
        patch("src.auth._update_last_used"),
    ):
        yield


def _png(color: str = "red") -> bytes:
    image = Image.new("RGB", (48, 48), "white")
    ImageDraw.Draw(image).ellipse((4, 4, 44, 44), fill=color)
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


@pytest.fixture
def api(pg_api):
    """The test client with an empty catalogue (the schema is shared by the module)."""
    client, db_manager, headers = pg_api
    with db_manager.engine.begin() as conn:
        conn.execute(text("TRUNCATE brands, brand_domains, brand_assets RESTART IDENTITY CASCADE"))
    return client, headers


class TestCatalogue:
    def test_the_catalogue_is_empty_until_someone_adds_a_brand(self, api):
        client, headers = api

        response = client.get("/api/v1/brands", headers=headers)

        assert response.status_code == 200
        assert response.get_json() == {"items": [], "total": 0, "limit": 50, "offset": 0}

    def test_create_read_update_and_deactivate(self, api):
        client, headers = api

        created = client.post("/api/v1/brands", json=BRAND, headers=headers)
        assert created.status_code == 201
        assert created.get_json()["domains"] == [
            {"domain": "acmebank-demo.com", "kind": "official", "login_url": None}
        ]
        assert client.get("/api/v1/brands/acme-bank", headers=headers).get_json()["priority"] == 1

        patched = client.patch("/api/v1/brands/acme-bank", json={"priority": 2}, headers=headers)
        assert patched.status_code == 200 and patched.get_json()["priority"] == 2

        listed = client.get("/api/v1/brands?search=acmebank", headers=headers).get_json()
        assert listed["total"] == 1 and listed["items"][0]["slug"] == "acme-bank"

        gone = client.delete("/api/v1/brands/acme-bank", headers=headers)
        assert gone.status_code == 200 and gone.get_json()["active"] is False
        assert client.get("/api/v1/brands", headers=headers).get_json()["total"] == 0
        assert (
            client.get("/api/v1/brands?include_inactive=true", headers=headers).get_json()["total"]
            == 1
        )

    def test_errors(self, api):
        client, headers = api
        client.post("/api/v1/brands", json=BRAND, headers=headers)

        invalid = client.post("/api/v1/brands", json={**BRAND, "slug": "Bad Slug"}, headers=headers)
        duplicate = client.post("/api/v1/brands", json=BRAND, headers=headers)
        missing = client.get("/api/v1/brands/nope", headers=headers)
        no_body = client.patch("/api/v1/brands/acme-bank", data="x", headers=headers)

        assert invalid.status_code == 400 and invalid.get_json()["parameter"] == "slug"
        assert duplicate.status_code == 409
        assert missing.status_code == 404
        assert no_body.status_code == 400

    def test_reading_needs_read_and_changing_needs_write(self, api):
        client, _ = api
        with key_with("read"):
            assert client.get("/api/v1/brands", headers=DB_HEADERS).status_code == 200
            assert client.post("/api/v1/brands", json=BRAND, headers=DB_HEADERS).status_code == 403
        with key_with("read,write"):
            assert client.post("/api/v1/brands", json=BRAND, headers=DB_HEADERS).status_code == 201


class TestAssets:
    def test_upload_and_delete_a_reference_favicon(self, api):
        client, headers = api
        client.post("/api/v1/brands", json=BRAND, headers=headers)

        uploaded = client.post(
            "/api/v1/brands/acme-bank/assets",
            data={"kind": "favicon", "file": (io.BytesIO(_png()), "favicon.png")},
            headers=headers,
            content_type="multipart/form-data",
        )
        assert uploaded.status_code == 201
        asset = uploaded.get_json()
        assert (
            asset["kind"] == "favicon" and asset["mmh3"] is not None and len(asset["phash"]) == 16
        )

        again = client.post(
            "/api/v1/brands/acme-bank/assets",
            data={"kind": "favicon", "file": (io.BytesIO(_png()), "favicon.png")},
            headers=headers,
            content_type="multipart/form-data",
        )
        assert again.status_code == 409

        deleted = client.delete(f"/api/v1/brands/acme-bank/assets/{asset['id']}", headers=headers)
        assert deleted.status_code == 204
        assert client.get("/api/v1/brands/acme-bank", headers=headers).get_json()["assets"] == []

    def test_bad_uploads_are_rejected(self, api):
        client, headers = api
        client.post("/api/v1/brands", json=BRAND, headers=headers)

        no_file = client.post(
            "/api/v1/brands/acme-bank/assets",
            data={"kind": "logo"},
            headers=headers,
            content_type="multipart/form-data",
        )
        not_image = client.post(
            "/api/v1/brands/acme-bank/assets",
            data={"kind": "logo", "file": (io.BytesIO(b"<svg onload=alert(1)>"), "x.svg")},
            headers=headers,
            content_type="multipart/form-data",
        )
        unknown = client.post(
            "/api/v1/brands/nope/assets",
            data={"kind": "logo", "file": (io.BytesIO(_png()), "logo.png")},
            headers=headers,
            content_type="multipart/form-data",
        )

        assert no_file.status_code == 400 and no_file.get_json()["parameter"] == "file"
        assert not_image.status_code == 400
        assert unknown.status_code == 404
