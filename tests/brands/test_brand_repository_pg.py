"""Brand catalogue repository on real PostgreSQL (migration 007)."""

import io

import pytest
from PIL import Image, ImageDraw
from sqlalchemy import text

from src.brands import current_catalog
from src.brands.repository import (
    BrandConflictError,
    BrandNotFoundError,
    BrandRepository,
    BrandValidationError,
    validate_brand,
)
from src.detection.normalize import normalize_host


def _png(color="red", size=(64, 64)) -> bytes:
    image = Image.new("RGB", size, "white")
    ImageDraw.Draw(image).ellipse((6, 6, size[0] - 6, size[1] - 6), fill=color)
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


BODY = {
    "slug": "acme-bank",
    "name": "ACME Bank",
    "category": "bank",
    "country": "CO",
    "priority": 1,
    "aliases": ["ACMEonline", "acmeonline"],
    "domains": [
        "https://www.AcmeBank-Demo.com/",
        {
            "domain": "login.acmebank-secure-demo.com",
            "kind": "login",
            "login_url": "https://login.acmebank-secure-demo.com/signin",
        },
    ],
    "lure_keywords": {"es": ["Clave Dinámica"], "en": ["verify"]},
    "takedown_preferences": {"contact": "abuse@acmebank-demo.com"},
}


class TestValidation:
    def test_the_body_is_normalised(self):
        cleaned = validate_brand(BODY)

        assert cleaned["aliases"] == ["acmeonline"]
        assert cleaned["domains"][0] == {
            "domain": "acmebank-demo.com",
            "kind": "official",
            "login_url": None,
        }
        assert cleaned["domains"][1]["domain"] == "login.acmebank-secure-demo.com"
        assert cleaned["lure_keywords"] == {"es": ["clave dinámica"], "en": ["verify"]}

    @pytest.mark.parametrize(
        "change, field",
        [
            ({"slug": "Bad Slug"}, "slug"),
            ({"name": ""}, "name"),
            ({"priority": 9}, "priority"),
            ({"priority": True}, "priority"),
            ({"aliases": "x"}, "aliases"),
            ({"domains": ["203.0.113.5"]}, "domains"),
            ({"domains": [{"domain": "a-demo.com", "kind": "nope"}]}, "domains"),
            (
                {
                    "domains": [
                        {"domain": "a-demo.com", "kind": "login", "login_url": "javascript:x"}
                    ]
                },
                "domains.login_url",
            ),
            ({"lure_keywords": {"fr": ["x"]}}, "lure_keywords"),
            ({"takedown_preferences": ["x"]}, "takedown_preferences"),
        ],
    )
    def test_invalid_fields_are_named(self, change, field):
        with pytest.raises(BrandValidationError) as error:
            validate_brand({**BODY, **change})

        assert error.value.field == field

    def test_patch_cannot_change_the_slug(self):
        with pytest.raises(BrandValidationError) as error:
            validate_brand({"slug": "other"}, partial=True)

        assert error.value.field == "slug"


class TestRepository:
    def test_the_catalogue_starts_empty(self, engine):
        assert BrandRepository(engine).list() == ([], 0)

    def test_create_get_and_list(self, engine):
        repo = BrandRepository(engine)

        created = repo.create(BODY)
        fetched = repo.get("acme-bank")
        items, total = repo.list(search="acmebank")

        assert created.slug == fetched.slug == "acme-bank" and fetched.priority == 1
        assert [d["domain"] for d in fetched.domains] == [
            "acmebank-demo.com",
            "login.acmebank-secure-demo.com",
        ]
        assert total == 1 and items[0].name == "ACME Bank"
        assert repo.list(search="nothing-like-it") == ([], 0)

    def test_slugs_and_domains_are_unique(self, engine):
        repo = BrandRepository(engine)
        repo.create(BODY)

        with pytest.raises(BrandConflictError):
            repo.create(BODY)
        with pytest.raises(BrandConflictError, match="already belongs to brand acme-bank"):
            repo.create({"slug": "copycat", "name": "Copycat", "domains": ["acmebank-demo.com"]})

    def test_update_replaces_fields_and_domains(self, engine):
        repo = BrandRepository(engine)
        repo.create(BODY)

        updated = repo.update(
            "acme-bank", {"priority": 2, "domains": ["acme-demo.com"], "aliases": []}
        )

        assert updated.priority == 2 and updated.aliases == []
        assert [d["domain"] for d in updated.domains] == ["acme-demo.com"]
        with pytest.raises(BrandNotFoundError):
            repo.update("missing", {"priority": 2})

    def test_deactivated_brands_leave_detection_but_stay_listed_on_request(self, engine):
        repo = BrandRepository(engine)
        repo.create(BODY)

        repo.deactivate("acme-bank")

        assert repo.list() == ([], 0)
        assert repo.list(include_inactive=True)[1] == 1
        assert repo.active_brands() == []
        assert repo.update("acme-bank", {"active": True}).active

    def test_reference_images_keep_hashes_only(self, engine):
        repo = BrandRepository(engine)
        repo.create(BODY)

        favicon = repo.add_asset(
            "acme-bank", "favicon", _png("red"), "https://acmebank-demo.com/f.ico"
        )
        logo = repo.add_asset("acme-bank", "logo", _png("blue", (120, 40)))

        assert favicon["mmh3"] is not None and logo["mmh3"] is None
        assert len(favicon["phash"]) == 16 and logo["width"] == 120
        with pytest.raises(BrandConflictError):
            repo.add_asset("acme-bank", "favicon", _png("red"))
        with pytest.raises(BrandValidationError):
            repo.add_asset("acme-bank", "banner", _png())
        with pytest.raises(BrandValidationError):
            repo.add_asset("acme-bank", "logo", b"not an image")
        with pytest.raises(BrandNotFoundError):
            repo.add_asset("missing", "logo", _png())

        repo.delete_asset("acme-bank", favicon["id"])
        assert [a["kind"] for a in repo.get("acme-bank").assets] == ["logo"]
        with pytest.raises(BrandNotFoundError):
            repo.delete_asset("acme-bank", favicon["id"])

    def test_console_brands_reach_the_detection_catalogue(self, engine):
        BrandRepository(engine).create(BODY)

        catalogue = current_catalog(engine=engine)

        assert (
            catalogue.official_brand(normalize_host("https://www.acmebank-demo.com/"))
            == "acme-bank"
        )
        assert (
            catalogue.match(normalize_host("https://acmeonline-verify.net/"))[0].brand
            == "acme-bank"
        )
        # Built-in brands are still there.
        assert catalogue.official_brand(normalize_host("https://www.paypal.com/")) == "paypal"

    def test_deleting_a_brand_row_cascades(self, engine):
        repo = BrandRepository(engine)
        repo.create(BODY)
        repo.add_asset("acme-bank", "logo", _png())
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM brands WHERE slug = 'acme-bank'"))
            leftovers = conn.execute(
                text(
                    "SELECT (SELECT COUNT(*) FROM brand_domains) + (SELECT COUNT(*) FROM brand_assets)"
                )
            ).scalar_one()

        assert leftovers == 0
