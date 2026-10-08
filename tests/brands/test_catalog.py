"""Detection catalogue: built-in brands plus console brands, cached, never failing detection."""

from unittest.mock import MagicMock, patch

from src.brands import catalog
from src.brands.catalog import builtin_brands, current_catalog, merge
from src.detection.normalize import Brand, BrandAsset, normalize_host


def test_the_builtin_list_is_known_brands_unchanged():
    from src.detection.url_analyzer import KNOWN_BRANDS

    brands = {b.slug: b for b in builtin_brands()}

    assert set(brands) == set(KNOWN_BRANDS)
    assert brands["nequi"].official_domains == tuple(KNOWN_BRANDS["nequi"])


def test_a_console_brand_extends_the_builtin_one_with_the_same_slug():
    asset = BrandAsset("favicon", 123, "0" * 16, "f" * 16)
    console = [
        Brand(
            "nequi", "Nequi", ("nequiapp",), ("nequi.com.co", "nequi.co"), (asset,), 1, ("clave",)
        ),
        Brand("acme-bank", "ACME Bank", (), ("acmebank.example",)),
    ]

    merged = merge(builtin_brands(), console)

    nequi = merged.get("nequi")
    assert nequi is not None
    assert nequi.official_domains[: len(builtin_brands()[0].official_domains)]  # built-ins kept
    assert "nequi.co" in nequi.official_domains and nequi.aliases == ("nequiapp",)
    assert nequi.assets == (asset,) and nequi.priority == 1
    assert merged.official_brand(normalize_host("https://pay.nequi.co/")) == "nequi"
    assert merged.match(normalize_host("https://nequiapp-login.com/"))[0].brand == "nequi"
    assert merged.get("acme-bank") is not None


def test_the_catalogue_is_cached_and_invalidated():
    repository = MagicMock()
    repository.return_value.active_brands.return_value = []
    with patch("src.brands.repository.BrandRepository", repository):
        first = current_catalog(engine=MagicMock(), now=1000.0)
        second = current_catalog(engine=MagicMock(), now=1030.0)
        assert first is second and repository.call_count == 1

        current_catalog(engine=MagicMock(), now=1000.0 + catalog.CATALOG_TTL_SECONDS + 1)
        assert repository.call_count == 2

        catalog.invalidate()
        current_catalog(engine=MagicMock(), now=2000.0)
        assert repository.call_count == 3


def test_a_database_outage_keeps_the_builtin_brands():
    repository = MagicMock()
    repository.return_value.active_brands.side_effect = OSError("database down")
    with patch("src.brands.repository.BrandRepository", repository):
        catalogue = current_catalog(engine=MagicMock(), now=5000.0)

    assert catalogue.official_brand(normalize_host("https://www.paypal.com/")) == "paypal"
    assert len(catalogue) == len(builtin_brands())
