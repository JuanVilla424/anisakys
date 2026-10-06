"""Host normalisation and token-boundary brand matching (src/detection/normalize.py)."""

import json

import pytest

from src.detection import normalize
from src.detection.normalize import (
    Brand,
    BrandCatalog,
    Host,
    host_of,
    normalize_host,
    saas_platform,
    skeleton,
    tld_abuse,
)

CATALOG = BrandCatalog(
    [
        Brand("paypal", "PayPal", (), ("paypal.com", "paypal.me")),
        Brand("microsoft", "Microsoft", (), ("microsoft.com", "live.com")),
        Brand("dian", "DIAN", (), ("dian.gov.co",)),
        Brand("bancolombia", "Bancolombia", (), ("bancolombia.com", "bancolombia.com.co")),
        Brand("google", "Google", (), ("google.com", "googleblog.com", "googledomains.com")),
    ]
)


def _host(url: str) -> Host:
    host = normalize_host(url)
    assert host is not None
    return host


class TestHosts:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("https://user:pw@Login.PayPal.com:8443/x?y=1", "login.paypal.com"),
            ("login.paypal.com/path", "login.paypal.com"),
            ("abuse@Example.COM", "example.com"),
            ("example.com.", "example.com"),
            ("", ""),
            ("http://[::1]/", "::1"),
        ],
    )
    def test_host_of(self, raw, expected):
        assert host_of(raw) == expected

    def test_registrable_domain_uses_the_private_public_suffixes(self):
        assert _host("https://shop.vercel.app/login").registrable == "shop.vercel.app"
        assert _host("a.b.bancolombia.com.co").registrable == "bancolombia.com.co"
        assert _host("a.b.bancolombia.com.co").subdomain == "a.b"

    def test_unicode_hosts_are_punycode_and_flagged(self):
        host = _host("https://раураl.com/")

        assert host.ascii.startswith("xn--") and host.is_idn
        assert host.unicode == "раураl.com"
        assert host.segments == ("раураl",)

    def test_ip_addresses_are_their_own_registrable(self):
        host = _host("http://203.0.113.9/login")

        assert host.is_ip and host.registrable == "203.0.113.9" and host.segments == ()

    def test_no_host_is_none(self):
        assert normalize_host("") is None
        assert normalize_host("https:///nohost") is None


class TestSkeleton:
    def test_look_alikes_share_a_skeleton(self):
        assert skeleton("rnicrosoft") == skeleton("microsoft")
        assert skeleton("раураl") == skeleton("paypal")  # Cyrillic р, а, у
        assert skeleton("paypa1") == skeleton("paypal")

    def test_different_words_do_not(self):
        assert skeleton("meridian") != skeleton("dian")


class TestBrandMatching:
    @pytest.mark.parametrize(
        "url, brand, kind",
        [
            ("https://paypal.xyz/", "paypal", "brand_label"),
            ("https://paypal-secure.com/", "paypal", "combo"),
            ("https://securepaypal.com/", "paypal", "combo"),
            ("https://bancolombia.com.co.verify-now.com/", "bancolombia", "combo"),
            ("https://dian-pagos.com/", "dian", "combo"),
            ("https://paypa1.com/", "paypal", "homoglyph"),
            ("https://rnicrosoft.com/", "microsoft", "homoglyph"),
            ("https://раураl.com/", "paypal", "homoglyph"),
            ("https://paypall.com/", "paypal", "typo"),
            ("https://bancolonbia.co/", "bancolombia", "typo"),
        ],
    )
    def test_impersonation_is_detected(self, url, brand, kind):
        matches = CATALOG.match(normalize_host(url))

        assert matches and (matches[0].brand, matches[0].kind) == (brand, kind)

    @pytest.mark.parametrize(
        "url",
        [
            # The phase 1 false positives: a short alias inside a word, official sister domains.
            "https://meridian-shop.example/login",
            "https://googleblog.com/",
            "https://googledomains.com/",
            "https://www.paypal.com/signin",
            "https://login.live.com/",
            "https://example.com/",
        ],
    )
    def test_no_false_impersonation(self, url):
        assert CATALOG.match(normalize_host(url)) == []

    def test_official_domains_come_first(self):
        assert CATALOG.official_brand(normalize_host("https://m.paypal.me/x")) == "paypal"
        assert CATALOG.official_brand(normalize_host("https://googleblog.com/")) == "google"
        assert CATALOG.official_brand(normalize_host("https://paypal-secure.com/")) is None
        assert CATALOG.official_domains("paypal") == ["paypal.com", "paypal.me"]

    def test_the_builtin_catalogue_loads(self):
        catalog = BrandCatalog.from_known_brands()

        assert catalog.official_brand(normalize_host("https://nequi.com.co/")) == "nequi"
        assert catalog.match(normalize_host("https://nequi-pagos.com/"))[0].brand == "nequi"


class TestContext:
    @pytest.mark.parametrize(
        "url, kind",
        [
            ("https://evil-login.vercel.app/", "hosting"),
            ("https://docs.google.com/forms/d/x", "forms"),
            ("https://bucket.s3.amazonaws.com/a.html", "storage"),
            ("https://bit.ly/abc", "shortener"),
            ("https://example.com/", None),
        ],
    )
    def test_saas_platforms(self, url, kind):
        assert saas_platform(normalize_host(url)) == kind

    def test_tld_abuse_reads_the_generated_table(self, tmp_path, monkeypatch):
        table = tmp_path / "tld_abuse.json"
        table.write_text(json.dumps({"tlds": {"xyz": {"log_odds": 1.5}}}), encoding="utf-8")
        monkeypatch.setattr(normalize, "TLD_ABUSE_FILE", table)
        normalize._tld_abuse.cache_clear()
        try:
            assert tld_abuse(normalize_host("https://paypal.xyz/")) == 1.5
            assert tld_abuse(normalize_host("https://paypal.com/")) is None
        finally:
            normalize._tld_abuse.cache_clear()
