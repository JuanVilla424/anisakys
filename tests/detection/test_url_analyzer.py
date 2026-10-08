"""Lexical URL analysis on the brand catalogue (src/detection/url_analyzer.py)."""

import pytest

from src.brands.catalog import builtin_brands
from src.detection.normalize import BrandCatalog
from src.detection.url_analyzer import URLAnalyzer


@pytest.fixture(scope="module")
def analyzer() -> URLAnalyzer:
    return URLAnalyzer(catalog=BrandCatalog(builtin_brands()))


class TestBrandImpersonation:
    def test_an_official_domain_is_never_impersonation(self, analyzer):
        result = analyzer.analyze("https://www.paypal.com/signin")

        assert result["official_brand"] == "paypal"
        assert not result["combo_squatting"]["detected"]
        assert not result["tld_swap"]["detected"]

    def test_the_brand_plus_other_words_is_combo_squatting(self, analyzer):
        result = analyzer.analyze("https://paypal-verificacion.com/login")

        assert result["combo_squatting"] == {
            "detected": True,
            "target_brand": "paypal",
            "combo_pattern": "[BRAND]-verificacion",
        }
        assert not result["tld_swap"]["detected"]
        assert any("Combo-squatting" in f for f in result["risk_factors"])

    @pytest.mark.parametrize(
        "url, brand, suffix",
        [
            ("https://google.com.pe/", "google", "com.pe"),
            ("https://amazon.fr/", "amazon", "fr"),
            ("https://bancolombia.co/", "bancolombia", "co"),
        ],
    )
    def test_the_exact_name_under_another_suffix_is_a_tld_swap(self, analyzer, url, brand, suffix):
        result = analyzer.analyze(url)

        assert result["tld_swap"] == {"detected": True, "target_brand": brand, "suffix": suffix}
        assert not result["combo_squatting"]["detected"]
        assert f"Brand name '{brand}' under another suffix (.{suffix})" in result["risk_factors"]
        assert result["risk_score"] >= 20

    def test_a_brand_inside_an_unrelated_word_is_nothing(self, analyzer):
        result = analyzer.analyze("https://meridian-shop.com/")

        assert not result["combo_squatting"]["detected"]
        assert not result["tld_swap"]["detected"]
        assert not result["typosquatting"]["detected"]

    def test_lookalikes(self, analyzer):
        typo = analyzer.analyze("https://paypa1.com/")
        idn = analyzer.analyze("https://раураl.com/")

        assert typo["typosquatting"]["detected"]
        assert typo["typosquatting"]["target_brand"] == "paypal"
        assert idn["homoglyphs"]["detected"]

    def test_an_unparseable_url_is_an_empty_analysis(self, analyzer):
        result = analyzer.analyze("not a url at all")

        assert result["risk_score"] == 0
