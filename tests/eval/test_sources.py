"""Sources of evaluation samples (src/eval/sources.py), without network access."""

import datetime
import json
from typing import Any, Dict, List, Optional
from unittest.mock import patch

from src.eval.dataset import make_sample
from src.eval.sources import (
    Brand,
    analyst_samples,
    infer_brand,
    load_brand_catalog,
    openphish_samples,
    seed_samples,
    tranco_samples,
    verify_live,
)


def _write_seeds(directory):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "official_brands.json").write_text(
        json.dumps(
            {
                "brands": [
                    {
                        "name": "nequi",
                        "aliases": ["nequiapp"],
                        "urls": ["https://www.nequi.com.co/"],
                    },
                    {
                        "name": "simit",
                        "aliases": ["fcm"],
                        "urls": ["https://www.fcm.org.co/simit/"],
                    },
                ]
            }
        )
    )
    (directory / "homonyms.txt").write_text("# comment\nhttps://www.phase.com/\n\nzoom.us\n")
    (directory / "benign_saas.txt").write_text("https://pages.github.com/  # official\n")


class TestCatalog:
    def test_merges_known_brands_with_the_seed_file(self, tmp_path):
        _write_seeds(tmp_path)

        catalog = {brand.name: brand for brand in load_brand_catalog(tmp_path)}

        assert "https://nequi.com/" in catalog["nequi"].urls  # from KNOWN_BRANDS
        assert "https://www.nequi.com.co/" in catalog["nequi"].urls  # from the seed file
        assert "nequiapp" in catalog["nequi"].aliases
        assert catalog["simit"].urls == ("https://www.fcm.org.co/simit/",)
        assert "paypal" in catalog  # every detector brand is present

    def test_infer_brand_matches_host_tokens(self):
        catalog = [Brand("paypal", ("paypal",), ()), Brand("dian", ("dian",), ())]

        assert infer_brand("https://paypal-secure.example/", catalog) == "paypal"
        assert infer_brand("https://securepaypal.example/", catalog) == "paypal"
        assert infer_brand("https://dian.gov.co.example/", catalog) == "dian"
        assert infer_brand("https://weather-report.example/", catalog) is None


class TestSeeds:
    def test_seed_negatives_with_categories(self, tmp_path):
        _write_seeds(tmp_path)

        samples, reports = seed_samples(tmp_path)

        categories = {s.category for s in samples}
        assert categories == {"official_brand", "homonym", "benign_saas"}
        assert all(s.label == "benign" for s in samples)
        assert {r.name for r in reports} == {
            "seeds/official_brands.json",
            "seeds/homonyms.txt",
            "seeds/benign_saas.txt",
        }
        assert any(s.url == "http://zoom.us/" for s in samples)


class TestFeedsAndTranco:
    def test_openphish_samples_are_positives_with_inferred_brands(self):
        catalog = [Brand("netflix", ("netflix",), ())]

        samples, report = openphish_samples(
            catalog,
            fetch=lambda: {
                "https://netflix-billing.example/x?c=1",
                "ftp://bad",
                "https://a.example/",
            },
        )

        assert report.fetched == 3 and report.kept == 2
        by_url = {s.url: s for s in samples}
        assert by_url["https://netflix-billing.example/x"].brand == "netflix"
        assert all(s.category == "feed_live_verified" for s in samples)

    def test_tranco_downloads_once_and_caches(self, tmp_path):
        class _Response:
            def __init__(self, payload: Any = None, body: str = ""):
                self.payload, self.text = payload, body

            def raise_for_status(self) -> None:
                return None

            def json(self) -> Any:
                return self.payload

        class _Session:
            def __init__(self) -> None:
                self.urls: List[str] = []

            def get(self, url: str, timeout: int) -> _Response:
                self.urls.append(url)
                if url.endswith("/latest"):
                    return _Response(payload={"list_id": "ABC12"})
                return _Response(body="1,google.com\n2,youtube.com\n3,facebook.com\n")

        session = _Session()
        samples, report = tranco_samples(2, tmp_path, session=session)  # type: ignore[arg-type]
        again, _ = tranco_samples(2, tmp_path, list_id="ABC12", session=session)  # type: ignore[arg-type]

        assert [s.url for s in samples] == ["https://google.com/", "https://youtube.com/"]
        assert report.fetched == 2
        assert samples[0].extra["rank"] == 1
        assert report.details == {"list_id": "ABC12"}
        assert len(session.urls) == 2  # latest id + one download; the second call hit the cache
        assert [s.url for s in again] == [s.url for s in samples]


class TestVerifyLive:
    def test_positives_need_content_negatives_may_be_challenged(self):
        positive_up = make_sample("https://p-up.example/", "feed_live_verified", "t")
        positive_waf = make_sample("https://p-waf.example/", "feed_live_verified", "t")
        negative_waf = make_sample("https://n-waf.example/", "tranco_top", "t")
        negative_dead = make_sample("https://n-dead.example/", "tranco_top", "t")
        classes = {
            "https://p-up.example/": "up",
            "https://p-waf.example/": "waf_challenge",
            "https://n-waf.example/": "waf_challenge",
            "https://n-dead.example/": "nxdomain",
        }

        def kit(url: str, _timeout: int, _brand: Optional[str]) -> Optional[str]:
            return "evilginx" if "p-up" in url else None

        live, counts = verify_live(
            [s for s in (positive_up, positive_waf, negative_waf, negative_dead) if s],
            probe=lambda url, _timeout: classes[url],
            kit=kit,
        )

        assert {s.url for s in live} == {"https://p-up.example/", "https://n-waf.example/"}
        assert next(s for s in live if s.is_positive).kit == "evilginx"
        assert counts == {"up": 1, "waf_challenge": 2, "nxdomain": 1}

    def test_probe_errors_drop_the_sample(self):
        sample = make_sample("https://err.example/", "homonym", "t")

        def broken(_url: str, _timeout: int) -> str:
            raise RuntimeError("dns down")

        live, counts = verify_live([sample] if sample else [], probe=broken, kit=None)

        assert live == [] and counts == {"probe_error": 1}


def test_analyst_samples_follow_the_latest_label():
    class _Label:
        def __init__(self, url: str, verdict: str, action: str, snapshot: Dict[str, Any]):
            self.id = 7
            self.url = url
            self.verdict = verdict
            self.action = action
            self.brand = "Nequi"
            self.kit = None
            self.detector_snapshot = snapshot
            self.created_at = datetime.datetime(2026, 10, 3, tzinfo=datetime.timezone.utc)

    labels = [
        _Label(
            "https://p.example/", "phishing", "report", {"first_seen": "2026-09-30T00:00:00+00:00"}
        ),
        _Label("https://b.example/", "benign", "dismiss", {}),
    ]
    with patch("src.labels.LabelRepository.latest_per_url", return_value=labels):
        samples, report = analyst_samples(engine=object())

    by_category = {s.category: s for s in samples}
    assert by_category["analyst_confirmed"].first_seen == "2026-09-30T00:00:00+00:00"
    assert by_category["analyst_dismissed"].first_seen.startswith("2026-10-03")
    assert by_category["analyst_confirmed"].extra == {"label_id": 7, "action": "report"}
    assert report.kept == 2
