"""Predictors of the evaluation harness (src/eval/predictors.py)."""

from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from src.eval.dataset import make_sample
from src.eval.predictors import (
    Prediction,
    ScanPredictor,
    StoredPredictor,
    level_at_least,
    normalize_level,
    offline_validator,
    ordinal_score,
    prediction_from_scan,
)


def _sample(url: str = "https://scan.example/login", category: str = "feed_live_verified"):
    sample = make_sample(url, category, "test")
    assert sample is not None
    return sample


class TestScore:
    def test_ordering_follows_level_then_confidence(self):
        ladder = [
            ("unknown", 99),
            ("clean", 90),
            ("clean", 10),
            ("low", 50),
            ("medium", 10),
            ("medium", 90),
            ("high", 50),
            ("critical", 99),
        ]
        scores = [ordinal_score(level, confidence) for level, confidence in ladder]

        assert scores == sorted(scores)
        assert scores[0] == 0.0
        assert 0.9 <= scores[-1] <= 1.0

    def test_garbage_is_unknown(self):
        assert normalize_level("SEVERE") == "unknown"
        assert normalize_level(None) == "unknown"
        assert ordinal_score("high", "lots") == 0.7

    def test_operating_points(self):
        assert level_at_least("critical", "high")
        assert level_at_least("medium", "medium")
        assert not level_at_least("medium", "high")
        assert not level_at_least("unknown", "low")


def test_prediction_keeps_the_deployed_verdict_and_recomputes_the_heuristic_one():
    scan: Dict[str, Any] = {
        "aggregated_threat_level": "unknown",  # no provider answered
        "confidence_score": 0,
        "virustotal": {"status": "no_data"},
        "urlvoid": {"status": "no_data"},
        "phishtank": {"status": "no_data"},
        "google_safe_browsing": {"status": "no_data"},
        "whois": {"domain_age_days": 2},
        "url_analysis": {"risk_score": 80, "typosquatting": {"detected": True}},
        "kit_fingerprint": {},
        "stage_timings_ms": {"url_analysis": 1.5, "whois": 800},
        "stage_status": {"virustotal_url": "no_data", "whois": "not_listed"},
    }

    prediction = prediction_from_scan("abc", scan)

    assert (prediction.level, prediction.score, prediction.covered) == ("unknown", 0.0, False)
    assert prediction.heuristic_level == "high"  # typosquatting forces high
    assert prediction.heuristic_score >= 0.7
    assert prediction.stage_timings_ms == {"url_analysis": 1.5, "whois": 800.0}
    assert prediction.stage_status["whois"] == "not_listed"


class _FakeValidator:
    def __init__(self, calls: List[str], fail_on: str = ""):
        self.calls = calls
        self.fail_on = fail_on

    def comprehensive_scan(self, url: str) -> Dict[str, Any]:
        self.calls.append(url)
        if self.fail_on and self.fail_on in url:
            raise RuntimeError("provider exploded token=secret123")
        return {
            "aggregated_threat_level": "high",
            "confidence_score": 80,
            "stage_timings_ms": {"virustotal_url": 120.0},
            "stage_status": {"virustotal_url": "listed"},
        }


class TestScanPredictor:
    def test_scans_caches_and_resumes(self, tmp_path):
        calls: List[str] = []
        samples = [_sample(f"https://s{i}.example/") for i in range(3)]
        cache = tmp_path / "cache.jsonl"
        progress: List[tuple] = []

        first = ScanPredictor(
            "live",
            lambda: _FakeValidator(calls),
            cache_path=cache,
            progress=lambda done, total: progress.append((done, total)),
        ).predict(samples)
        second = ScanPredictor("live", lambda: _FakeValidator(calls), cache_path=cache).predict(
            samples
        )

        assert [p.level for p in first] == ["high", "high", "high"]
        assert [p.sample_id for p in second] == [s.id for s in samples]
        assert len(calls) == 3  # the second run read everything from the cache
        assert progress[-1] == (3, 3)

    def test_failures_become_unknown_with_a_sanitised_error(self):
        calls: List[str] = []
        samples = [_sample("https://ok.example/"), _sample("https://boom.example/")]

        predictions = ScanPredictor("live", lambda: _FakeValidator(calls, "boom")).predict(samples)

        failed = next(p for p in predictions if p.sample_id == samples[1].id)
        assert failed.level == "unknown"
        assert failed.error is not None
        assert "secret123" not in failed.error

    def test_max_scans_bounds_a_run(self):
        calls: List[str] = []
        samples = [_sample(f"https://m{i}.example/") for i in range(5)]

        predictions = ScanPredictor("live", lambda: _FakeValidator(calls), max_scans=2).predict(
            samples
        )

        assert len(predictions) == 2
        assert len(calls) == 2


def test_offline_validator_disables_every_threat_intel_provider():
    validator = offline_validator()

    for provider in ("virustotal", "urlvoid", "phishtank", "google_safe_browsing"):
        client = getattr(validator, provider)
        assert client.scan_url("https://x.example/")["status"] == "no_data"
        assert client.check_url("https://x.example/")["status"] == "no_data"


def test_stored_predictor_uses_the_label_snapshot():
    sample = _sample("https://stored.example/login", category="analyst_confirmed")
    other = _sample("https://never-labelled.example/", category="analyst_confirmed")

    class _Label:
        url = "https://stored.example/login?session=1"
        detector_snapshot = {"multi_api_threat_level": "critical", "api_confidence_score": 95}

    with patch("src.labels.LabelRepository.latest_per_url", return_value=[_Label()]):
        predictions = StoredPredictor(engine=object()).predict([sample, other])

    assert predictions[0].level == "critical"
    assert predictions[0].score == pytest.approx(0.995)
    assert predictions[1].level == "unknown"


def test_prediction_round_trip():
    prediction = Prediction(
        sample_id="x",
        level="medium",
        confidence=60,
        score=0.56,
        heuristic_level="high",
        heuristic_score=0.75,
        stage_timings_ms={"whois": 10.0},
        stage_status={"whois": "not_listed"},
    )

    assert Prediction.from_dict(prediction.to_dict()) == prediction
