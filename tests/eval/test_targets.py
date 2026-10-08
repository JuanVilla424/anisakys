"""Quality targets (eval/targets.json): met, missed or not resolvable — never met by default."""

from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from src.eval.dataset import make_sample
from src.eval.metrics import rates
from src.eval.predictors import Prediction, ordinal_score
from src.eval.report import build_report, render_html
from src.eval.targets import check_detection, check_pipeline, load_targets

TARGETS: Dict[str, Any] = {
    "operating_point": "auto_report",
    "detection": {"precision": {"min": 0.95}, "recall": {"min": 0.8}, "fpr": {"max": 0.001}},
    "min_positives": 10,
    "min_predicted_positives": 10,
    "brand_overrides": {"bancolombia": {"recall": {"min": 0.9}}},
    "pipeline_hours": {
        "time_to_detect": {"max_median": 24},
        "time_to_report": {"max_median": 1},
    },
    "min_pipeline_events": 5,
}


def _counts(tp: int, fp: int, fn: int, tn: int) -> Dict[str, Any]:
    counts = {"tp": tp, "fp": fp, "fn": fn, "tn": tn}
    return {"samples": tp + fp + fn + tn, **counts, **rates(counts)}


def _point(tp: int, fp: int, fn: int, tn: int, per_brand: Optional[Dict[str, Any]] = None):
    return {**_counts(tp, fp, fn, tn), "per_brand": per_brand or {}}


def _statuses(result: Dict[str, Any]) -> Dict[str, str]:
    return {metric: r["status"] for metric, r in result["targets"].items()}


class TestDetectionTargets:
    def test_met_and_missed(self):
        met = check_detection(_point(19, 1, 1, 1999), TARGETS)
        missed = check_detection(_point(10, 5, 10, 1995), TARGETS)

        assert _statuses(met["overall"]) == {"precision": "met", "recall": "met", "fpr": "met"}
        assert _statuses(missed["overall"]) == {
            "precision": "missed",
            "recall": "missed",
            "fpr": "missed",
        }
        assert missed["overall"]["summary"] == {"met": 0, "missed": 3, "not_resolvable": 0}

    def test_too_little_data_is_not_resolvable_never_met(self):
        # The phase 1 baseline at level >= high: 4 TP, 2 FP, 23 FN, 109 TN.
        result = check_detection(_point(4, 2, 23, 109), TARGETS)["overall"]

        assert result["targets"]["precision"]["reason"] == "needs >= 10 flagged, has 6"
        assert result["targets"]["recall"]["status"] == "missed"  # 27 positives are enough
        assert result["targets"]["fpr"]["reason"] == "needs >= 1000 negatives, has 111"
        assert result["summary"] == {"met": 0, "missed": 1, "not_resolvable": 2}

    def test_every_brand_is_judged_with_its_overrides_and_unknown_is_skipped(self):
        per_brand = {
            "unknown": _counts(5, 0, 5, 50),
            "bancolombia": _counts(
                17, 0, 3, 0
            ),  # recall 0.85: default 0.8 met, override 0.9 missed
            "paypal": _counts(1, 0, 0, 2),
        }

        result = check_detection(_point(23, 0, 8, 52, per_brand), TARGETS)

        assert set(result["brands"]) == {"bancolombia", "paypal"}
        recall = result["brands"]["bancolombia"]["targets"]["recall"]
        assert (recall["status"], recall["target"]) == ("missed", {"min": 0.9})
        assert _statuses(result["brands"]["paypal"]) == {
            "precision": "not_resolvable",
            "recall": "not_resolvable",
            "fpr": "not_resolvable",
        }
        assert result["summary"] == {
            "brands": 2,
            "brands_fully_resolvable": 0,
            "brands_meeting_all": 0,
        }


class TestPipelineTargets:
    def test_medians_need_enough_events(self):
        result = check_pipeline(
            {
                "time_to_detect": {"count": 16, "median": 18.0},
                "time_to_report": {"count": 3, "median": 0.5},
            },
            TARGETS,
        )

        assert _statuses(result) == {"time_to_detect": "met", "time_to_report": "not_resolvable"}
        assert result["targets"]["time_to_report"]["reason"] == "needs >= 5 events, has 3"

    def test_a_slow_median_is_missed(self):
        result = check_pipeline({"time_to_detect": {"count": 6, "median": 30.0}}, TARGETS)

        assert result["targets"]["time_to_detect"]["status"] == "missed"
        assert result["targets"]["time_to_report"]["status"] == "not_resolvable"


class TestTargetsFile:
    def test_the_repository_targets_load(self):
        targets = load_targets(Path(__file__).resolve().parents[2] / "eval" / "targets.json")

        assert targets["operating_point"] == "auto_report"
        assert targets["detection"] == {
            "precision": {"min": 0.95},
            "recall": {"min": 0.8},
            "fpr": {"max": 0.001},
        }
        assert targets["pipeline_hours"]["time_to_report"] == {"max_median": 1}

    def test_a_file_without_targets_is_rejected(self, tmp_path):
        path = tmp_path / "targets.json"
        path.write_text('{"operating_point": "auto_report"}', encoding="utf-8")

        with pytest.raises(ValueError, match="no detection or pipeline targets"):
            load_targets(path)


def _report(targets: Dict[str, Any]) -> Dict[str, Any]:
    rows = [
        ("https://bancolombia-clave.example/", "phishing", 90),  # flagged at auto_report
        ("https://nequi-pagos.example/", "phishing", 70),  # level high, confidence too low
        ("https://www.phase.com/", "homonym", 95),  # benign, flagged
    ]
    samples, predictions = [], []
    for url, category, confidence in rows:
        sample = make_sample(
            url, "feed_live_verified" if category == "phishing" else category, "test"
        )
        assert sample is not None
        samples.append(sample)
        predictions.append(
            Prediction(
                sample_id=sample.id,
                level="high",
                confidence=confidence,
                score=ordinal_score("high", confidence),
            )
        )
    manifest = {"name": "unit", "version": "v1", "samples_sha256": "0" * 64}
    return build_report(
        manifest,
        "test",
        "stored",
        samples,
        predictions,
        targets=targets,
        auto_report_min_confidence=85,
    )


class TestReportTargets:
    def test_the_auto_report_point_needs_the_confidence_threshold(self):
        report = _report(TARGETS)

        point = report["verdicts"]["deployed"]["operating_points"]["auto_report"]
        assert (point["tp"], point["fn"], point["fp"]) == (1, 1, 1)
        high = report["verdicts"]["deployed"]["operating_points"]["level>=high"]
        assert (high["tp"], high["fn"]) == (2, 0)
        assert report["auto_report_rule"]["min_confidence"] == 85
        assert report["targets"]["operating_point"] == "auto_report"
        assert report["targets"]["overall"]["summary"]["not_resolvable"] == 3

    def test_the_page_shows_the_targets(self):
        page = render_html(_report(TARGETS))

        assert "Targets — deployed, auto_report" in page
        assert "not resolvable (needs &gt;= 10 flagged, has 2)" in page

    def test_an_unknown_operating_point_is_rejected(self):
        with pytest.raises(ValueError, match="unknown operating point 'nope'"):
            _report({**TARGETS, "operating_point": "nope"})
