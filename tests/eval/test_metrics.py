"""Detection-quality metrics (src/eval/metrics.py), checked against hand-computed values."""

import pytest

from src.eval.metrics import (
    average_precision,
    calibration,
    confusion,
    grouped,
    latency_summary,
    pr_curve,
    precision_at_k,
    rates,
    roc_points,
    tpr_at_fpr,
)


class TestConfusionAndRates:
    def test_counts_and_rates(self):
        counts = confusion([1, 1, 0, 0, 1], [1, 0, 1, 0, 1])

        assert counts == {"tp": 2, "fp": 1, "fn": 1, "tn": 1}
        assert rates(counts) == {
            "precision": round(2 / 3, 4),
            "recall": round(2 / 3, 4),
            "f1": round(2 / 3, 4),
            "fpr": 0.5,
            "accuracy": 0.6,
        }

    def test_undefined_rates_are_none_not_invented(self):
        nothing_flagged = rates(confusion([1, 0], [0, 0]))
        no_positives = rates(confusion([0, 0], [1, 0]))

        assert nothing_flagged["precision"] is None
        assert nothing_flagged["recall"] == 0.0
        assert nothing_flagged["f1"] == 0.0
        assert no_positives["recall"] is None
        assert no_positives["f1"] is None

    def test_length_mismatch_is_an_error(self):
        with pytest.raises(ValueError):
            confusion([1], [1, 0])


class TestRanking:
    Y = [1, 0, 1, 1, 0]
    S = [0.9, 0.8, 0.7, 0.6, 0.5]

    def test_average_precision_matches_the_step_definition(self):
        # thresholds: P=1 at R=1/3, P=2/3 at R=2/3, P=3/4 at R=1
        expected = (1 / 3) * 1 + (1 / 3) * (2 / 3) + (1 / 3) * (3 / 4)
        assert average_precision(self.Y, self.S) == round(expected, 4)

    def test_ties_form_one_threshold(self):
        curve = pr_curve([1, 0, 1], [0.5, 0.5, 0.1])

        assert curve[0] == {"threshold": 0.5, "precision": 0.5, "recall": 0.5}
        assert len(curve) == 2

    def test_no_positives_gives_no_curve(self):
        assert pr_curve([0, 0], [0.4, 0.3]) == []
        assert average_precision([0, 0], [0.4, 0.3]) is None

    def test_roc_points_need_both_classes(self):
        assert roc_points([1, 1], [0.2, 0.1]) == []
        points = roc_points(self.Y, self.S)
        assert points[-1] == {"threshold": 0.5, "fpr": 1.0, "tpr": 1.0}

    def test_precision_at_k(self):
        assert precision_at_k(self.Y, self.S, 1) == 1.0
        assert precision_at_k(self.Y, self.S, 2) == 0.5
        assert precision_at_k(self.Y, self.S, 10) is None


class TestTprAtFpr:
    def test_best_tpr_within_the_fpr_budget(self):
        y = [1, 1, 0, 1, 0, 0, 0, 0, 0, 0]
        s = [0.95, 0.9, 0.85, 0.8, 0.4, 0.3, 0.2, 0.1, 0.05, 0.01]

        result = tpr_at_fpr(y, s, target_fpr=0.2)

        # 7 negatives: FPR 1/7 at threshold 0.8 still within 0.2; TPR 3/3.
        assert result["tpr"] == 1.0
        assert result["threshold"] == 0.8
        assert result["resolvable"] is True

    def test_too_few_negatives_is_flagged(self):
        result = tpr_at_fpr([1, 0, 0], [0.9, 0.2, 0.1], target_fpr=1e-3)

        assert result["resolvable"] is False
        assert result["negatives"] == 2
        assert result["negatives_needed"] == 1000
        assert result["tpr"] == 1.0  # no false positive at all

    def test_single_class_has_no_tpr(self):
        assert tpr_at_fpr([0, 0], [0.1, 0.2], target_fpr=0.1)["tpr"] is None


class TestCalibration:
    def test_bins_and_expected_calibration_error(self):
        result = calibration([1, 0, 1, 1], [0.95, 0.05, 0.9, 0.15], bins=10)

        top = result["bins"][9]
        assert (top["count"], top["mean_score"], top["positive_rate"]) == (2, 0.925, 1.0)
        bottom = result["bins"][0]
        assert (bottom["count"], bottom["positive_rate"]) == (1, 0.0)
        # |0.925-1|*2 + |0.05-0|*1 + |0.15-1|*1 = 0.15 + 0.05 + 0.85 = 1.05 over 4
        assert result["ece"] == round(1.05 / 4, 4)

    def test_empty_input(self):
        assert calibration([], [])["ece"] is None


def test_grouped_confusion_orders_groups_by_size():
    groups = grouped(["a", "b", None, "a"], [1, 0, 1, 1], [1, 1, 0, 0])

    assert list(groups) == ["a", "b", "unknown"]
    assert groups["a"]["samples"] == 2
    assert (groups["a"]["tp"], groups["a"]["fn"]) == (1, 1)
    assert groups["b"]["fp"] == 1


def test_latency_summary():
    assert latency_summary([]) == {"count": 0, "p50": None, "p95": None, "mean": None}
    summary = latency_summary([10, 20, 30, 40, 1000])
    assert summary["p50"] == 30.0
    assert summary["count"] == 5
    assert summary["p95"] == pytest.approx(808.0, abs=0.1)
