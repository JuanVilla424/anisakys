"""Detection-quality metrics, in plain Python (no numpy/scikit-learn).

Conventions: ``y_true`` holds 1 for phishing and 0 for benign; ``scores`` are
"higher means more likely phishing"; ``y_pred`` is the 0/1 decision of an
operating point. Every function returns ``None`` (or flags the result) instead of
inventing a number when the data cannot support it, e.g. a precision with no
predicted positives or a TPR at FPR 1e-4 measured on 300 negatives.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Sequence, Tuple


def confusion(y_true: Sequence[int], y_pred: Sequence[int]) -> Dict[str, int]:
    """Count true/false positives/negatives.

    Args:
        y_true: Ground truth (1 = phishing).
        y_pred: Decisions (1 = flagged).

    Returns:
        ``{"tp", "fp", "fn", "tn"}``.

    Raises:
        ValueError: If the sequences differ in length.
    """
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred differ in length")
    tp = fp = fn = tn = 0
    for truth, pred in zip(y_true, y_pred):
        if truth and pred:
            tp += 1
        elif pred:
            fp += 1
        elif truth:
            fn += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def _safe_div(numerator: float, denominator: float) -> Optional[float]:
    """Divide, or return ``None`` for a zero denominator.

    Args:
        numerator: Numerator.
        denominator: Denominator.

    Returns:
        The rounded quotient or ``None``.
    """
    return round(numerator / denominator, 4) if denominator else None


def rates(counts: Dict[str, int]) -> Dict[str, Optional[float]]:
    """Precision, recall, F1, FPR and accuracy of a confusion matrix.

    Args:
        counts: Output of :func:`confusion`.

    Returns:
        ``{"precision", "recall", "f1", "fpr", "accuracy"}`` (``None`` when
        undefined).
    """
    tp, fp, fn, tn = counts["tp"], counts["fp"], counts["fn"], counts["tn"]
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1: Optional[float]
    if precision is not None and recall is not None:
        f1 = round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0
    elif recall == 0:
        f1 = 0.0  # positives exist and nothing was flagged
    else:
        f1 = None
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": _safe_div(fp, fp + tn),
        "accuracy": _safe_div(tp + tn, tp + fp + fn + tn),
    }


def _ranked(y_true: Sequence[int], scores: Sequence[float]) -> List[Tuple[float, int]]:
    """Pair scores with labels, highest score first.

    Args:
        y_true: Ground truth.
        scores: Scores.

    Returns:
        ``[(score, label), ...]`` sorted by descending score.

    Raises:
        ValueError: If the sequences differ in length.
    """
    if len(y_true) != len(scores):
        raise ValueError("y_true and scores differ in length")
    return sorted(zip((float(s) for s in scores), (int(t) for t in y_true)), key=lambda p: -p[0])


def pr_curve(y_true: Sequence[int], scores: Sequence[float]) -> List[Dict[str, float]]:
    """Precision/recall at every distinct score threshold (ties grouped).

    Args:
        y_true: Ground truth.
        scores: Scores.

    Returns:
        ``[{"threshold", "precision", "recall"}, ...]`` from the highest
        threshold down; empty when there is no positive.
    """
    positives = sum(1 for t in y_true if t)
    if positives == 0:
        return []
    points: List[Dict[str, float]] = []
    tp = fp = 0
    ranked = _ranked(y_true, scores)
    for index, (score, truth) in enumerate(ranked):
        if truth:
            tp += 1
        else:
            fp += 1
        last_of_tie = index == len(ranked) - 1 or ranked[index + 1][0] != score
        if last_of_tie:
            points.append(
                {
                    "threshold": round(score, 6),
                    "precision": round(tp / (tp + fp), 4),
                    "recall": round(tp / positives, 4),
                }
            )
    return points


def average_precision(y_true: Sequence[int], scores: Sequence[float]) -> Optional[float]:
    """Area under the precision-recall curve (step-wise average precision).

    ``AP = Σ (R_n − R_{n−1}) · P_n`` over the distinct thresholds, the same
    definition scikit-learn uses (no interpolation).

    Args:
        y_true: Ground truth.
        scores: Scores.

    Returns:
        The average precision, or ``None`` without positives.
    """
    curve = pr_curve(y_true, scores)
    if not curve:
        return None
    area = 0.0
    previous_recall = 0.0
    for point in curve:
        area += (point["recall"] - previous_recall) * point["precision"]
        previous_recall = point["recall"]
    return round(area, 4)


def roc_points(y_true: Sequence[int], scores: Sequence[float]) -> List[Dict[str, float]]:
    """False/true positive rates at every distinct threshold.

    Args:
        y_true: Ground truth.
        scores: Scores.

    Returns:
        ``[{"threshold", "fpr", "tpr"}, ...]`` from the highest threshold down;
        empty unless both classes are present.
    """
    positives = sum(1 for t in y_true if t)
    negatives = len(y_true) - positives
    if positives == 0 or negatives == 0:
        return []
    points: List[Dict[str, float]] = []
    tp = fp = 0
    ranked = _ranked(y_true, scores)
    for index, (score, truth) in enumerate(ranked):
        if truth:
            tp += 1
        else:
            fp += 1
        if index == len(ranked) - 1 or ranked[index + 1][0] != score:
            points.append(
                {
                    "threshold": round(score, 6),
                    "fpr": round(fp / negatives, 6),
                    "tpr": round(tp / positives, 4),
                }
            )
    return points


def tpr_at_fpr(y_true: Sequence[int], scores: Sequence[float], target_fpr: float) -> Dict[str, Any]:
    """Best true-positive rate whose false-positive rate stays within ``target_fpr``.

    With ``n`` negatives the smallest non-zero FPR is ``1/n``; below that the
    result can only say "no false positive at all" and is flagged as not
    resolvable rather than reported as if it measured ``target_fpr``.

    Args:
        y_true: Ground truth.
        scores: Scores.
        target_fpr: Maximum false-positive rate (e.g. ``1e-3``).

    Returns:
        ``{"target_fpr", "tpr", "threshold", "negatives",
        "negatives_needed", "resolvable"}`` (``tpr`` is ``None`` when a class
        is missing).
    """
    negatives = sum(1 for t in y_true if not t)
    needed = math.ceil(1 / target_fpr)
    result: Dict[str, Any] = {
        "target_fpr": target_fpr,
        "tpr": None,
        "threshold": None,
        "negatives": negatives,
        "negatives_needed": needed,
        "resolvable": negatives >= needed,
    }
    best_tpr = 0.0
    best_threshold: Optional[float] = None
    for point in roc_points(y_true, scores):
        if point["fpr"] <= target_fpr and point["tpr"] >= best_tpr:
            best_tpr = point["tpr"]
            best_threshold = point["threshold"]
    if negatives and negatives < len(y_true):
        result["tpr"] = round(best_tpr, 4)
        result["threshold"] = best_threshold
    return result


def precision_at_k(y_true: Sequence[int], scores: Sequence[float], k: int) -> Optional[float]:
    """Share of phishing among the ``k`` highest-scored samples.

    Args:
        y_true: Ground truth.
        scores: Scores.
        k: Cut-off.

    Returns:
        The precision, or ``None`` when fewer than ``k`` samples exist.
    """
    if k <= 0 or len(y_true) < k:
        return None
    top = _ranked(y_true, scores)[:k]
    return round(sum(truth for _score, truth in top) / k, 4)


def calibration(y_true: Sequence[int], scores: Sequence[float], bins: int = 10) -> Dict[str, Any]:
    """Reliability diagram data and expected calibration error (ECE).

    Scores must lie in ``[0, 1]``; bin ``i`` holds ``i/bins <= s < (i+1)/bins``
    (the last bin includes 1.0).

    Args:
        y_true: Ground truth.
        scores: Scores in ``[0, 1]``.
        bins: Number of equal-width bins.

    Returns:
        ``{"bins": [{"lower", "upper", "count", "mean_score",
        "positive_rate"}], "ece": float | None}``.
    """
    totals = [0] * bins
    score_sums = [0.0] * bins
    positive_counts = [0] * bins
    for truth, score in zip(y_true, scores):
        clipped = min(max(float(score), 0.0), 1.0)
        index = min(int(clipped * bins), bins - 1)
        totals[index] += 1
        score_sums[index] += clipped
        positive_counts[index] += 1 if truth else 0
    rows = []
    weighted_gap = 0.0
    total = sum(totals)
    for index in range(bins):
        count = totals[index]
        mean_score = score_sums[index] / count if count else None
        positive_rate = positive_counts[index] / count if count else None
        if count and mean_score is not None and positive_rate is not None:
            weighted_gap += count * abs(mean_score - positive_rate)
        rows.append(
            {
                "lower": round(index / bins, 4),
                "upper": round((index + 1) / bins, 4),
                "count": count,
                "mean_score": round(mean_score, 4) if mean_score is not None else None,
                "positive_rate": round(positive_rate, 4) if positive_rate is not None else None,
            }
        )
    return {"bins": rows, "ece": round(weighted_gap / total, 4) if total else None}


def grouped(
    groups: Sequence[Optional[str]], y_true: Sequence[int], y_pred: Sequence[int]
) -> Dict[str, Dict[str, Any]]:
    """Confusion matrix and rates per group (brand, category, ...).

    Args:
        groups: Group of each sample (``None`` is reported as ``unknown``).
        y_true: Ground truth.
        y_pred: Decisions.

    Returns:
        ``{group: {"tp", "fp", "fn", "tn", "precision", "recall", ...}}``,
        ordered by group size (largest first).
    """
    members: Dict[str, List[int]] = defaultdict(list)
    for index, group in enumerate(groups):
        members[group or "unknown"].append(index)
    result: Dict[str, Dict[str, Any]] = {}
    for group, indexes in sorted(members.items(), key=lambda item: (-len(item[1]), item[0])):
        counts = confusion([y_true[i] for i in indexes], [y_pred[i] for i in indexes])
        result[group] = {"samples": len(indexes), **counts, **rates(counts)}
    return result


def latency_summary(values_ms: Sequence[float]) -> Dict[str, Optional[float]]:
    """Describe latencies.

    Args:
        values_ms: Durations in milliseconds.

    Returns:
        ``{"count", "p50", "p95", "mean"}`` in milliseconds.
    """
    ordered = sorted(float(v) for v in values_ms)
    if not ordered:
        return {"count": 0, "p50": None, "p95": None, "mean": None}

    def quantile(q: float) -> float:
        position = (len(ordered) - 1) * q
        lower, upper = math.floor(position), math.ceil(position)
        if lower == upper:
            return ordered[int(position)]
        return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)

    return {
        "count": len(ordered),
        "p50": round(quantile(0.5), 1),
        "p95": round(quantile(0.95), 1),
        "mean": round(sum(ordered) / len(ordered), 1),
    }
