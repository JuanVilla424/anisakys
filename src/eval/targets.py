"""Quality targets: are the detector and the pipeline where we agreed they must be?

The targets live in ``eval/targets.json`` (docs/ROADMAP.md, D25):

* detection targets (precision, recall, FPR) are checked on the deployed
  verdict at one operating point, overall and for every brand in the split;
* pipeline targets are maximum medians (hours) of the operational metrics.

Every target is ``met``, ``missed`` or ``not_resolvable``. A target is never met
by default: precision needs enough flagged samples, recall enough positives,
an FPR ceiling at least ``1/FPR`` negatives (as for TPR at a fixed FPR, D23) and
a pipeline median enough events.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

MET = "met"
MISSED = "missed"
NOT_RESOLVABLE = "not_resolvable"
DETECTION_METRICS = ("precision", "recall", "fpr")


def load_targets(path: Path) -> Dict[str, Any]:
    """Read a targets file.

    Args:
        path: ``eval/targets.json`` or another file with the same shape.

    Returns:
        The targets document.

    Raises:
        ValueError: When the file has no detection or pipeline targets.
    """
    targets = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(targets, dict) or not (
        targets.get("detection") or targets.get("pipeline_hours")
    ):
        raise ValueError(f"{path}: no detection or pipeline targets")
    return targets


def _summary(results: Mapping[str, Mapping[str, Any]]) -> Dict[str, int]:
    """Count the targets by status.

    Args:
        results: Target results by name.

    Returns:
        ``{"met", "missed", "not_resolvable"}`` counts.
    """
    counts = {MET: 0, MISSED: 0, NOT_RESOLVABLE: 0}
    for result in results.values():
        counts[result["status"]] += 1
    return counts


def _detection_target(
    metric: str, bound: Mapping[str, float], counts: Mapping[str, Any], targets: Mapping[str, Any]
) -> Dict[str, Any]:
    """Judge one detection metric of one group.

    Args:
        metric: ``precision``, ``recall`` or ``fpr``.
        bound: ``{"min": x}`` or ``{"max": x}``.
        counts: Confusion counts and rates (``tp``, ``fp``, ``fn``, ``tn``, ``precision``...).
        targets: The targets document (sample minimums).

    Returns:
        ``{"value", "target", "status", "reason"}``.
    """
    tp, fp, fn, tn = (int(counts.get(k) or 0) for k in ("tp", "fp", "fn", "tn"))
    value = counts.get(metric)
    target = {k: v for k, v in bound.items() if k in ("min", "max")}
    if metric == "precision":
        needed, have, what = int(targets.get("min_predicted_positives", 10)), tp + fp, "flagged"
    elif metric == "recall":
        needed, have, what = int(targets.get("min_positives", 10)), tp + fn, "positives"
    else:
        ceiling = float(bound.get("max") or 0)
        needed = math.ceil(1 / ceiling) if ceiling > 0 else 0
        have, what = fp + tn, "negatives"
    if have < needed or value is None:
        return {
            "value": value,
            "target": target,
            "status": NOT_RESOLVABLE,
            "reason": f"needs >= {needed} {what}, has {have}",
        }
    ok = (value >= bound["min"]) if "min" in bound else (value <= bound["max"])
    return {"value": value, "target": target, "status": MET if ok else MISSED, "reason": ""}


def _group_targets(
    counts: Mapping[str, Any],
    targets: Mapping[str, Any],
    overrides: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Judge every detection target of one group (overall or one brand).

    Args:
        counts: Confusion counts and rates of the group.
        targets: The targets document.
        overrides: Thresholds that replace the defaults for this group.

    Returns:
        ``{"targets": {metric: result}, "summary": counts}``.
    """
    bounds = {**(targets.get("detection") or {}), **(overrides or {})}
    results = {
        metric: _detection_target(metric, bounds[metric], counts, targets)
        for metric in DETECTION_METRICS
        if metric in bounds
    }
    return {"targets": results, "summary": _summary(results)}


def check_detection(
    operating_point: Mapping[str, Any], targets: Mapping[str, Any]
) -> Dict[str, Any]:
    """Judge the detection targets at one operating point, overall and per brand.

    Args:
        operating_point: An operating point of a verdict block (counts, rates
            and ``per_brand``).
        targets: The targets document.

    Returns:
        ``{"operating_point", "overall", "brands", "summary"}``; samples without
        a brand are only part of the overall figures.
    """
    overrides = targets.get("brand_overrides") or {}
    brands = {
        brand: _group_targets(counts, targets, overrides.get(brand))
        for brand, counts in (operating_point.get("per_brand") or {}).items()
        if brand != "unknown"
    }
    resolved = [b for b, result in brands.items() if result["summary"][NOT_RESOLVABLE] == 0]
    return {
        "operating_point": targets.get("operating_point"),
        "overall": _group_targets(operating_point, targets),
        "brands": brands,
        "summary": {
            "brands": len(brands),
            "brands_fully_resolvable": len(resolved),
            "brands_meeting_all": sum(1 for b in resolved if brands[b]["summary"][MISSED] == 0),
        },
    }


def check_pipeline(
    durations_hours: Mapping[str, Mapping[str, Any]], targets: Mapping[str, Any]
) -> Dict[str, Any]:
    """Judge the pipeline targets (maximum medians, in hours).

    Args:
        durations_hours: ``durations_hours`` of the operational metrics.
        targets: The targets document.

    Returns:
        ``{"targets": {metric: result}, "summary": counts}``.
    """
    needed = int(targets.get("min_pipeline_events", 5))
    results: Dict[str, Any] = {}
    for metric, bound in (targets.get("pipeline_hours") or {}).items():
        stats = durations_hours.get(metric) or {}
        count, median = int(stats.get("count") or 0), stats.get("median")
        target = {"max_median": bound["max_median"]}
        if count < needed or median is None:
            results[metric] = {
                "value": median,
                "target": target,
                "status": NOT_RESOLVABLE,
                "reason": f"needs >= {needed} events, has {count}",
            }
            continue
        ok = median <= bound["max_median"]
        results[metric] = {
            "value": median,
            "target": target,
            "status": MET if ok else MISSED,
            "reason": "",
        }
    return {"targets": results, "summary": _summary(results)}
