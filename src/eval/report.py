"""Evaluation reports: the metrics document (JSON) and a self-contained HTML page.

The JSON is the source of truth (it is what the roadmap quotes); the HTML renders
it with inline SVG charts (precision-recall curves, reliability diagram) and no
external resources, so it opens anywhere and passes a strict CSP. URLs of the
misclassified samples are shown defanged.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.eval.dataset import Sample, utc_now_iso
from src.eval.metrics import (
    average_precision,
    calibration,
    confusion,
    grouped,
    latency_summary,
    pr_curve,
    precision_at_k,
    rates,
    tpr_at_fpr,
)
from src.eval.predictors import SCORE_DEFINITION, Prediction, level_at_least
from src.eval.targets import MET, MISSED, check_detection

OPERATING_POINTS: Dict[str, str] = {"level>=high": "high", "level>=medium": "medium"}
PRIMARY_OPERATING_POINT = "level>=high"
# The detection side of the auto-report rule (src/detection/analyzer.py): threat level
# high/critical with confidence >= AUTO_REPORT_THRESHOLD_CONFIDENCE.
AUTO_REPORT_POINT = "auto_report"
DEFAULT_AUTO_REPORT_MIN_CONFIDENCE = 85
FPR_TARGETS = (1e-3, 1e-4)
K_VALUES = (10, 50, 100)
ANSWERED = frozenset({"listed", "not_listed"})
CALLED = ANSWERED | {"error"}
MAX_LISTED_ERRORS = 25


def defang(url: str) -> str:
    """Make a URL non-clickable for display.

    Args:
        url: URL.

    Returns:
        ``hxxps[://]host[.]tld/path``.
    """
    return url.replace("http", "hxxp", 1).replace("://", "[://]").replace(".", "[.]")


def verdict_block(
    samples: Sequence[Sample],
    predictions: Sequence[Prediction],
    heuristic: bool = False,
    auto_report_min_confidence: int = DEFAULT_AUTO_REPORT_MIN_CONFIDENCE,
) -> Dict[str, Any]:
    """All quality metrics of one verdict (deployed or heuristic).

    Args:
        samples: Scored samples.
        predictions: Their predictions, in the same order.
        heuristic: Use the heuristic level/score instead of the deployed one.
        auto_report_min_confidence: Confidence the ``auto_report`` operating point
            requires on top of level high.

    Returns:
        Coverage, level distribution, operating points (with per-brand and
        per-category confusion), PR-AUC and curve, TPR at fixed FPRs,
        precision@k, calibration and the misclassified samples.
    """
    y_true = [1 if s.is_positive else 0 for s in samples]
    levels = [p.heuristic_level if heuristic else p.level for p in predictions]
    scores = [p.heuristic_score if heuristic else p.score for p in predictions]
    brands = [s.brand for s in samples]
    categories = [s.category for s in samples]

    distribution: Dict[str, Dict[str, int]] = {"phishing": {}, "benign": {}}
    for sample, level in zip(samples, levels):
        bucket = distribution[sample.label]
        bucket[level] = bucket.get(level, 0) + 1

    decisions: Dict[str, List[int]] = {
        name: [1 if level_at_least(level, minimum) else 0 for level in levels]
        for name, minimum in OPERATING_POINTS.items()
    }
    decisions[AUTO_REPORT_POINT] = [
        (
            1
            if level_at_least(level, "high") and (p.confidence or 0) >= auto_report_min_confidence
            else 0
        )
        for level, p in zip(levels, predictions)
    ]
    operating_points: Dict[str, Any] = {}
    misclassified: Dict[str, List[Dict[str, Any]]] = {}
    for name, y_pred in decisions.items():
        counts = confusion(y_true, y_pred)
        operating_points[name] = {
            **counts,
            **rates(counts),
            "per_brand": grouped(brands, y_true, y_pred),
            "per_category": grouped(categories, y_true, y_pred),
        }
        if name == PRIMARY_OPERATING_POINT:
            misclassified = _misclassified(samples, levels, y_true, y_pred)

    covered = sum(1 for level in levels if level != "unknown")
    return {
        "coverage": {
            "covered": covered,
            "total": len(levels),
            "rate": round(covered / len(levels), 4) if levels else None,
        },
        "level_distribution": distribution,
        "operating_points": operating_points,
        "pr_auc": average_precision(y_true, scores),
        "pr_curve": pr_curve(y_true, scores),
        "tpr_at_fpr": [tpr_at_fpr(y_true, scores, target) for target in FPR_TARGETS],
        "precision_at_k": {str(k): precision_at_k(y_true, scores, k) for k in K_VALUES},
        "calibration": calibration(y_true, scores),
        "misclassified": misclassified,
    }


def _misclassified(
    samples: Sequence[Sample],
    levels: Sequence[str],
    y_true: Sequence[int],
    y_pred: Sequence[int],
) -> Dict[str, List[Dict[str, Any]]]:
    """List false negatives and false positives (capped), for diagnosis.

    Args:
        samples: Scored samples.
        levels: Verdict per sample.
        y_true: Ground truth.
        y_pred: Decisions.

    Returns:
        ``{"false_negatives": [...], "false_positives": [...]}``.
    """
    false_negatives: List[Dict[str, Any]] = []
    false_positives: List[Dict[str, Any]] = []
    for sample, level, truth, pred in zip(samples, levels, y_true, y_pred):
        entry = {
            "id": sample.id,
            "url": sample.url,
            "category": sample.category,
            "brand": sample.brand,
            "level": level,
        }
        if truth and not pred and len(false_negatives) < MAX_LISTED_ERRORS:
            false_negatives.append(entry)
        elif pred and not truth and len(false_positives) < MAX_LISTED_ERRORS:
            false_positives.append(entry)
    return {"false_negatives": false_negatives, "false_positives": false_positives}


def stage_block(
    predictions: Sequence[Prediction], costs: Optional[Dict[str, float]] = None
) -> Dict[str, Any]:
    """Latency, provider answers and cost per pipeline stage.

    A call is counted when the stage answered (``listed``/``not_listed``) or
    failed (``error``); ``no_data`` means nothing was asked (provider not
    configured or disabled) or nothing came back.

    Args:
        predictions: Predictions with ``stage_timings_ms``/``stage_status``.
        costs: USD per call by stage (default 0: free tiers).

    Returns:
        ``{stage: {"latency_ms", "status", "calls", "answered", "cost_usd"}}``
        plus a ``"total"`` entry.
    """
    timings: Dict[str, List[float]] = {}
    statuses: Dict[str, Counter] = {}
    for prediction in predictions:
        for stage, value in prediction.stage_timings_ms.items():
            timings.setdefault(stage, []).append(float(value))
        for stage, status in prediction.stage_status.items():
            statuses.setdefault(stage, Counter())[status] += 1
    price = costs or {}
    result: Dict[str, Any] = {}
    total_cost = 0.0
    total_ms: List[float] = []
    for prediction in predictions:
        if prediction.stage_timings_ms:
            total_ms.append(sum(prediction.stage_timings_ms.values()))
    for stage in sorted(set(timings) | set(statuses)):
        counter = statuses.get(stage, Counter())
        calls = sum(count for status, count in counter.items() if status in CALLED)
        cost = round(calls * float(price.get(stage, 0.0)), 4)
        total_cost += cost
        result[stage] = {
            "latency_ms": latency_summary(timings.get(stage, [])),
            "status": dict(counter),
            "calls": calls,
            "answered": sum(count for status, count in counter.items() if status in ANSWERED),
            "cost_usd": cost,
        }
    result["total"] = {"latency_ms": latency_summary(total_ms), "cost_usd": round(total_cost, 4)}
    return result


def build_report(
    manifest: Dict[str, Any],
    split: str,
    predictor: str,
    samples: Sequence[Sample],
    predictions: Sequence[Prediction],
    costs: Optional[Dict[str, float]] = None,
    code_commit: Optional[str] = None,
    notes: Optional[List[str]] = None,
    targets: Optional[Dict[str, Any]] = None,
    auto_report_min_confidence: Optional[int] = None,
) -> Dict[str, Any]:
    """Assemble the metrics document of one evaluation run.

    Args:
        manifest: Dataset manifest.
        split: Evaluated split.
        predictor: Predictor name.
        samples: Samples of the split.
        predictions: Predictions (samples without one are reported as not scored).
        costs: USD per call by stage.
        code_commit: Commit of the evaluated code.
        notes: Context worth keeping with the numbers (e.g. providers configured).
        targets: Quality targets (``eval/targets.json``), checked on the deployed verdict.
        auto_report_min_confidence: Confidence of the ``auto_report`` operating point
            (default: ``AUTO_REPORT_THRESHOLD_CONFIDENCE`` from the settings).

    Returns:
        The report document.

    Raises:
        ValueError: When the targets name an unknown operating point.
    """
    if auto_report_min_confidence is None:
        auto_report_min_confidence = _configured_auto_report_confidence()
    by_id = {p.sample_id: p for p in predictions}
    pairs: List[Tuple[Sample, Prediction]] = [(s, by_id[s.id]) for s in samples if s.id in by_id]
    scored = [s for s, _ in pairs]
    scored_predictions = [p for _, p in pairs]
    report: Dict[str, Any] = {
        "dataset": {
            "name": manifest.get("name"),
            "version": manifest.get("version"),
            "samples_sha256": manifest.get("samples_sha256"),
            "split": split,
        },
        "predictor": predictor,
        "generated_at": utc_now_iso(),
        "code_commit": code_commit,
        "score_definition": SCORE_DEFINITION,
        "notes": list(notes or []),
        "counts": {
            "samples": len(scored),
            "positives": sum(1 for s in scored if s.is_positive),
            "negatives": sum(1 for s in scored if not s.is_positive),
            "not_scored": len(samples) - len(scored),
            "errors": sum(1 for p in scored_predictions if p.error),
        },
        "auto_report_rule": {
            "min_level": "high",
            "min_confidence": auto_report_min_confidence,
            "source": "src/detection/analyzer.py (threat level high/critical with confidence "
            ">= AUTO_REPORT_THRESHOLD_CONFIDENCE)",
        },
        "verdicts": {
            "deployed": verdict_block(
                scored, scored_predictions, auto_report_min_confidence=auto_report_min_confidence
            )
        },
    }
    if predictor != "stored":
        report["verdicts"]["heuristic"] = verdict_block(
            scored,
            scored_predictions,
            heuristic=True,
            auto_report_min_confidence=auto_report_min_confidence,
        )
        report["stages"] = stage_block(scored_predictions, costs)
    if targets:
        point = targets.get("operating_point", AUTO_REPORT_POINT)
        operating_points = report["verdicts"]["deployed"]["operating_points"]
        if point not in operating_points:
            raise ValueError(f"targets: unknown operating point {point!r}")
        report["targets"] = check_detection(operating_points[point], targets)
    return report


def _configured_auto_report_confidence() -> int:
    """The deployed auto-report confidence threshold.

    Returns:
        ``AUTO_REPORT_THRESHOLD_CONFIDENCE``, else the settings default (85).
    """
    from src.config import settings

    return int(
        getattr(settings, "AUTO_REPORT_THRESHOLD_CONFIDENCE", DEFAULT_AUTO_REPORT_MIN_CONFIDENCE)
    )


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_CSS = """
:root{--bg:#ffffff;--fg:#1d2433;--muted:#5b6475;--line:#d8dde6;--card:#f6f8fb;
--a:#2563eb;--b:#d97706;--ok:#15803d;--bad:#b91c1c}
@media (prefers-color-scheme:dark){:root{--bg:#0f141c;--fg:#e6e9ef;--muted:#9aa3b2;
--line:#2a3342;--card:#161d28;--a:#60a5fa;--b:#fbbf24;--ok:#4ade80;--bad:#f87171}}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px}
h3{font-size:15px;margin:20px 0 6px}p.meta{color:var(--muted);margin:0 0 16px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}
.card b{display:block;font-size:22px;font-variant-numeric:tabular-nums}
.card span{color:var(--muted);font-size:13px}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums;margin:8px 0}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;font-size:13px}
th{color:var(--muted);font-weight:600}td.n{text-align:right}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}
svg{background:var(--card);border:1px solid var(--line);border-radius:8px;width:100%;height:auto}
svg text{fill:var(--muted);font-size:11px}.axis{stroke:var(--line)}
.sa{stroke:var(--a);fill:none;stroke-width:2}.sb{stroke:var(--b);fill:none;stroke-width:2}
.diag{stroke:var(--muted);stroke-dasharray:4 4}.dot{fill:var(--a)}
code,.url{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all}
ul.notes{color:var(--muted);padding-left:18px}
td.ok{color:var(--ok);font-weight:600}td.bad{color:var(--bad);font-weight:600}td.na{color:var(--muted)}
"""


def _fmt(value: Any, digits: int = 3) -> str:
    """Format a metric for a table cell.

    Args:
        value: Number or ``None``.
        digits: Decimals for floats.

    Returns:
        The formatted text (``—`` for ``None``).
    """
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return html.escape(str(value))


def _curve_svg(series: Sequence[Tuple[str, str, List[Tuple[float, float]]]], title: str) -> str:
    """Draw one or more curves in the unit square.

    Args:
        series: ``(label, css class, [(x, y), ...])`` per curve.
        title: Chart title.

    Returns:
        An ``<svg>`` element.
    """
    size, pad = 300, 36
    inner = size - 2 * pad

    def px(x: float, y: float) -> str:
        return f"{pad + x * inner:.1f},{size - pad - y * inner:.1f}"

    parts = [
        f'<svg viewBox="0 0 {size} {size}" role="img" aria-label="{html.escape(title)}">',
        f'<text x="{pad}" y="20">{html.escape(title)}</text>',
        f'<line class="axis" x1="{pad}" y1="{size - pad}" x2="{size - pad}" y2="{size - pad}"/>',
        f'<line class="axis" x1="{pad}" y1="{pad}" x2="{pad}" y2="{size - pad}"/>',
        f'<text x="{size - pad - 8}" y="{size - 10}">1</text>',
        f'<text x="{pad - 4}" y="{size - 10}">0</text>',
        f'<text x="8" y="{pad + 4}">1</text>',
    ]
    legend_y = 34
    for label, css, points in series:
        if points:
            path = " ".join(px(x, y) for x, y in points)
            parts.append(f'<polyline class="{css}" points="{path}"/>')
        parts.append(
            f'<text x="{size - pad - 110}" y="{legend_y}" class="{css}">{html.escape(label)}</text>'
        )
        legend_y += 14
    parts.append("</svg>")
    return "".join(parts)


def _pr_points(curve: List[Dict[str, float]]) -> List[Tuple[float, float]]:
    """Convert a PR curve to plotted (recall, precision) points.

    Args:
        curve: Output of :func:`pr_curve`.

    Returns:
        Points starting at recall 0.
    """
    if not curve:
        return []
    return [(0.0, curve[0]["precision"])] + [(p["recall"], p["precision"]) for p in curve]


def _reliability_svg(bins: List[Dict[str, Any]]) -> str:
    """Draw the reliability diagram (mean score vs observed phishing rate).

    Args:
        bins: Calibration bins.

    Returns:
        An ``<svg>`` element.
    """
    size, pad = 300, 36
    inner = size - 2 * pad
    parts = [
        f'<svg viewBox="0 0 {size} {size}" role="img" aria-label="Reliability diagram">',
        f'<text x="{pad}" y="20">Reliability (deployed score)</text>',
        f'<line class="axis" x1="{pad}" y1="{size - pad}" x2="{size - pad}" y2="{size - pad}"/>',
        f'<line class="axis" x1="{pad}" y1="{pad}" x2="{pad}" y2="{size - pad}"/>',
        f'<line class="diag" x1="{pad}" y1="{size - pad}" x2="{size - pad}" y2="{pad}"/>',
    ]
    for row in bins:
        if row["count"] and row["mean_score"] is not None:
            x = pad + row["mean_score"] * inner
            y = size - pad - row["positive_rate"] * inner
            radius = min(3 + row["count"] ** 0.5, 12)
            parts.append(f'<circle class="dot" cx="{x:.1f}" cy="{y:.1f}" r="{radius:.1f}"/>')
    parts.append("</svg>")
    return "".join(parts)


def _ops_table(block: Dict[str, Any]) -> str:
    """Render the operating points of a verdict.

    Args:
        block: Output of :func:`verdict_block`.

    Returns:
        An HTML table.
    """
    rows = []
    for name, point in block["operating_points"].items():
        rows.append(
            "<tr>"
            f"<td>{html.escape(name)}</td>"
            + "".join(
                f'<td class="n">{_fmt(point[key])}</td>'
                for key in ("tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr")
            )
            + "</tr>"
        )
    header = "".join(
        f"<th>{h}</th>"
        for h in ("Operating point", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1", "FPR")
    )
    return f"<table><thead><tr>{header}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def _group_table(groups: Dict[str, Dict[str, Any]], title: str, limit: int = 20) -> str:
    """Render per-group confusion (largest groups first).

    Args:
        groups: Output of :func:`grouped`.
        title: Group column title.
        limit: Maximum rows.

    Returns:
        An HTML table.
    """
    rows = []
    for name, row in list(groups.items())[:limit]:
        rows.append(
            f"<tr><td>{html.escape(name)}</td>"
            + "".join(
                f'<td class="n">{_fmt(row[key])}</td>'
                for key in ("samples", "tp", "fp", "fn", "tn", "precision", "recall")
            )
            + "</tr>"
        )
    header = "".join(
        f"<th>{h}</th>" for h in (title, "Samples", "TP", "FP", "FN", "TN", "Precision", "Recall")
    )
    return f"<table><thead><tr>{header}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


_STATUS_LABELS = {MET: ("ok", "met"), MISSED: ("bad", "missed")}


def _target_cells(name: str, result: Dict[str, Any]) -> str:
    """Render one target result as table cells.

    Args:
        name: Metric name.
        result: Output of :mod:`src.eval.targets` for one metric.

    Returns:
        ``<td>`` cells: metric, target, value, status.
    """
    target = result["target"]
    bound = (
        f"≥ {_fmt(target['min'])}"
        if "min" in target
        else f"≤ {_fmt(target.get('max', target.get('max_median')))}"
    )
    css, label = _STATUS_LABELS.get(result["status"], ("na", "not resolvable"))
    reason = f" ({html.escape(result['reason'])})" if result.get("reason") else ""
    return (
        f"<td>{html.escape(name)}</td><td>{bound}</td><td class='n'>{_fmt(result['value'])}</td>"
        f"<td class='{css}'>{label}{reason}</td>"
    )


def _targets_html(targets: Dict[str, Any]) -> str:
    """Render the quality targets: overall, then the brands with enough data.

    Args:
        targets: ``report["targets"]``.

    Returns:
        An HTML fragment.
    """
    header = "<tr><th>Metric</th><th>Target</th><th>Value</th><th>Status</th></tr>"
    overall = "".join(
        f"<tr>{_target_cells(metric, result)}</tr>"
        for metric, result in targets["overall"]["targets"].items()
    )
    brand_rows = "".join(
        f"<tr><td>{html.escape(brand)}</td>"
        + "".join(
            f"<td class='{_STATUS_LABELS.get(r['status'], ('na', ''))[0]}'>"
            f"{_fmt(r['value'])}</td>"
            for r in result["targets"].values()
        )
        + "</tr>"
        for brand, result in targets["brands"].items()
        if any(r["status"] != "not_resolvable" for r in result["targets"].values())
    )
    summary = targets["summary"]
    parts = [
        f"<h2>Targets — deployed, {html.escape(str(targets['operating_point']))}</h2>",
        f"<table><thead>{header}</thead><tbody>{overall}</tbody></table>",
        f"<p class='meta'>{summary['brands']} brand(s) in the split; "
        f"{summary['brands_fully_resolvable']} with enough data for every target; "
        f"{summary['brands_meeting_all']} meeting all of them.</p>",
    ]
    if brand_rows:
        metrics = "".join(f"<th>{html.escape(m)}</th>" for m in targets["overall"]["targets"])
        parts.append(
            f"<table><thead><tr><th>Brand</th>{metrics}</tr></thead><tbody>{brand_rows}</tbody>"
            "</table>"
        )
    return "".join(parts)


def _errors_table(entries: List[Dict[str, Any]]) -> str:
    """Render misclassified samples with defanged URLs.

    Args:
        entries: Misclassified entries.

    Returns:
        An HTML table, or a note when there are none.
    """
    if not entries:
        return "<p class='meta'>None.</p>"
    rows = "".join(
        f"<tr><td class='url'>{html.escape(defang(e['url']))}</td>"
        f"<td>{html.escape(e['category'])}</td><td>{_fmt(e.get('brand'))}</td>"
        f"<td>{html.escape(e['level'])}</td></tr>"
        for e in entries
    )
    return (
        "<table><thead><tr><th>URL (defanged)</th><th>Category</th><th>Brand</th>"
        f"<th>Verdict</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def render_html(report: Dict[str, Any]) -> str:
    """Render a report as a standalone HTML page.

    Args:
        report: Output of :func:`build_report`.

    Returns:
        The HTML document.
    """
    deployed = report["verdicts"]["deployed"]
    heuristic = report["verdicts"].get("heuristic")
    primary = deployed["operating_points"][PRIMARY_OPERATING_POINT]
    counts = report["counts"]
    dataset = report["dataset"]
    cards = [
        ("Samples", counts["samples"]),
        ("Phishing / benign", f"{counts['positives']} / {counts['negatives']}"),
        ("Coverage (deployed)", _fmt(deployed["coverage"]["rate"])),
        ("Precision @high", _fmt(primary["precision"])),
        ("Recall @high", _fmt(primary["recall"])),
        ("PR-AUC (deployed)", _fmt(deployed["pr_auc"])),
    ]
    if heuristic:
        cards.append(("PR-AUC (heuristic)", _fmt(heuristic["pr_auc"])))
    card_html = "".join(
        f"<div class='card'><b>{_fmt(v)}</b><span>{k}</span></div>" for k, v in cards
    )

    series = [("deployed", "sa", _pr_points(deployed["pr_curve"]))]
    if heuristic:
        series.append(("heuristic", "sb", _pr_points(heuristic["pr_curve"])))
    charts = _curve_svg(series, "Precision (y) vs recall (x)") + _reliability_svg(
        deployed["calibration"]["bins"]
    )

    tpr_rows = "".join(
        f"<tr><td>{entry['target_fpr']:g}</td><td class='n'>{_fmt(entry['tpr'])}</td>"
        f"<td class='n'>{entry['negatives']}</td><td class='n'>{entry['negatives_needed']}</td>"
        f"<td>{'yes' if entry['resolvable'] else 'no (too few negatives)'}</td></tr>"
        for entry in deployed["tpr_at_fpr"]
    )
    patk = "".join(
        f"<tr><td>{html.escape(k)}</td><td class='n'>{_fmt(v)}</td></tr>"
        for k, v in deployed["precision_at_k"].items()
    )

    sections = [
        f"<h1>Anisakys evaluation — {html.escape(str(dataset['name']))} "
        f"{html.escape(str(dataset['version']))} ({html.escape(dataset['split'])})</h1>",
        f"<p class='meta'>Predictor <code>{html.escape(report['predictor'])}</code> · "
        f"generated {html.escape(report['generated_at'])} · commit "
        f"<code>{html.escape(str(report.get('code_commit')))}</code> · samples SHA-256 "
        f"<code>{html.escape(str(dataset.get('samples_sha256'))[:16])}…</code></p>",
        f"<div class='cards'>{card_html}</div>",
    ]
    if report.get("notes"):
        sections.append(
            "<ul class='notes'>"
            + "".join(f"<li>{html.escape(n)}</li>" for n in report["notes"])
            + "</ul>"
        )
    if report.get("targets"):
        sections.append(_targets_html(report["targets"]))
    sections += [
        "<h2>Operating points — deployed verdict</h2>",
        _ops_table(deployed),
    ]
    if heuristic:
        sections += ["<h2>Operating points — heuristics only</h2>", _ops_table(heuristic)]
    sections += [
        f"<h2>Curves</h2><div class='charts'>{charts}</div>",
        "<h3>TPR at fixed false-positive rates (deployed score)</h3>",
        "<table><thead><tr><th>FPR ≤</th><th>TPR</th><th>Negatives</th>"
        f"<th>Needed</th><th>Resolvable</th></tr></thead><tbody>{tpr_rows}</tbody></table>",
        "<h3>Precision@k (deployed score)</h3>",
        f"<table><thead><tr><th>k</th><th>Precision</th></tr></thead><tbody>{patk}</tbody></table>",
        f"<p class='meta'>{html.escape(report['score_definition'])}</p>",
        "<h2>Per brand — deployed, level ≥ high</h2>",
        _group_table(primary["per_brand"], "Brand"),
        "<h2>Per category — deployed, level ≥ high</h2>",
        _group_table(primary["per_category"], "Category"),
    ]
    stages = report.get("stages")
    if stages:
        stage_rows = "".join(
            f"<tr><td>{html.escape(name)}</td>"
            f"<td class='n'>{_fmt(row['latency_ms']['p50'], 1)}</td>"
            f"<td class='n'>{_fmt(row['latency_ms']['p95'], 1)}</td>"
            f"<td class='n'>{row.get('calls', '—')}</td>"
            f"<td class='n'>{row.get('answered', '—')}</td>"
            f"<td class='n'>{_fmt(row['cost_usd'], 4)}</td></tr>"
            for name, row in stages.items()
        )
        sections += [
            "<h2>Latency and cost per stage</h2>",
            "<table><thead><tr><th>Stage</th><th>p50 ms</th><th>p95 ms</th><th>Calls</th>"
            f"<th>Answered</th><th>USD</th></tr></thead><tbody>{stage_rows}</tbody></table>",
        ]
    misclassified = deployed.get("misclassified") or {}
    sections += [
        "<h2>False negatives — deployed, level ≥ high (first 25)</h2>",
        _errors_table(misclassified.get("false_negatives", [])),
        "<h2>False positives — deployed, level ≥ high (first 25)</h2>",
        _errors_table(misclassified.get("false_positives", [])),
    ]
    title = f"Anisakys evaluation {dataset['name']} {dataset['version']}"
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>"
        f"<body><main>{''.join(sections)}</main></body></html>"
    )


def write_report(directory: Path, report: Dict[str, Any]) -> Tuple[Path, Path]:
    """Write ``report.json`` and ``report.html``.

    Args:
        directory: Output directory (created).
        report: The report document.

    Returns:
        ``(json path, html path)``.
    """
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / "report.json"
    html_path = directory / "report.html"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    html_path.write_text(render_html(report), encoding="utf-8")
    return json_path, html_path
