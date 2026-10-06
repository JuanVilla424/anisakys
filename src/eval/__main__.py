"""Command line of the evaluation harness: ``python -m src.eval <command>``.

Examples::

    python -m src.eval build --name baseline --version 2026-10-04
    python -m src.eval verify eval/datasets/baseline/2026-10-04
    python -m src.eval run eval/datasets/baseline/2026-10-04 --predictor live
    python -m src.eval run eval/datasets/baseline/2026-10-04 --predictor heuristic
    python -m src.eval ops --days 30
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASETS = ROOT / "eval" / "datasets"
DEFAULT_SEEDS = ROOT / "eval" / "seeds"
DEFAULT_CACHE = ROOT / "eval" / "cache"
DEFAULT_RUNS = ROOT / "eval" / "runs"
DEFAULT_COSTS = ROOT / "eval" / "costs.json"
DEFAULT_TARGETS = ROOT / "eval" / "targets.json"
DEFAULT_TLD_ABUSE = ROOT / "src" / "data" / "tld_abuse.json"
# The phase 1 (pre-v2) run on the phase 2 dataset: the reference the fusion's
# activation gate has to beat (docs/ROADMAP.md, "Phase 2 results").
DEFAULT_GATE_BASELINE = (
    DEFAULT_RUNS / "phase2-2026-10-05-test-live-20261006T022110Z" / "report.json"
)


def _targets(path: Optional[str]) -> Optional[Dict[str, Any]]:
    """Load the quality targets, if the file exists.

    Args:
        path: Targets file (``""`` disables the check).

    Returns:
        The targets document, or ``None``.
    """
    from src.eval.targets import load_targets

    if not path or not Path(path).exists():
        return None
    return load_targets(Path(path))


def code_commit() -> Optional[str]:
    """Short commit of the working tree, with ``-dirty`` for local changes.

    Returns:
        E.g. ``2f189a1`` or ``2f189a1-dirty``; ``None`` outside a git checkout.
    """
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return f"{commit}-dirty" if dirty else commit


def _engine() -> Any:
    """Engine of the configured database.

    Returns:
        A SQLAlchemy engine (``DATABASE_URL``).
    """
    from src.database import DatabaseManager

    return DatabaseManager().engine


def _judge_prompt_version() -> str:
    from src.detection.llm_judge import PROMPT_VERSION

    return PROMPT_VERSION


def _progress(done: int, total: int) -> None:
    """Report scan progress on stderr every 10 samples.

    Args:
        done: Samples finished.
        total: Samples to finish.
    """
    if done == total or done % 10 == 0:
        print(f"  {done}/{total} scored", file=sys.stderr, flush=True)


def providers_configured() -> Dict[str, bool]:
    """Which threat-intel providers the deployed detector can call (no secrets shown).

    Returns:
        ``{provider: configured}``.
    """
    from src.config import secret_value, settings

    return {
        "virustotal": bool(secret_value(settings.VIRUSTOTAL_API_KEY)),
        "phishtank_app_key": bool(secret_value(settings.PHISHTANK_API_KEY)),
        "google_safe_browsing": bool(secret_value(settings.GOOGLE_SAFE_BROWSING_API_KEY)),
        "urlvoid": bool(settings.URLVOID_ENABLED and secret_value(settings.URLVOID_API_KEY)),
    }


def cmd_build(args: argparse.Namespace) -> int:
    """Build and write a dataset.

    Args:
        args: Parsed arguments.

    Returns:
        Exit code.
    """
    from src.eval.dataset import assign_splits, dedupe, write_dataset
    from src.eval.sources import (
        analyst_samples,
        load_brand_catalog,
        openphish_samples,
        seed_samples,
        tranco_samples,
        verify_live,
    )

    seeds_dir = Path(args.seeds)
    catalog = load_brand_catalog(seeds_dir)
    candidates, analyst = [], []
    reports: List[Dict[str, Any]] = []

    seeds, seed_reports = seed_samples(seeds_dir)
    candidates += seeds
    reports += [r.to_dict() for r in seed_reports]
    if args.tranco_top > 0:
        tranco, report = tranco_samples(args.tranco_top, Path(args.cache), args.tranco_list_id)
        candidates += tranco
        reports.append(report.to_dict())
    if not args.no_feeds:
        feed, report = openphish_samples(catalog, limit=args.feed_limit)
        candidates += feed
        reports.append(report.to_dict())
    if not args.no_db:
        try:
            analyst, report = analyst_samples(_engine())
            reports.append(report.to_dict())
        except Exception as exc:
            reports.append({"name": "labels", "error": f"{type(exc).__name__}: {exc}"})

    print(f"Probing {len(candidates)} candidate URL(s)...", file=sys.stderr, flush=True)
    if args.skip_liveness:
        live, classes = candidates, {"not_probed": len(candidates)}
    else:
        live, classes = verify_live(candidates, workers=args.workers, timeout=args.timeout)
    reports.append({"name": "liveness", "description": "probe class per candidate", **classes})

    samples = assign_splits(dedupe(analyst + live, args.max_per_kit), args.test_fraction)
    directory = Path(args.out) / args.name / args.version
    manifest = write_dataset(
        directory,
        samples,
        name=args.name,
        version=args.version,
        sources=reports,
        parameters={
            "tranco_top": args.tranco_top,
            "tranco_list_id": args.tranco_list_id,
            "feed_limit": args.feed_limit,
            "feeds": not args.no_feeds,
            "analyst_labels": not args.no_db,
            "liveness_verified": not args.skip_liveness,
            "probe_timeout_seconds": args.timeout,
            "max_per_kit": args.max_per_kit,
            "test_fraction": args.test_fraction,
        },
        code_commit=code_commit(),
    )
    print(json.dumps({"dataset": str(directory), "counts": manifest["counts"]}, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a dataset against its manifest.

    Args:
        args: Parsed arguments.

    Returns:
        0 when intact, 1 otherwise.
    """
    from src.eval.dataset import verify_dataset

    problems = verify_dataset(Path(args.dataset))
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}")
        return 1
    print(f"OK: {args.dataset}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Score a dataset split and write the reports.

    Args:
        args: Parsed arguments.

    Returns:
        Exit code.
    """
    from src.eval.dataset import load_dataset, select_split
    from src.eval.predictors import (
        ScanPredictor,
        StoredPredictor,
        judge_from_settings,
        live_validator,
        offline_validator,
        with_judge,
    )
    from src.eval.report import build_report, write_report

    if args.judge and args.predictor == "stored":
        print("--judge needs a scanning predictor (live or heuristic)", file=sys.stderr)
        return 2
    manifest, samples = load_dataset(Path(args.dataset))
    selected = sorted(select_split(samples, args.split), key=lambda s: s.id)
    if args.limit:
        selected = selected[: args.limit]
    commit = code_commit()
    run_name = f"{args.predictor}+judge" if args.judge else args.predictor
    cache = (
        Path(args.cache)
        / f"{run_name}-{manifest['name']}-{manifest['version']}-{commit or 'nogit'}.jsonl"
    )
    max_scans = args.max_scans
    notes: List[str] = []
    if args.reuse_cache:
        # Score with the scans of an earlier run: the same predictions, no new network calls.
        cache, max_scans = Path(args.reuse_cache), 0
        notes.append(f"Predictions reused from {cache.name} (no new scans in this run)")
    predictor: Any
    if args.predictor == "stored":
        predictor = StoredPredictor(_engine())
    else:
        factory = live_validator if args.predictor == "live" else offline_validator
        if args.judge and max_scans != 0:
            try:
                judge = judge_from_settings()
            except ValueError as e:
                print(str(e), file=sys.stderr)
                return 2
            factory = with_judge(factory, judge)
            notes.append(
                f"LLM judge measured: {judge.config.provider} {judge.config.model} "
                f"(prompt {_judge_prompt_version()}, daily budget "
                f"{judge.config.daily_budget_usd} USD)"
            )
        predictor = ScanPredictor(
            run_name,
            factory,
            cache_path=cache,
            workers=args.workers,
            max_scans=max_scans,
            progress=_progress,
        )
        configured = providers_configured()
        notes.append(
            "Threat-intel providers configured for this run: "
            + ", ".join(f"{name}={'yes' if ok else 'no'}" for name, ok in configured.items())
            + (" (all disabled: heuristic predictor)" if args.predictor == "heuristic" else "")
        )
    print(
        f"Scoring {len(selected)} sample(s) with the {run_name} predictor...",
        file=sys.stderr,
        flush=True,
    )
    predictions = predictor.predict(selected)
    costs = (
        json.loads(Path(args.costs).read_text(encoding="utf-8"))
        if args.costs and Path(args.costs).exists()
        else {}
    )
    report = build_report(
        manifest,
        args.split,
        run_name,
        selected,
        predictions,
        costs=costs.get("usd_per_call", costs),
        code_commit=commit,
        notes=notes,
        targets=_targets(args.targets),
        auto_report_min_confidence=args.auto_report_confidence,
    )
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = (
        Path(args.out) / f"{manifest['name']}-{manifest['version']}-{args.split}-{run_name}-{stamp}"
    )
    json_path, html_path = write_report(out, report)
    deployed = report["verdicts"]["deployed"]
    print(
        json.dumps(
            {
                "report_json": str(json_path),
                "report_html": str(html_path),
                "counts": report["counts"],
                "coverage": deployed["coverage"],
                "level>=high": {
                    k: deployed["operating_points"]["level>=high"][k]
                    for k in ("precision", "recall", "f1", "fpr")
                },
                "pr_auc": deployed["pr_auc"],
                "heuristic_pr_auc": report["verdicts"].get("heuristic", {}).get("pr_auc"),
                "judge_pr_auc": report["verdicts"].get("judge", {}).get("pr_auc"),
                "targets": (
                    {
                        "operating_point": report["targets"]["operating_point"],
                        **{
                            metric: result["status"]
                            for metric, result in report["targets"]["overall"]["targets"].items()
                        },
                        "brands": report["targets"]["summary"],
                    }
                    if report.get("targets")
                    else None
                ),
            },
            indent=2,
        )
    )
    return 0


def cmd_ops(args: argparse.Namespace) -> int:
    """Print (and optionally save) the operational metrics.

    Args:
        args: Parsed arguments.

    Returns:
        Exit code.
    """
    from src.eval.targets import check_pipeline
    from src.observability.operational import compute_operational_metrics

    metrics = compute_operational_metrics(_engine(), args.days)
    targets = _targets(args.targets)
    if targets and targets.get("pipeline_hours"):
        metrics["targets"] = check_pipeline(metrics["durations_hours"], targets)
    text = json.dumps(metrics, indent=2, default=str)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


def cmd_tld_stats(args: argparse.Namespace) -> int:
    """Write the per-TLD phishing log-odds table (``src/data/tld_abuse.json``).

    Args:
        args: Parsed arguments.

    Returns:
        Exit code.
    """
    from src.eval.dataset import load_dataset, select_split
    from src.eval.tld_stats import tld_table

    manifest, samples = load_dataset(Path(args.dataset))
    selected = select_split(samples, args.split)
    table = tld_table(manifest, args.split, selected, min_samples=args.min_samples)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(table, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    ranked = sorted(table["tlds"].items(), key=lambda item: -item[1]["log_odds"])
    print(
        json.dumps(
            {
                "out": str(out),
                "counts": table["counts"],
                "most_abused": {tld: row["log_odds"] for tld, row in ranked[:10]},
            },
            indent=2,
        )
    )
    return 0


def _vector_cache_candidates(manifest: Dict[str, Any], predictor: str = "heuristic") -> List[Path]:
    """Cache files of ``predictor`` runs on this dataset, newest first."""
    prefix = f"{predictor}-{manifest['name']}-{manifest['version']}-"
    return sorted(
        (p for p in DEFAULT_CACHE.glob(f"{prefix}*.jsonl") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )


def _load_vector_cache(cache: Path) -> Dict[str, Dict[str, float]]:
    """``fusion_features`` by sample id from a prediction cache.

    Args:
        cache: JSONL cache written by ``run`` (predictions carry the vector).

    Returns:
        The vectors of every prediction that has one.
    """
    vectors: Dict[str, Dict[str, float]] = {}
    for line in cache.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        features = record.get("fusion_features") or {}
        if features:
            vectors[str(record["sample_id"])] = {str(k): float(v) for k, v in features.items()}
    return vectors


def _resolve_vector_cache(manifest: Dict[str, Any], explicit: Optional[str]) -> Optional[Path]:
    """The cache to train/gate on: explicit file or the newest with vectors."""
    if explicit:
        path = Path(explicit)
        if not path.exists():
            raise SystemExit(f"cache not found: {path}")
        return path
    for candidate in _vector_cache_candidates(manifest):
        if _load_vector_cache(candidate):
            return candidate
    return None


def _fusion_dataset(
    dataset: str, split: str, cache_arg: Optional[str]
) -> Tuple[Dict[str, Any], List, Path, Dict[str, Dict[str, float]]]:
    """Load a split and the fusion vectors of its samples from a cache."""
    from src.eval.dataset import load_dataset, select_split

    manifest, samples = load_dataset(Path(dataset))
    selected = sorted(select_split(samples, split), key=lambda s: s.id)
    cache = _resolve_vector_cache(manifest, cache_arg)
    if cache is None:
        raise SystemExit(
            "no prediction cache with fusion_features for "
            f"{manifest['name']}-{manifest['version']} -- first score the split with "
            "`python -m src.eval run <dataset> --predictor heuristic --split "
            f"{split}` (the new code stores the vector in the cache)"
        )
    return manifest, selected, cache, _load_vector_cache(cache)


def cmd_train_fusion(args: argparse.Namespace) -> int:
    """Fit and write the calibrated fusion artifact from cached scan vectors."""
    from src.detection.fusion import MODELS_DIR, train_model

    manifest, selected, cache, vectors_by_id = _fusion_dataset(args.dataset, args.split, args.cache)
    vectors: List[Dict[str, float]] = []
    labels: List[int] = []
    missing = 0
    for sample in selected:
        vector = vectors_by_id.get(sample.id)
        if not vector:
            missing += 1
            continue
        vectors.append(vector)
        labels.append(1 if sample.is_positive else 0)
    if missing:
        print(
            f"note: {missing} sample(s) of the split have no vector in the cache "
            "(scans made before the fusion existed) and are left out",
            file=sys.stderr,
        )
    model, metrics = train_model(
        vectors,
        labels,
        dataset={
            "name": manifest["name"],
            "version": manifest["version"],
            "split": args.split,
            "cache": cache.name,
            "samples": len(vectors),
            "positives": sum(labels),
            # The runtime refuses to report with a different capture engine:
            # a calibration fitted on fetch captures does not hold for
            # real-browser captures.
            "capture_engine": ("browser" if any(v.get("g_browser") for v in vectors) else "fetch"),
        },
        min_precision=args.min_precision,
    )
    out = Path(args.artifact) if args.artifact else MODELS_DIR / "fusion-v1.json"
    # The artifact's name is the model's id (fusion-v1.json -> "fusion-v1"):
    # detector_version and the demo read it verbatim.
    model.model_id = out.stem
    model.save(out)
    print(
        json.dumps(
            {
                "artifact": str(out),
                "gate": None,
                "dataset": model.dataset,
                "metrics": metrics,
            },
            indent=2,
        )
    )
    return 0


def cmd_gate(args: argparse.Namespace) -> int:
    """Evaluate the activation gate and write its verdict into the artifact.

    The fusion may report the deployed verdict only when, on the split's
    ``auto_report`` operating point, its precision is at least the baseline's,
    its recall is higher and its false-positive rate is not worse. Otherwise the
    artifact keeps the fusion in shadow (stored, never reported).
    """
    from src.detection.fusion import DEFAULT_ARTIFACT, FusionModel
    from src.eval.predictors import Prediction, ordinal_score
    from src.eval.report import _configured_auto_report_confidence, verdict_block

    artifact = Path(args.artifact) if args.artifact else DEFAULT_ARTIFACT
    if not artifact.exists():
        raise SystemExit(f"no fusion artifact at {artifact} -- run train-fusion first")
    model = FusionModel.load(artifact)

    manifest, selected, cache, vectors_by_id = _fusion_dataset(args.dataset, args.split, args.cache)
    predictions: List[Prediction] = []
    scored: List = []
    missing = 0
    for sample in selected:
        vector = vectors_by_id.get(sample.id)
        if not vector:
            missing += 1
            continue
        result = model.predict_vector(vector)
        level = str(result["level"])
        confidence = int(result["confidence"])
        predictions.append(
            Prediction(
                sample_id=sample.id,
                level=level,
                confidence=confidence,
                score=ordinal_score(level, confidence),
            )
        )
        scored.append(sample)
    if not predictions:
        raise SystemExit("no cached vectors for this split -- score it first (see run)")

    baseline_path = Path(args.baseline or DEFAULT_GATE_BASELINE)
    if not baseline_path.exists():
        raise SystemExit(f"baseline report not found: {baseline_path}")
    baseline_report = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline_ops = (
        baseline_report.get("verdicts", {})
        .get("deployed", {})
        .get("operating_points", {})
        .get("auto_report", {})
    )
    if not baseline_ops:
        raise SystemExit(f"baseline report has no auto_report point: {baseline_path}")

    min_confidence = (
        args.auto_report_confidence
        if args.auto_report_confidence is not None
        else _configured_auto_report_confidence()
    )
    fusion_block = verdict_block(scored, predictions, auto_report_min_confidence=min_confidence)
    fusion_ops = fusion_block["operating_points"]["auto_report"]

    def _precision(ops: Dict[str, Any]) -> Optional[float]:
        return ops.get("precision") if (ops.get("tp", 0) + ops.get("fp", 0)) else None

    base_precision = _precision(baseline_ops)
    fusion_precision = _precision(fusion_ops)
    # An operating point that flagged nothing has no measurable precision; the
    # conservative reading for the gate is "perfect" (nothing wrong flagged).
    base_for_rule = 1.0 if base_precision is None else base_precision
    fusion_for_rule = 1.0 if fusion_precision is None else fusion_precision
    passed = (
        fusion_for_rule >= base_for_rule
        and float(fusion_ops.get("recall") or 0) > float(baseline_ops.get("recall") or 0)
        and float(fusion_ops.get("fpr") or 0) <= float(baseline_ops.get("fpr") or 0) + 1e-12
    )
    gate = {
        "passed": bool(passed),
        "evaluated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "rule": "auto_report: precision >= baseline, recall > baseline, fpr <= baseline",
        "auto_report_min_confidence": min_confidence,
        "baseline": {
            "report": str(baseline_path),
            "predictor": baseline_report.get("predictor"),
            "auto_report": baseline_ops,
            "pr_auc": baseline_report.get("verdicts", {}).get("deployed", {}).get("pr_auc"),
        },
        "fusion": {
            "model_id": model.model_id,
            "cache": cache.name,
            "auto_report": fusion_ops,
            "pr_auc": fusion_block["pr_auc"],
            "coverage": fusion_block["coverage"],
        },
        "missing_vectors": missing,
    }
    model.gate = gate
    model.save(artifact)
    print(
        json.dumps(
            {
                "artifact": str(artifact),
                "gate": {k: gate[k] for k in ("passed", "rule")},
                "baseline_auto_report": {
                    k: baseline_ops.get(k)
                    for k in ("tp", "fp", "fn", "tn", "precision", "recall", "fpr")
                },
                "fusion_auto_report": {
                    k: fusion_ops.get(k)
                    for k in ("tp", "fp", "fn", "tn", "precision", "recall", "fpr")
                },
                "fusion_pr_auc": fusion_block["pr_auc"],
                "missing_vectors": missing,
                "mode": "active" if passed else "shadow",
            },
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Define the command line.

    Returns:
        The argument parser.
    """
    parser = argparse.ArgumentParser(
        prog="python -m src.eval",
        description="Evaluation harness: datasets, detection-quality runs, operational metrics.",
    )
    parser.add_argument("--verbose", action="store_true", help="show the detector's INFO logs")
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build", help="assemble a versioned dataset")
    build.add_argument("--name", default="baseline")
    build.add_argument(
        "--version", default=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    )
    build.add_argument("--out", default=str(DEFAULT_DATASETS))
    build.add_argument("--seeds", default=str(DEFAULT_SEEDS))
    build.add_argument("--cache", default=str(DEFAULT_CACHE))
    build.add_argument("--tranco-top", type=int, default=500, help="0 disables Tranco")
    build.add_argument("--tranco-list-id", default=None)
    build.add_argument("--no-feeds", action="store_true", help="skip the OpenPhish feed")
    build.add_argument("--feed-limit", type=int, default=None)
    build.add_argument("--no-db", action="store_true", help="skip analyst labels")
    build.add_argument("--skip-liveness", action="store_true", help="do not probe candidates")
    build.add_argument("--workers", type=int, default=16)
    build.add_argument("--timeout", type=int, default=10)
    build.add_argument("--max-per-kit", type=int, default=20)
    build.add_argument("--test-fraction", type=float, default=0.3)
    build.set_defaults(handler=cmd_build)

    verify = commands.add_parser("verify", help="check a dataset against its manifest")
    verify.add_argument("dataset")
    verify.set_defaults(handler=cmd_verify)

    run = commands.add_parser("run", help="score a split and write report.json/report.html")
    run.add_argument("dataset")
    run.add_argument("--predictor", choices=("live", "heuristic", "stored"), default="live")
    run.add_argument("--split", choices=("test", "train", "all"), default="test")
    run.add_argument("--limit", type=int, default=None, help="score the first N samples (by id)")
    run.add_argument("--max-scans", type=int, default=None, help="new scans this run (resumable)")
    run.add_argument("--workers", type=int, default=4)
    run.add_argument("--cache", default=str(DEFAULT_CACHE))
    run.add_argument(
        "--reuse-cache",
        default=None,
        metavar="FILE",
        help="score with the cached scans of an earlier run (no new scans)",
    )
    run.add_argument(
        "--judge",
        action="store_true",
        help="also ask the LLM judge on each capture and report its verdict "
        "(needs LLM_JUDGE_API_KEY; billed within LLM_JUDGE_DAILY_BUDGET_USD)",
    )
    run.add_argument("--costs", default=str(DEFAULT_COSTS))
    run.add_argument("--targets", default=str(DEFAULT_TARGETS), help='"" disables the check')
    run.add_argument(
        "--auto-report-confidence",
        type=int,
        default=None,
        help="confidence of the auto_report operating point (default: "
        "AUTO_REPORT_THRESHOLD_CONFIDENCE)",
    )
    run.add_argument("--out", default=str(DEFAULT_RUNS))
    run.set_defaults(handler=cmd_run)

    train_fusion = commands.add_parser(
        "train-fusion",
        help="fit the calibrated fusion artifact from a split's cached vectors",
    )
    train_fusion.add_argument("dataset")
    train_fusion.add_argument("--split", choices=("train", "test", "all"), default="train")
    train_fusion.add_argument(
        "--cache",
        default=None,
        metavar="FILE",
        help="prediction cache with fusion_features (default: newest heuristic cache)",
    )
    train_fusion.add_argument(
        "--artifact", default=None, help="artifact to write (default: models/fusion-v1.json)"
    )
    train_fusion.add_argument(
        "--min-precision",
        type=float,
        default=0.90,
        help="precision the high threshold must keep on out-of-fold predictions",
    )
    train_fusion.set_defaults(handler=cmd_train_fusion)

    gate = commands.add_parser(
        "gate", help="evaluate the fusion's activation gate against a baseline report"
    )
    gate.add_argument("dataset")
    gate.add_argument("--split", choices=("test", "train", "all"), default="test")
    gate.add_argument(
        "--cache",
        default=None,
        metavar="FILE",
        help="prediction cache with fusion_features (default: newest heuristic cache)",
    )
    gate.add_argument(
        "--artifact", default=None, help="artifact to gate (default: models/fusion-v1.json)"
    )
    gate.add_argument(
        "--baseline",
        default=None,
        metavar="FILE",
        help="baseline report.json (default: the phase 1 run on the phase2 dataset)",
    )
    gate.add_argument(
        "--auto-report-confidence",
        type=int,
        default=None,
        help="confidence of the auto_report operating point (default: configured)",
    )
    gate.set_defaults(handler=cmd_gate)

    tld = commands.add_parser(
        "tld-stats", help="write the per-TLD phishing log-odds table from a dataset split"
    )
    tld.add_argument("dataset")
    tld.add_argument("--split", choices=("train", "test", "all"), default="train")
    tld.add_argument("--min-samples", type=int, default=5)
    tld.add_argument("--out", default=str(DEFAULT_TLD_ABUSE))
    tld.set_defaults(handler=cmd_tld_stats)

    ops = commands.add_parser("ops", help="operational metrics of the configured database")
    ops.add_argument("--days", type=int, default=30)
    ops.add_argument("--targets", default=str(DEFAULT_TARGETS), help='"" disables the check')
    ops.add_argument("--out", default=None, help="also write the JSON to this file")
    ops.set_defaults(handler=cmd_ops)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the command line.

    Args:
        argv: Arguments (default: ``sys.argv[1:]``).

    Returns:
        Exit code.
    """
    args = build_parser().parse_args(argv)
    if args.verbose:
        return int(args.handler(args))
    # Quiet the scanners' INFO chatter for the run only; callers keep their levels.
    loggers = [logging.getLogger(), logging.getLogger("app")]
    previous = [lg.level for lg in loggers]
    for lg in loggers:
        lg.setLevel(logging.WARNING)
    try:
        return int(args.handler(args))
    finally:
        for lg, level in zip(loggers, previous):
            lg.setLevel(level)


if __name__ == "__main__":
    sys.exit(main())
