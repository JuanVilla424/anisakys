"""Predictors: the detector's verdict on each evaluation sample.

* :class:`ScanPredictor` runs :meth:`MultiAPIValidator.comprehensive_scan`, the
  same multi-source analysis the deployed auto-analyzer uses, and records the
  verdict, its per-stage latency and which providers answered. Built with
  :func:`offline_validator` it becomes the ``heuristic`` predictor: every
  threat-intel provider is replaced by a stand-in that answers "no data", so
  only the lexical analysis, WHOIS age and kit fingerprint remain.
* :class:`StoredPredictor` reads the ``detector_snapshot`` an analyst label
  captured: what the deployed detector said when the analyst decided.

Each scan also yields the **heuristic level**: the aggregation of the same
signals without the "no external evidence means unknown" rule, i.e. what the
heuristics alone would conclude. Scores are ordinal (see
:data:`SCORE_DEFINITION`), not calibrated probabilities.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from src.eval.dataset import Sample, sanitize_url
from src.intelligence.provider_common import NO_DATA
from src.reporting.outbox import sanitize_error

LEVELS = ("unknown", "clean", "low", "medium", "high", "critical")
_LEVEL_BASE = {"clean": 0.1, "low": 0.3, "medium": 0.5, "high": 0.7, "critical": 0.9}
_MALICIOUS = frozenset({"medium", "high", "critical"})

SCORE_DEFINITION = (
    "Ordinal score in [0, 1]: unknown = 0; clean 0.1-0.2, low 0.3-0.4, medium 0.5-0.6, "
    "high 0.7-0.8, critical 0.9-1.0. Inside medium/high/critical a higher confidence "
    "raises the score; inside clean/low a higher confidence lowers it (more sure it is "
    "benign). The ranking follows the threat level first; it is not a calibrated "
    "probability (see the reliability diagram)."
)


def normalize_level(level: Any) -> str:
    """Map a stored or reported threat level onto :data:`LEVELS`.

    Args:
        level: Raw level.

    Returns:
        The level, or ``unknown`` for anything else.
    """
    value = str(level or "").strip().lower()
    return value if value in LEVELS else "unknown"


def ordinal_score(level: Any, confidence: Any) -> float:
    """Score a verdict (see :data:`SCORE_DEFINITION`).

    Args:
        level: Threat level.
        confidence: Confidence 0-100 (anything else counts as 0).

    Returns:
        The score in ``[0, 1]``.
    """
    normalized = normalize_level(level)
    if normalized == "unknown":
        return 0.0
    try:
        share = min(max(float(confidence or 0), 0.0), 100.0) / 100.0
    except (TypeError, ValueError):
        share = 0.0
    base = _LEVEL_BASE[normalized]
    bump = 0.1 * share if normalized in _MALICIOUS else 0.1 * (1.0 - share)
    return round(base + bump, 4)


def level_at_least(level: Any, minimum: str) -> bool:
    """Whether a verdict reaches an operating point (``unknown`` never does).

    Args:
        level: Threat level.
        minimum: Lowest level that counts as flagged.

    Returns:
        ``True`` when ``level`` is at least ``minimum``.
    """
    normalized = normalize_level(level)
    if normalized == "unknown":
        return False
    return LEVELS.index(normalized) >= LEVELS.index(minimum)


@dataclass
class Prediction:
    """The detector's output for one sample."""

    sample_id: str
    level: str
    confidence: int
    score: float
    heuristic_level: str = "unknown"
    heuristic_score: float = 0.0
    stage_timings_ms: Dict[str, float] = field(default_factory=dict)
    stage_status: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    # The LLM judge's verdict on the same capture (None when the judge did not run).
    judge_status: Optional[str] = None
    judge_level: str = "unknown"
    judge_confidence: int = 0
    judge_score: float = 0.0
    # Measured cost of stages billed per request (the judge), instead of a flat price.
    stage_costs_usd: Dict[str, float] = field(default_factory=dict)
    # Detection signals of the scan (lexical, capture, content, brand), each a yes/no.
    signals: Dict[str, bool] = field(default_factory=dict)
    # Feature vector the calibrated fusion consumes (src/detection/fusion.py);
    # empty for scans made before the fusion existed (old caches still load).
    fusion_features: Dict[str, float] = field(default_factory=dict)
    # How the page was captured: "browser" (multi-profile worker), "fetch" (plain
    # HTTP) or "" (pre-WS3 scans). A browser-model must not be trained on a mix.
    capture_engine: str = ""
    # Wall-clock milliseconds of the scan (None for scans whose stages ran one after
    # another, where the sum of the stages is the duration).
    total_ms: Optional[float] = None

    @property
    def covered(self) -> bool:
        """Whether the detector reached a verdict (anything but ``unknown``).

        Returns:
            ``True`` when the deployed verdict is known.
        """
        return self.level != "unknown"

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for the cache.

        Returns:
            The prediction as a dict.
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Prediction":
        """Build from a cache record.

        Args:
            data: Decoded record.

        Returns:
            The prediction.
        """
        return cls(
            sample_id=data["sample_id"],
            level=normalize_level(data.get("level")),
            confidence=int(data.get("confidence") or 0),
            score=float(data.get("score") or 0.0),
            heuristic_level=normalize_level(data.get("heuristic_level")),
            heuristic_score=float(data.get("heuristic_score") or 0.0),
            stage_timings_ms=dict(data.get("stage_timings_ms") or {}),
            stage_status=dict(data.get("stage_status") or {}),
            error=data.get("error"),
            judge_status=data.get("judge_status"),
            judge_level=normalize_level(data.get("judge_level")),
            judge_confidence=int(data.get("judge_confidence") or 0),
            judge_score=float(data.get("judge_score") or 0.0),
            stage_costs_usd={k: float(v) for k, v in (data.get("stage_costs_usd") or {}).items()},
            signals={k: bool(v) for k, v in (data.get("signals") or {}).items()},
            fusion_features={k: float(v) for k, v in (data.get("fusion_features") or {}).items()},
            capture_engine=str(data.get("capture_engine") or ""),
            total_ms=float(data["total_ms"]) if data.get("total_ms") is not None else None,
        )


def scan_signals(scan: Dict[str, Any]) -> Dict[str, bool]:
    """The yes/no detection signals of a scan, for the report's signal table.

    Args:
        scan: A ``comprehensive_scan`` result.

    Returns:
        Lexical, capture, content and brand signals; empty for scans made before the
        page capture existed (no capture, features or brand identification).
    """
    analysis = scan.get("url_analysis") or {}
    features = scan.get("page_features") or {}
    brand = scan.get("visual_brand") or {}
    capture = scan.get("capture") or {}
    if not (features or brand or capture):
        return {}

    def detected(key: str) -> bool:
        return bool((analysis.get(key) or {}).get("detected"))

    return {
        "capture_ok": capture.get("status") == "ok",
        "credential_form": bool(features.get("credential_form")),
        "external_form_action": bool(features.get("external_form_actions")),
        "kit_trait": bool(features.get("kit_traits")),
        "tracker_ids": bool(features.get("trackers")),
        "qr_code": bool(features.get("qr_urls")),
        "cross_domain_redirect": bool(features.get("cross_domain_redirect")),
        "brand_identified": bool(brand.get("top_brand")),
        "official_domain": bool(brand.get("official_brand")),
        "brand_domain_mismatch": bool(brand.get("brand_domain_mismatch")),
        "credential_form_for_other_brand": bool(brand.get("credential_form_for_other_brand")),
        "typosquatting": detected("typosquatting"),
        "combo_squatting": detected("combo_squatting"),
        "tld_swap": detected("tld_swap"),
        "homoglyphs": detected("homoglyphs"),
        "suspicious_tld": detected("suspicious_tld"),
    }


def prediction_from_scan(sample_id: str, scan: Dict[str, Any]) -> Prediction:
    """Turn a ``comprehensive_scan`` result into a prediction.

    Args:
        sample_id: Id of the scanned sample.
        scan: The scan result.

    Returns:
    The prediction, with the heuristic level recomputed from the same
    signals without the external-evidence rule, and the fusion feature
    vector of the scan (empty when the scan predates the fusion).
    """
    from src.detection.fusion import feature_vector
    from src.intelligence.multi_api_validator import MultiAPIValidator

    level = normalize_level(scan.get("aggregated_threat_level"))
    confidence = int(scan.get("confidence_score") or 0)
    signals = (
        scan.get("virustotal") or {},
        scan.get("urlvoid") or {},
        scan.get("phishtank") or {},
        (scan.get("whois") or {}).get("domain_age_days"),
        scan.get("url_analysis") or {},
        scan.get("google_safe_browsing") or {},
        scan.get("kit_fingerprint") or {},
    )
    heuristic_level = normalize_level(MultiAPIValidator._aggregate_threat_level(*signals))
    heuristic_confidence = MultiAPIValidator._calculate_confidence_score(*signals)
    prediction = Prediction(
        sample_id=sample_id,
        level=level,
        confidence=confidence,
        score=ordinal_score(level, confidence),
        heuristic_level=heuristic_level,
        heuristic_score=ordinal_score(heuristic_level, heuristic_confidence),
        stage_timings_ms={k: float(v) for k, v in (scan.get("stage_timings_ms") or {}).items()},
        stage_status={k: str(v) for k, v in (scan.get("stage_status") or {}).items()},
        signals=scan_signals(scan),
        fusion_features=feature_vector(scan),
        capture_engine=str(scan.get("capture_engine") or ""),
        total_ms=float(scan["scan_ms"]) if scan.get("scan_ms") is not None else None,
    )
    judgement = scan.get("llm_judge")
    if isinstance(judgement, dict):
        from src.detection.llm_judge import verdict_level

        verdict = judgement.get("verdict") if judgement.get("status") == "ok" else None
        judge_level, judge_confidence = verdict_level(verdict or {})
        prediction.judge_status = str(judgement.get("status") or "unknown")
        prediction.judge_level = judge_level
        prediction.judge_confidence = judge_confidence
        prediction.judge_score = ordinal_score(judge_level, judge_confidence)
        prediction.stage_costs_usd["llm_judge"] = float(judgement.get("cost_usd") or 0.0)
    return prediction


class _OfflineProvider:
    """Stand-in for every threat-intel client: never calls out, always "no data"."""

    _ANSWER = {"status": NO_DATA, "error": "provider disabled for heuristic evaluation"}

    def _no_data(self, *_args: Any, **_kwargs: Any) -> Dict[str, Any]:
        return dict(self._ANSWER)

    scan_url = _no_data
    get_domain_report = _no_data
    analyze_domain = _no_data
    check_phishing_status = _no_data
    check_url = _no_data


def offline_validator() -> Any:
    """A ``MultiAPIValidator`` whose threat-intel providers are all disabled.

    Returns:
        The validator (lexical analysis, WHOIS and kit fingerprint still run).
    """
    from src.intelligence.multi_api_validator import MultiAPIValidator

    # Typed as Any: the stand-in only mimics the client methods the scan calls.
    validator: Any = MultiAPIValidator()
    offline = _OfflineProvider()
    validator.virustotal = offline
    validator.urlvoid = offline
    validator.phishtank = offline
    validator.google_safe_browsing = offline
    return validator


def live_validator() -> Any:
    """The validator exactly as the deployed auto-analyzer builds it.

    Returns:
        A ``MultiAPIValidator`` configured from the settings.
    """
    from src.intelligence.multi_api_validator import MultiAPIValidator

    return MultiAPIValidator()


def judge_from_settings() -> Any:
    """The LLM judge for a measurement run, whether or not production has it enabled.

    Returns:
        An ``LLMJudge`` built from the ``LLM_JUDGE_*`` settings.

    Raises:
        ValueError: Without ``LLM_JUDGE_API_KEY``.
    """
    from src.config import settings
    from src.detection.llm_judge import JudgeConfig, LLMJudge

    config = JudgeConfig.from_settings(settings)
    if config is None:
        raise ValueError("measuring the judge needs LLM_JUDGE_API_KEY in the environment")
    return LLMJudge(config)


def with_judge(factory: Callable[[], Any], judge: Any) -> Callable[[], Any]:
    """Wrap a validator factory so every validator consults ``judge``.

    Args:
        factory: Builds a validator.
        judge: The judge shared by every worker (its state is thread-safe).

    Returns:
        The wrapped factory.
    """

    def build() -> Any:
        validator = factory()
        validator.judge = judge
        return validator

    return build


class ScanPredictor:
    """Scan each sample with a validator, caching results to resume long runs."""

    def __init__(
        self,
        name: str,
        validator_factory: Callable[[], Any],
        cache_path: Optional[Path] = None,
        workers: int = 1,
        max_scans: Optional[int] = None,
        progress: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """Create a predictor.

        Args:
            name: ``live`` or ``heuristic`` (reported).
            validator_factory: Builds one validator per worker thread.
            cache_path: JSONL file of finished predictions (reused, appended).
            workers: Parallel scans.
            max_scans: Stop after this many new scans (``None`` = all).
            progress: Called with ``(done, total)`` after each scan.
        """
        self.name = name
        self.validator_factory = validator_factory
        self.cache_path = cache_path
        self.workers = max(1, workers)
        self.max_scans = max_scans
        self.progress = progress
        self._local = threading.local()
        self._cache_lock = threading.Lock()

    def _validator(self) -> Any:
        """Return this thread's validator, creating it on first use.

        Returns:
            The validator.
        """
        validator = getattr(self._local, "validator", None)
        if validator is None:
            validator = self.validator_factory()
            self._local.validator = validator
        return validator

    def _load_cache(self) -> Dict[str, Prediction]:
        """Read finished predictions from the cache file.

        Returns:
            Predictions by sample id (empty without a cache).
        """
        if not self.cache_path or not self.cache_path.exists():
            return {}
        cached: Dict[str, Prediction] = {}
        for line in self.cache_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                prediction = Prediction.from_dict(json.loads(line))
                cached[prediction.sample_id] = prediction
        return cached

    def _store(self, prediction: Prediction) -> None:
        """Append a prediction to the cache file.

        Args:
            prediction: Finished prediction.
        """
        if not self.cache_path:
            return
        with self._cache_lock:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with self.cache_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(prediction.to_dict(), sort_keys=True) + "\n")

    def _scan(self, sample: Sample) -> Prediction:
        """Scan one sample; a failure becomes an ``unknown`` prediction.

        Args:
            sample: Sample to scan.

        Returns:
            The prediction.
        """
        try:
            scan = self._validator().comprehensive_scan(sample.url)
            return prediction_from_scan(sample.id, scan)
        except Exception as exc:
            return Prediction(
                sample_id=sample.id,
                level="unknown",
                confidence=0,
                score=0.0,
                error=sanitize_error(exc),
            )

    def predict(self, samples: Sequence[Sample]) -> List[Prediction]:
        """Predict every sample (cached ones are not scanned again).

        Args:
            samples: Samples to score.

        Returns:
            Predictions in the order of ``samples``; samples left out by
            ``max_scans`` have none.
        """
        cached = self._load_cache()
        pending = [s for s in samples if s.id not in cached]
        if self.max_scans is not None:
            pending = pending[: self.max_scans]
        done = len(samples) - len(pending)
        total = len(samples)
        results: Dict[str, Prediction] = dict(cached)
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._scan, sample): sample for sample in pending}
            for future in as_completed(futures):
                prediction = future.result()
                results[prediction.sample_id] = prediction
                self._store(prediction)
                done += 1
                if self.progress:
                    self.progress(done, total)
        return [results[s.id] for s in samples if s.id in results]


class StoredPredictor:
    """The verdict the deployed detector had stored when an analyst labelled the site."""

    name = "stored"

    def __init__(self, engine: Any) -> None:
        """Create a predictor.

        Args:
            engine: Engine of the database holding ``labels``.
        """
        self.engine = engine

    def predict(self, samples: Sequence[Sample]) -> List[Prediction]:
        """Look up the labelled snapshot of every sample.

        Args:
            samples: Samples to score.

        Returns:
            One prediction per sample; samples without a stored verdict are
            ``unknown`` (not covered).
        """
        from src.labels import LabelRepository

        snapshots: Dict[str, Dict[str, Any]] = {}
        for label in LabelRepository(self.engine).latest_per_url():
            clean = sanitize_url(label.url)
            if clean:
                snapshots[clean] = label.detector_snapshot
        predictions: List[Prediction] = []
        for sample in samples:
            snapshot = snapshots.get(sample.url, {})
            level = normalize_level(snapshot.get("multi_api_threat_level"))
            confidence = int(snapshot.get("api_confidence_score") or 0)
            predictions.append(
                Prediction(
                    sample_id=sample.id,
                    level=level,
                    confidence=confidence,
                    score=ordinal_score(level, confidence),
                )
            )
        return predictions
