"""Calibrated fusion of every signal of a comprehensive scan (phase 2, WS8).

The fusion turns the signals a scan already produced -- lexical analysis, WHOIS,
threat intel, page capture, content features, brand identification, kit
fingerprint and the optional LLM judge -- into one calibrated probability of
phishing, plus the coverage of the evidence behind it.

Design (docs/ROADMAP.md, phase 2):

* every signal group carries its own missing indicator: an absent source is
  neither clean nor malicious, it is *absent* (``stage_status`` semantics);
* the model is a logistic regression with L2 regularisation fitted in numpy
  (log-odds), calibrated with Platt scaling -- isotonic (PAV) when the train
  split has enough positives -- over cross-validated predictions;
* strong signals set floors on the calibrated probability (a GSB or verified
  PhishTank listing never fuses below 0.97);
* probability and coverage are reported separately: ``clean`` is only allowed
  with enough coverage, otherwise the level is ``unknown``;
* the versioned artifact (``src/detection/models/fusion-v*.json``) carries the
  weights, the calibration, the thresholds, the dataset hash and the activation
  gate's verdict. The gate is the single source of truth: unless it says
  ``passed`` the fusion runs in shadow (stored, never reported).

The training and gating commands live in ``src/eval`` (``train-fusion``,
``gate``); this module only fits, scores and loads.
"""

from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

import numpy as np

from src.detection.normalize import normalize_host, tld_abuse

logger = logging.getLogger(__name__)

# Where the versioned artifacts live and which one the runtime picks by default.
MODELS_DIR = Path(__file__).resolve().parent / "models"
DEFAULT_ARTIFACT = MODELS_DIR / "fusion-v1.json"

ARTIFACT_VERSION = 1
MODEL_ID = "fusion-v1"

# --- Signal groups -----------------------------------------------------------
#
# Every feature is a float in [0, 1] (or a small log-odds for the TLD table).
# ``g_<group>`` features are the missing indicators: 1 = the group produced
# data, 0 = it did not (absent, never clean).

FEATURE_NAMES: Tuple[str, ...] = (
    # Lexical (always present).
    "lex_risk_score",
    "lex_typosquatting",
    "lex_homoglyphs",
    "lex_combo_squatting",
    "lex_tld_swap",
    "lex_suspicious_tld",
    "lex_excessive_subdomains",
    "lex_tld_abuse",
    # Domain / WHOIS.
    "g_domain",
    "dom_age_log",
    "dom_young_30d",
    "dom_young_365d",
    # Threat intel.
    "g_intel",
    "intel_answered",
    "intel_listed_count",
    "intel_vt_listed",
    "intel_uv_listed",
    "intel_pt_listed",
    "intel_gsb_listed",
    "intel_pt_verified",
    "intel_vt_threat_ratio",
    # Capture.
    "g_capture",
    "cap_tls_invalid",
    "cap_non_200",
    "cap_redirect_hops",
    "cap_cross_domain_redirect",
    "cap_final_domain_differs",
    # Content.
    "g_content",
    "con_credential_form",
    "con_password_fields",
    "con_otp_fields",
    "con_card_fields",
    "con_external_form_actions",
    "con_kit_traits",
    "con_lure_hits",
    "con_title_brands",
    "con_text_brands",
    "con_text_chars_log",
    "con_trackers",
    "con_qr_code",
    "con_missing_hsts",
    "con_missing_csp",
    # Visual brand identification.
    "g_visual",
    "vis_brand_identified",
    "vis_top_score",
    "vis_brand_domain_mismatch",
    "vis_credential_form_other_brand",
    "vis_official_brand_host",
    # Kit fingerprint.
    "g_kit",
    "kit_detected",
    "kit_confidence",
    # LLM judge.
    "g_judge",
    "judge_phishing",
    "judge_confidence",
    # Multi-profile browser capture (WS3): cloaking divergences and walls.
    "g_browser",
    "cloaking_final_url_divergence",
    "cloaking_text_divergence",
    "cloaking_visual_divergence",
    "cloaking_bot_served_different",
    "captcha_cloudflare_challenge",
    "captcha_recaptcha",
    "captcha_turnstile",
)

# Group membership (for coverage) and how much each group weighs.
GROUPS: Dict[str, Tuple[str, ...]] = {
    "lexical": tuple(n for n in FEATURE_NAMES if n.startswith("lex_")),
    "domain": ("g_domain", *(n for n in FEATURE_NAMES if n.startswith("dom_"))),
    "intel": ("g_intel", *(n for n in FEATURE_NAMES if n.startswith("intel_"))),
    "capture": ("g_capture", *(n for n in FEATURE_NAMES if n.startswith("cap_"))),
    "content": ("g_content", *(n for n in FEATURE_NAMES if n.startswith("con_"))),
    "visual": ("g_visual", *(n for n in FEATURE_NAMES if n.startswith("vis_"))),
    "kit": ("g_kit", *(n for n in FEATURE_NAMES if n.startswith("kit_"))),
    "judge": ("g_judge", *(n for n in FEATURE_NAMES if n.startswith("judge_"))),
    "browser": (
        "g_browser",
        *(n for n in FEATURE_NAMES if n.startswith(("cloaking_", "captcha_"))),
    ),
}
COVERAGE_WEIGHTS: Dict[str, float] = {
    "lexical": 0.14,
    "domain": 0.14,
    "intel": 0.18,
    "capture": 0.14,
    "content": 0.14,
    "visual": 0.09,
    "kit": 0.05,
    "judge": 0.05,
    "browser": 0.07,
}

# Floors: a strong signal pins the calibrated probability from below. Kit and
# homoglyph sit at 0.97 (critical): the rules short-circuit both to critical
# and an active fusion must never downgrade the strongest evidence -- both
# satisfy the plan's ">= 0.9" minimum for kits.
FLOOR_GSB_LISTED = 0.97
FLOOR_PT_VERIFIED = 0.97
FLOOR_VISUAL_MISMATCH_FORM = 0.90
FLOOR_KIT_FAMILY = 0.97
FLOOR_HOMOGLYPHS = 0.97

# Level thresholds (versioned in the artifact; ``high`` is chosen by training
# inside [0.50, 0.85] so the auto-report confidence rule stays reachable).
DEFAULT_THRESHOLDS: Dict[str, float] = {
    "low": 0.10,
    "medium": 0.50,
    "high": 0.85,
    "critical": 0.97,
    "min_clean_coverage": 0.55,
}
# Below this many positives, Platt beats isotonic on variance.
ISOTONIC_MIN_POSITIVES = 150

LEVELS = ("clean", "low", "medium", "high", "critical", "unknown")


def _clip01(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _detected(analysis: Mapping[str, Any], key: str) -> float:
    return 1.0 if (analysis.get(key) or {}).get("detected") else 0.0


def feature_vector(scan: Mapping[str, Any]) -> Dict[str, float]:
    """Build the fusion feature vector of a comprehensive scan.

    Args:
        scan: Result of ``MultiAPIValidator.comprehensive_scan``.

    Returns:
        Every :data:`FEATURE_NAMES` key as a float, ``0.0`` when the source was
        absent (its ``g_<group>`` indicator carries the absence).
    """
    # Provider statuses are classified exactly as the scan itself does.
    from src.intelligence.multi_api_validator import gsb_status, provider_status

    vector: Dict[str, float] = dict.fromkeys(FEATURE_NAMES, 0.0)

    url = str(scan.get("url") or "")
    analysis = scan.get("url_analysis") or {}
    lexical_present = bool(analysis) and not analysis.get("error")
    if lexical_present:
        vector["lex_risk_score"] = _clip01((analysis.get("risk_score") or 0) / 100)
        for key, name in (
            ("typosquatting", "lex_typosquatting"),
            ("homoglyphs", "lex_homoglyphs"),
            ("combo_squatting", "lex_combo_squatting"),
            ("tld_swap", "lex_tld_swap"),
            ("suspicious_tld", "lex_suspicious_tld"),
            ("excessive_subdomains", "lex_excessive_subdomains"),
        ):
            vector[name] = _detected(analysis, key)
    abuse = tld_abuse(normalize_host(url)) if url else None
    if abuse is not None:
        vector["lex_tld_abuse"] = max(-8.0, min(8.0, float(abuse)))

    whois = scan.get("whois") or {}
    if whois:
        vector["g_domain"] = 1.0
        age = whois.get("domain_age_days")
        if age is not None:
            try:
                age = float(age)
            except (TypeError, ValueError):
                age = None
        if age is not None:
            vector["dom_age_log"] = math.log1p(min(max(age, 0.0), 36500.0)) / 10.0
            vector["dom_young_30d"] = 1.0 if age < 30 else 0.0
            vector["dom_young_365d"] = 1.0 if age < 365 else 0.0

    statuses = {
        "virustotal": provider_status(scan.get("virustotal") or {}),
        "urlvoid": provider_status(scan.get("urlvoid") or {}),
        "phishtank": provider_status(scan.get("phishtank") or {}),
        "google_safe_browsing": gsb_status(scan.get("google_safe_browsing") or {}),
    }
    answered = [s for s in statuses.values() if s in ("listed", "not_listed")]
    if answered:
        vector["g_intel"] = 1.0
        vector["intel_answered"] = min(len(answered), 5) / 5.0
        vector["intel_listed_count"] = min(sum(1 for s in answered if s == "listed"), 4) / 4.0
        vector["intel_vt_listed"] = 1.0 if statuses["virustotal"] == "listed" else 0.0
        vector["intel_uv_listed"] = 1.0 if statuses["urlvoid"] == "listed" else 0.0
        vector["intel_pt_listed"] = 1.0 if statuses["phishtank"] == "listed" else 0.0
        vector["intel_gsb_listed"] = 1.0 if statuses["google_safe_browsing"] == "listed" else 0.0
        pt = scan.get("phishtank") or {}
        vector["intel_pt_verified"] = (
            1.0 if statuses["phishtank"] == "listed" and pt.get("verified") else 0.0
        )
        vt = scan.get("virustotal") or {}
        try:
            threats = float(vt.get("threat_count") or 0)
        except (TypeError, ValueError):
            threats = 0.0
        vector["intel_vt_threat_ratio"] = min(max(threats, 0.0), 20.0) / 20.0

    features = scan.get("page_features") or {}
    capture = scan.get("capture") or {}
    capture_ok = capture.get("status") == "ok"
    if capture_ok:
        vector["g_capture"] = 1.0
        vector["cap_tls_invalid"] = 1.0 if capture.get("tls_valid") is False else 0.0
        http_status = capture.get("http_status")
        vector["cap_non_200"] = 1.0 if http_status is not None and http_status != 200 else 0.0
        try:
            hops = float(features.get("redirect_hops") or 0)
        except (TypeError, ValueError):
            hops = 0.0
        vector["cap_redirect_hops"] = min(max(hops, 0.0), 10.0) / 10.0
        vector["cap_cross_domain_redirect"] = 1.0 if features.get("cross_domain_redirect") else 0.0
        vector["cap_final_domain_differs"] = 1.0 if features.get("final_domain_differs") else 0.0

    if "credential_form" in features:
        vector["g_content"] = 1.0
        vector["con_credential_form"] = 1.0 if features.get("credential_form") else 0.0
        for key, name, cap in (
            ("password_fields", "con_password_fields", 3),
            ("otp_fields", "con_otp_fields", 2),
            ("card_fields", "con_card_fields", 2),
            ("external_form_actions", "con_external_form_actions", 3),
        ):
            try:
                vector[name] = min(float(features.get(key) or 0), cap) / cap
            except (TypeError, ValueError):
                vector[name] = 0.0
        kit_traits = features.get("kit_traits") or {}
        vector["con_kit_traits"] = min(len(kit_traits), 3) / 3.0
        try:
            vector["con_lure_hits"] = min(float(features.get("lure_hits") or 0), 10) / 10.0
        except (TypeError, ValueError):
            vector["con_lure_hits"] = 0.0
        vector["con_title_brands"] = min(len(features.get("title_brands") or []), 3) / 3.0
        vector["con_text_brands"] = min(len(features.get("text_brands") or []), 3) / 3.0
        try:
            vector["con_text_chars_log"] = (
                math.log1p(min(float(features.get("text_chars") or 0), 20000)) / 12.0
            )
        except (TypeError, ValueError):
            vector["con_text_chars_log"] = 0.0
        trackers = features.get("trackers") or {}
        vector["con_trackers"] = min(sum(len(v) for v in trackers.values()), 5) / 5.0
        vector["con_qr_code"] = 1.0 if features.get("qr_urls") else 0.0
        vector["con_missing_hsts"] = 1.0 if features.get("missing_hsts") else 0.0
        vector["con_missing_csp"] = 1.0 if features.get("missing_csp") else 0.0

    brand = scan.get("visual_brand") or {}
    if capture_ok and "top_brand" in brand:
        vector["g_visual"] = 1.0
        top = brand.get("top_brand")
        vector["vis_brand_identified"] = 1.0 if top else 0.0
        try:
            vector["vis_top_score"] = _clip01(brand.get("top_score") or 0.0)
        except (TypeError, ValueError):
            vector["vis_top_score"] = 0.0
        vector["vis_brand_domain_mismatch"] = 1.0 if brand.get("brand_domain_mismatch") else 0.0
        vector["vis_credential_form_other_brand"] = (
            1.0 if brand.get("credential_form_for_other_brand") else 0.0
        )
        vector["vis_official_brand_host"] = 1.0 if brand.get("official_brand") else 0.0

    kit = scan.get("kit_fingerprint") or {}
    if kit:
        vector["g_kit"] = 1.0
        vector["kit_detected"] = 1.0 if kit.get("kit_type") else 0.0
        try:
            vector["kit_confidence"] = _clip01((kit.get("confidence") or 0) / 100)
        except (TypeError, ValueError):
            vector["kit_confidence"] = 0.0

    judge = scan.get("llm_judge")
    if isinstance(judge, Mapping) and judge.get("status") == "ok":
        vector["g_judge"] = 1.0
        verdict = judge.get("verdict") or {}
        decision = verdict.get("is_phishing")
        vector["judge_phishing"] = 1.0 if decision else 0.0
        try:
            vector["judge_confidence"] = _clip01((verdict.get("confidence") or 0) / 100)
        except (TypeError, ValueError):
            vector["judge_confidence"] = 0.0

    # Multi-profile browser capture (WS3): cloaking divergences between the
    # profiles and the human-verification walls the primary profile met.
    cloaking = scan.get("cloaking")
    if isinstance(cloaking, Mapping) and cloaking.get("measured_profiles"):
        vector["g_browser"] = 1.0
        vector["cloaking_final_url_divergence"] = (
            1.0 if cloaking.get("final_url_divergence") else 0.0
        )
        vector["cloaking_text_divergence"] = 1.0 if cloaking.get("text_divergence") else 0.0
        vector["cloaking_visual_divergence"] = 1.0 if cloaking.get("visual_divergence") else 0.0
        vector["cloaking_bot_served_different"] = (
            1.0 if cloaking.get("bot_served_different_content") else 0.0
        )
    walls = features.get("captcha_walls")
    if isinstance(walls, Mapping) and any(walls.values()):
        vector["g_browser"] = 1.0
        vector["captcha_cloudflare_challenge"] = 1.0 if walls.get("cloudflare_challenge") else 0.0
        vector["captcha_recaptcha"] = 1.0 if walls.get("recaptcha") else 0.0
        vector["captcha_turnstile"] = 1.0 if walls.get("turnstile") else 0.0

    return vector


# --- Numeric core (numpy, no sklearn) ----------------------------------------


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -35.0, 35.0)))


def fit_logistic(
    x: np.ndarray, y: np.ndarray, l2: float = 1.0, max_iter: int = 100
) -> Tuple[np.ndarray, float]:
    """Fit a logistic regression by Newton's method with an L2 ridge.

    The intercept is not penalised. Converges in a handful of iterations at
    this problem size (few thousand rows, few dozen features).

    Args:
        x: Feature matrix ``(n, d)``.
        y: Targets ``(n,)`` in {0, 1}.
        l2: Ridge strength.
        max_iter: Iteration cap.

    Returns:
        ``(weights (d,), bias)``.
    """
    n, d = x.shape
    w = np.zeros(d)
    b = 0.0
    eye = np.eye(d + 1)
    eye[d, d] = 0.0  # the bias row stays unpenalised
    for _ in range(max_iter):
        p = _sigmoid(x @ w + b)
        grad = p - y
        grad_w = x.T @ grad + l2 * w
        grad_b = float(grad.sum())
        weight = np.clip(p * (1.0 - p), 1e-6, None)
        hessian = np.empty((d + 1, d + 1))
        hessian[:d, :d] = (x * weight[:, None]).T @ x + l2 * np.eye(d)
        hessian[:d, d] = x.T @ weight
        hessian[d, :d] = hessian[:d, d]
        hessian[d, d] = float(weight.sum()) + 1e-9
        gradient = np.concatenate([grad_w, [grad_b]])
        try:
            step = np.linalg.solve(hessian, gradient)
        except np.linalg.LinAlgError:  # singular (e.g. separated classes)
            step = np.linalg.lstsq(hessian + 1e-6 * eye, gradient, rcond=None)[0]
        w = w - step[:d]
        b = b - float(step[d])
        if float(np.max(np.abs(step))) < 1e-10:
            break
    return w, b


def fit_platt(logits: np.ndarray, y: np.ndarray) -> Tuple[float, float]:
    """Platt scaling: a one-feature logistic on the model's log-odds.

    Args:
        logits: Uncalibrated log-odds ``(n,)``.
        y: Targets ``(n,)``.

    Returns:
        ``(a, b)`` with ``p = sigmoid(a * logit + b)``.
    """
    a, b = fit_logistic(logits.reshape(-1, 1), y, l2=1e-6)
    return float(a[0]), float(b)


@dataclass
class _Isotonic:
    """Isotonic regression (pool-adjacent-violators) as a step function."""

    boundaries: np.ndarray  # (k+1,) ascending score boundaries
    values: np.ndarray  # (k,) fitted value per block

    @classmethod
    def fit(cls, scores: np.ndarray, y: np.ndarray) -> "_Isotonic":
        order = np.argsort(scores, kind="stable")
        xs, ys = scores[order], y[order]
        # Blocks of (sum_y, count) merged until non-decreasing.
        sums: List[float] = []
        counts: List[int] = []
        bounds: List[float] = []
        for i in range(len(ys)):
            sums.append(float(ys[i]))
            counts.append(1)
            bounds.append(xs[i])
            while len(sums) > 1 and sums[-2] / counts[-2] > sums[-1] / counts[-1]:
                sums[-2] += sums[-1]
                counts[-2] += counts[-1]
                sums.pop()
                counts.pop()
                # The surviving block extends to the NEW point: its boundary is
                # the last score of the merged pair, so drop the previous one.
                bounds.pop(-2)
        values = np.array([s / c for s, c in zip(sums, counts)], dtype=float)
        boundaries = np.array(bounds, dtype=float)
        return cls(boundaries=boundaries, values=values)

    def predict(self, scores: np.ndarray) -> np.ndarray:
        # side="left": a score belongs to the block whose (prev, last] range
        # contains it -- x strictly between two block boundaries lands in the
        # LATER block, whose value is the fitted value for that range.
        idx = np.searchsorted(self.boundaries, scores, side="left")
        idx = np.clip(idx, 0, len(self.values) - 1)
        return self.values[idx]

    def to_dict(self) -> Dict[str, List[float]]:
        return {
            "boundaries": [round(float(v), 6) for v in self.boundaries],
            "values": [round(float(v), 6) for v in self.values],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Sequence[float]]) -> "_Isotonic":
        return cls(
            boundaries=np.array(data["boundaries"], dtype=float),
            values=np.array(data["values"], dtype=float),
        )


def average_precision(
    y: Union[Sequence[int], np.ndarray], scores: Union[Sequence[float], np.ndarray]
) -> float:
    """Area under the precision-recall curve (average precision)."""
    y_arr = np.asarray(y, dtype=int)
    scores_arr = np.asarray(scores, dtype=float)
    positives = int(y_arr.sum())
    if positives == 0 or y_arr.size == 0:
        return 0.0
    order = np.argsort(-scores_arr, kind="stable")
    hits, precision_sum = 0, 0.0
    for rank, idx in enumerate(order, start=1):
        if y_arr[idx]:
            hits += 1
            precision_sum += hits / rank
    return float(precision_sum / positives)


def roc_auc(
    y: Union[Sequence[int], np.ndarray], scores: Union[Sequence[float], np.ndarray]
) -> float:
    """Area under the ROC curve by rank statistic."""
    positives = [s for s, label in zip(scores, y) if label]
    negatives = [s for s, label in zip(scores, y) if not label]
    if not positives or not negatives:
        return 0.5
    order = np.argsort(np.asarray(scores), kind="stable")
    ranks = np.empty(len(scores), dtype=float)
    ranks[order] = np.arange(1, len(scores) + 1)
    rank_sum = sum(ranks[i] for i in range(len(y)) if y[i])
    n_pos, n_neg = len(positives), len(negatives)
    return float((rank_sum - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def _stratified_folds(y: np.ndarray, k: int, seed: int) -> np.ndarray:
    """Round-robin fold assignment, positives and negatives separately."""
    rng = np.random.default_rng(seed)
    folds = np.empty(len(y), dtype=int)
    for label in (0, 1):
        indexes = np.flatnonzero(y == label)
        rng.shuffle(indexes)
        folds[indexes] = np.arange(len(indexes)) % k
    return folds


# --- Model -------------------------------------------------------------------


class FusionModel:
    """A trained, calibrated fusion: vector in, probability/coverage out."""

    def __init__(
        self,
        model_id: str = MODEL_ID,
        features: Optional[Sequence[Mapping[str, Any]]] = None,
        weights: Optional[Union[Sequence[float], np.ndarray]] = None,
        bias: float = 0.0,
        l2: float = 1.0,
        calibration: Optional[Mapping[str, Any]] = None,
        thresholds: Optional[Mapping[str, float]] = None,
        dataset: Optional[Mapping[str, Any]] = None,
        metrics: Optional[Mapping[str, Any]] = None,
        gate: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.model_id = model_id
        self.features = list(features or [])
        self.weights = (
            np.asarray(weights, dtype=float)
            if weights is not None and len(weights) > 0
            else np.zeros(len(self.features))
        )
        self.bias = float(bias)
        self.l2 = float(l2)
        self.thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
        self.dataset = dict(dataset or {})
        self.metrics = dict(metrics or {})
        self.gate = dict(gate) if gate else None

        self._names = [f["name"] for f in self.features]
        self._mean = np.array([f["mean"] for f in self.features], dtype=float)
        self._std = np.array([max(float(f["std"]), 1e-9) for f in self.features])
        calibration = calibration or {"kind": "platt", "a": 1.0, "b": 0.0}
        self._calibration_kind = str(calibration.get("kind", "platt"))
        if self._calibration_kind == "isotonic":
            self._isotonic = _Isotonic.from_dict(calibration)
            self._platt = (1.0, 0.0)
        else:
            self._isotonic = None
            self._platt = (float(calibration.get("a", 1.0)), float(calibration.get("b", 0.0)))

    # -- scoring ------------------------------------------------------

    def _raw_logit(self, vector: Mapping[str, float]) -> float:
        row = np.array([float(vector.get(name, 0.0)) for name in self._names], dtype=float)
        z = (row - self._mean) / self._std
        return float(self.weights @ z + self.bias)

    def floors_of(self, vector: Mapping[str, float]) -> List[str]:
        """Strong signals whose floor applies to this vector."""
        floors: List[str] = []
        if vector.get("intel_gsb_listed"):
            floors.append("gsb_listed")
        if vector.get("intel_pt_verified"):
            floors.append("phishtank_verified")
        if vector.get("vis_brand_domain_mismatch") and vector.get("con_credential_form"):
            floors.append("visual_mismatch_form")
        if vector.get("kit_detected"):
            floors.append("kit_family")
        if vector.get("lex_homoglyphs"):
            floors.append("homoglyphs")
        return floors

    @staticmethod
    def floor_value(name: str) -> float:
        return {
            "gsb_listed": FLOOR_GSB_LISTED,
            "phishtank_verified": FLOOR_PT_VERIFIED,
            "visual_mismatch_form": FLOOR_VISUAL_MISMATCH_FORM,
            "kit_family": FLOOR_KIT_FAMILY,
            "homoglyphs": FLOOR_HOMOGLYPHS,
        }[name]

    def coverage_of(self, vector: Mapping[str, float]) -> float:
        """Weighted share of signal groups that produced data."""
        total = sum(COVERAGE_WEIGHTS.values())
        present = 0.0
        for group, names in GROUPS.items():
            indicator = f"g_{group}" if group != "lexical" else None
            if group == "lexical":
                present += COVERAGE_WEIGHTS[group]  # always present
            elif indicator and vector.get(indicator):
                present += COVERAGE_WEIGHTS[group]
        return round(present / total, 3) if total else 0.0

    def level_of(self, probability: float, coverage: float) -> str:
        """Level from a calibrated probability and its coverage."""
        t = self.thresholds
        if probability >= t["critical"]:
            return "critical"
        if probability >= t["high"]:
            return "high"
        if probability >= t["medium"]:
            return "medium"
        if probability >= t["low"]:
            return "low"
        if coverage >= t["min_clean_coverage"]:
            return "clean"
        return "unknown"

    def predict_vector(self, vector: Mapping[str, float]) -> Dict[str, Any]:
        """Score one feature vector.

        Args:
            vector: :func:`feature_vector` output.

        Returns:
            ``{"model_id", "probability", "coverage", "level", "confidence",
            "floors_applied", "active"}``.
        """
        logit = self._raw_logit(vector)
        if self._isotonic is not None:
            probability = float(self._isotonic.predict(np.array([logit]))[0])
        else:
            a, b = self._platt
            probability = float(_sigmoid(np.array([a * logit + b]))[0])
        floors = self.floors_of(vector)
        for name in floors:
            probability = max(probability, self.floor_value(name))
        probability = float(np.clip(probability, 0.0, 1.0))
        coverage = self.coverage_of(vector)
        level = self.level_of(probability, coverage)
        if level == "unknown":
            confidence = 0
        else:
            confidence = int(round(100.0 * max(probability, 1.0 - probability)))
        return {
            "model_id": self.model_id,
            "probability": round(probability, 4),
            "coverage": coverage,
            "level": level,
            "confidence": confidence,
            "floors_applied": floors,
            "active": self.is_active(),
        }

    def predict_scan(self, scan: Mapping[str, Any]) -> Dict[str, Any]:
        """Score one comprehensive scan (vector built here).

        The fusion only reports (``active``) when the scan was captured with
        the SAME engine the model was trained on: a calibration fitted on
        plain-fetch captures does not hold for real-browser captures (JS
        rendering changes the feature distribution) -- an engine mismatch
        demotes the verdict to shadow, with the reason.
        """
        result = self.predict_vector(feature_vector(scan))
        trained_on = str((self.dataset or {}).get("capture_engine") or "fetch")
        scan_engine = str(
            scan.get("capture_engine") or ("browser" if scan.get("capture_profiles") else "fetch")
        )
        if scan_engine != trained_on:
            result["active"] = False
            result["inactive_reason"] = (
                f"capture engine mismatch: trained on {trained_on}, scanned with {scan_engine}"
            )
        return result

    def is_active(self) -> bool:
        """Whether the activation gate lets this model report the verdict."""
        return bool(self.gate and self.gate.get("passed"))

    # -- persistence --------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        calibration: Dict[str, Any]
        if self._isotonic is not None:
            calibration = {"kind": "isotonic", **self._isotonic.to_dict()}
        else:
            calibration = {"kind": "platt", "a": self._platt[0], "b": self._platt[1]}
        return {
            "model_id": self.model_id,
            "artifact_version": ARTIFACT_VERSION,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "features": [
                {"name": name, "mean": float(m), "std": float(s)}
                for name, m, s in zip(self._names, self._mean, self._std)
            ],
            "weights": [round(float(w), 8) for w in self.weights],
            "bias": round(self.bias, 8),
            "l2": self.l2,
            "calibration": calibration,
            "thresholds": dict(self.thresholds),
            "dataset": self.dataset,
            "metrics": self.metrics,
            "gate": self.gate,
        }

    def save(self, path: Path) -> None:
        """Write the artifact (pretty, sorted, deterministic order)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = self.to_dict()
        path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n")

    @classmethod
    def load(cls, path: Path) -> "FusionModel":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            model_id=str(data.get("model_id") or MODEL_ID),
            features=data.get("features") or [],
            weights=data.get("weights") or [],
            bias=float(data.get("bias") or 0.0),
            l2=float(data.get("l2") or 1.0),
            calibration=data.get("calibration"),
            thresholds=data.get("thresholds"),
            dataset=data.get("dataset"),
            metrics=data.get("metrics"),
            gate=data.get("gate"),
        )


# --- Training ----------------------------------------------------------------


def train_model(
    vectors: Sequence[Mapping[str, float]],
    labels: Sequence[int],
    dataset: Optional[Mapping[str, Any]] = None,
    min_precision: float = 0.90,
    k_folds: int = 5,
    l2_grid: Sequence[float] = (0.03, 0.1, 0.3, 1.0, 3.0, 10.0),
    seed: int = 13,
) -> Tuple[FusionModel, Dict[str, Any]]:
    """Fit, calibrate and threshold the fusion.

    Args:
        vectors: Feature vectors (:func:`feature_vector` output).
        labels: 1 phishing / 0 benign, aligned with ``vectors``.
        dataset: Provenance stored in the artifact (name, version, split, hash...).
        min_precision: Precision the ``high`` threshold must keep on the
            out-of-fold predictions.
        k_folds: Stratified folds (lowered when positives are scarce).
        l2_grid: Ridge strengths tried by cross-validation.
        seed: Fold shuffling seed.

    Returns:
        The model and its cross-validation metrics.
    """
    if len(vectors) != len(labels):
        raise ValueError("vectors and labels must be aligned")
    positives = int(sum(labels))
    if positives < 5:
        raise ValueError(f"training needs at least 5 positives, got {positives}")

    names = list(FEATURE_NAMES)
    x_raw = np.array([[float(v.get(name, 0.0)) for name in names] for v in vectors], dtype=float)
    y = np.asarray(labels, dtype=float)
    mean = x_raw.mean(axis=0)
    std = x_raw.std(axis=0)
    std = np.where(std < 1e-9, 1.0, std)
    x = (x_raw - mean) / std

    k = max(2, min(k_folds, positives))
    folds = _stratified_folds(y.astype(int), k, seed)

    def out_of_fold(l2: float) -> np.ndarray:
        logits = np.zeros(len(y))
        for fold in range(k):
            train, test = folds != fold, folds == fold
            if not train.any() or not test.any():
                continue
            w, b = fit_logistic(x[train], y[train], l2=l2)
            logits[test] = x[test] @ w + b
        return logits

    chosen_l2: float = float(l2_grid[0])
    chosen_logits: np.ndarray = np.zeros(len(y))
    best_ap = -1.0
    for l2 in l2_grid:
        logits = out_of_fold(float(l2))
        ap = average_precision(y.astype(int), logits)
        if ap > best_ap:
            chosen_l2, chosen_logits, best_ap = float(l2), logits, ap

    # Calibrate on the out-of-fold log-odds; Platt unless positives are plenty.
    if positives >= ISOTONIC_MIN_POSITIVES:
        isotonic = _Isotonic.fit(chosen_logits, y)
        calibrated = isotonic.predict(chosen_logits)
        calibration: Dict[str, Any] = {"kind": "isotonic", **isotonic.to_dict()}
    else:
        a, b = fit_platt(chosen_logits, y)
        calibrated = _sigmoid(a * chosen_logits + b)
        calibration = {"kind": "platt", "a": round(a, 6), "b": round(b, 6)}

    # The ``high`` threshold: max recall with precision >= min_precision on the
    # out-of-fold calibrated scores, always <= 0.85 so ``confidence >= 85``
    # (the auto-report rule) stays reachable at the operating point.
    y_int = y.astype(int)
    best_threshold, best_recall = 0.85, -1.0
    for threshold in np.arange(0.50, 0.851, 0.01):
        flagged = calibrated >= threshold
        tp = int(np.sum(flagged & (y_int == 1)))
        fp = int(np.sum(flagged & (y_int == 0)))
        recall = tp / positives if positives else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        if precision >= min_precision and recall > best_recall:
            best_threshold, best_recall = round(float(threshold), 2), recall

    thresholds = dict(DEFAULT_THRESHOLDS)
    thresholds["high"] = best_threshold

    # Refit on the full training set with the chosen ridge.
    weights, bias = fit_logistic(x, y, l2=chosen_l2)
    features = [
        {"name": name, "mean": float(m), "std": float(s)} for name, m, s in zip(names, mean, std)
    ]
    metrics = {
        "cv": {
            "folds": k,
            "l2": chosen_l2,
            "chosen_by": "average_precision",
            "average_precision_oof": round(best_ap, 4),
            "roc_auc_oof": round(roc_auc(y_int, chosen_logits), 4),
            "brier_oof": round(float(np.mean((calibrated - y) ** 2)), 4),
        },
        "high_threshold": best_threshold,
        "at_high_threshold": _counts_at(calibrated, y_int, best_threshold),
        "positives": positives,
        "samples": int(len(y)),
    }
    model = FusionModel(
        model_id=MODEL_ID,
        features=features,
        weights=weights,
        bias=bias,
        l2=chosen_l2,
        calibration=calibration,
        thresholds=thresholds,
        dataset=dict(dataset or {}),
        metrics=metrics,
        gate=None,
    )
    return model, metrics


def _counts_at(scores: np.ndarray, y: np.ndarray, threshold: float) -> Dict[str, int]:
    flagged = scores >= threshold
    tp = int(np.sum(flagged & (y == 1)))
    fp = int(np.sum(flagged & (y == 0)))
    fn = int(np.sum(~flagged & (y == 1)))
    tn = int(np.sum(~flagged & (y == 0)))
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


# --- Runtime entry point -------------------------------------------------------


@lru_cache(maxsize=4)
def _cached_model(path: str, mtime: float, size: int) -> Optional[FusionModel]:
    try:
        return FusionModel.load(Path(path))
    except (OSError, ValueError, KeyError) as exc:
        logger.warning(f"Fusion artifact {path} unusable: {exc}")
        return None


def get_deployed_model() -> Optional[FusionModel]:
    """The model the runtime should consult, or None when fusion is off.

    Off means: ``FUSION_ENABLED`` is false, or no artifact exists yet. The
    artifact's own ``gate`` section decides whether the fusion may report the
    verdict (:meth:`FusionModel.is_active`); a failed gate leaves it in shadow.
    """
    from src.config import settings

    if not getattr(settings, "FUSION_ENABLED", True):
        return None
    path = Path(getattr(settings, "FUSION_MODEL_PATH", None) or DEFAULT_ARTIFACT)
    if not path.exists():
        return None
    stat = path.stat()
    return _cached_model(str(path), stat.st_mtime, stat.st_size)


def fuse_scan(scan: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Score a comprehensive scan with the deployed fusion model.

    Args:
        scan: Result of ``MultiAPIValidator.comprehensive_scan``.

    Returns:
        The fusion result (``probability``, ``coverage``, ``level``,
        ``confidence``, ``floors_applied``, ``active``), or None when no
        artifact is deployed. ``active`` is false while the activation gate
        has not passed: the fusion then runs in shadow (stored, not reported).
    """
    model = get_deployed_model()
    if model is None:
        return None
    return model.predict_scan(scan)
