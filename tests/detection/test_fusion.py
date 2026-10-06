"""Calibrated fusion: vector, model, calibration, floors, coverage, runtime (phase 2, WS8)."""

import json
from unittest.mock import patch

import numpy as np
import pytest

from src.detection.fusion import (
    COVERAGE_WEIGHTS,
    DEFAULT_THRESHOLDS,
    FEATURE_NAMES,
    FusionModel,
    _Isotonic,
    average_precision,
    feature_vector,
    fit_logistic,
    fit_platt,
    fuse_scan,
    roc_auc,
    train_model,
)


def _scan(**overrides):
    """A comprehensive-scan result carrying one signal of every group."""
    scan = {
        "url": "http://paypall-seguro.login.example.xyz/verify",
        "url_analysis": {
            "risk_score": 72,
            "typosquatting": {"detected": True},
            "homoglyphs": {"detected": False},
            "combo_squatting": {"detected": True},
            "tld_swap": {"detected": False},
            "suspicious_tld": {"detected": True},
            "excessive_subdomains": {"detected": False},
        },
        "whois": {"domain_age_days": 4},
        "virustotal": {"status": "no_data"},
        "urlvoid": {"status": "error"},
        "phishtank": {"status": "not_listed", "is_phishing": False},
        "google_safe_browsing": {"status": "no_data"},
        "capture": {"status": "ok", "http_status": 200, "tls_valid": False},
        "page_features": {
            "credential_form": True,
            "password_fields": 2,
            "otp_fields": 1,
            "card_fields": 0,
            "external_form_actions": 1,
            "kit_traits": {"t1": "high"},
            "lure_hits": 4,
            "title_brands": ["paypal"],
            "text_brands": ["paypal"],
            "text_chars": 4200,
            "trackers": {"ga4": ["G-ABC12345"]},
            "qr_urls": [],
            "missing_hsts": True,
            "missing_csp": True,
            "redirect_hops": 2,
            "cross_domain_redirect": False,
            "final_domain_differs": False,
        },
        "visual_brand": {
            "top_brand": "paypal",
            "top_score": 0.9,
            "official_brand": None,
            "brand_domain_mismatch": True,
            "credential_form_for_other_brand": True,
        },
        "kit_fingerprint": {"kit_type": "evilginx3", "confidence": 80},
    }
    scan.update(overrides)
    return scan


class TestFeatureVector:
    def test_every_feature_present_and_read(self):
        vector = feature_vector(_scan())
        assert set(vector) == set(FEATURE_NAMES)
        assert vector["lex_risk_score"] == pytest.approx(0.72)
        assert vector["lex_typosquatting"] == 1.0
        assert vector["g_domain"] == 1.0 and vector["dom_age_log"] > 0
        assert vector["dom_young_30d"] == 1.0
        assert vector["g_intel"] == 1.0  # phishtank answered not_listed
        assert vector["intel_answered"] == pytest.approx(1 / 5)
        assert vector["intel_vt_listed"] == 0.0  # no_data is not an answer
        assert vector["g_capture"] == 1.0 and vector["cap_tls_invalid"] == 1.0
        assert vector["cap_redirect_hops"] == pytest.approx(0.2)
        assert vector["con_credential_form"] == 1.0
        assert vector["con_password_fields"] == pytest.approx(2 / 3)
        assert vector["vis_brand_domain_mismatch"] == 1.0
        assert vector["kit_detected"] == 1.0 and vector["kit_confidence"] == pytest.approx(0.8)
        assert vector["g_judge"] == 0.0  # no judge ran

    def test_absent_groups_carry_their_indicator(self):
        vector = feature_vector({"url": "http://no-data.example/"})
        assert vector["g_domain"] == 0.0
        assert vector["g_intel"] == 0.0
        assert vector["g_capture"] == 0.0
        assert vector["g_content"] == 0.0
        assert vector["g_visual"] == 0.0
        assert vector["g_kit"] == 0.0
        assert vector["g_judge"] == 0.0
        assert all(vector[name] == 0.0 for name in FEATURE_NAMES if name.startswith("lex_"))

    def test_judge_group_when_the_judge_ran(self):
        scan = _scan(llm_judge={"status": "ok", "verdict": {"is_phishing": True, "confidence": 88}})
        vector = feature_vector(scan)
        assert vector["g_judge"] == 1.0
        assert vector["judge_phishing"] == 1.0
        assert vector["judge_confidence"] == pytest.approx(0.88)

    def test_a_failed_judge_is_absent_not_innocent(self):
        scan = _scan(llm_judge={"status": "error", "verdict": {}})
        assert feature_vector(scan)["g_judge"] == 0.0

    def test_provider_errors_are_not_listings(self):
        scan = _scan(
            virustotal={"status": "error", "error": "boom"},
            urlvoid={"status": "error", "error": "boom"},
            phishtank={"status": "error", "error": "boom"},
            google_safe_browsing={"status": "error", "error": "boom"},
        )
        vector = feature_vector(scan)
        assert vector["g_intel"] == 0.0
        assert vector["intel_listed_count"] == 0.0

    def test_tld_abuse_feature_is_bounded(self):
        vector = feature_vector(_scan(url="http://login-account.example.cm/"))
        # The exact log-odds come from src/data/tld_abuse.json; whatever it is,
        # the feature stays inside the documented bounds.
        assert -8.0 <= vector["lex_tld_abuse"] <= 8.0


class TestNumericCore:
    def test_logistic_separates_linear_data(self):
        rng = np.random.default_rng(3)
        x_pos = rng.normal(loc=2.0, scale=0.5, size=(200, 1))
        x_neg = rng.normal(loc=-2.0, scale=0.5, size=(200, 1))
        x = np.vstack([x_pos, x_neg])
        y = np.hstack([np.ones(200), np.zeros(200)])
        w, b = fit_logistic(x, y, l2=0.1)
        accuracy = (((x @ w + b) > 0) == (y == 1)).mean()
        assert accuracy > 0.99

    def test_ridge_shrinks_the_weights(self):
        rng = np.random.default_rng(4)
        x = rng.normal(size=(300, 3))
        y = (x[:, 0] > 0).astype(float)
        w_weak, _ = fit_logistic(x, y, l2=10.0)
        w_strong, _ = fit_logistic(x, y, l2=0.01)
        assert np.linalg.norm(w_weak) < np.linalg.norm(w_strong)

    def test_isotonic_pools_violators_and_stays_monotone(self):
        scores = np.array([0.1, 0.2, 0.3, 0.4, 0.8, 0.9])
        targets = np.array([0.0, 0.0, 1.0, 0.0, 1.0, 1.0])
        iso = _Isotonic.fit(scores, targets)
        out = iso.predict(np.array([0.05, 0.25, 0.35, 0.45, 0.85]))
        assert np.all(np.diff(out) >= 0)
        # The (0.3, 1) and (0.4, 0) violators pool to their mean; a score inside
        # that block (0.35) and one past its end (0.45) read the right block.
        assert list(out) == pytest.approx([0.0, 0.5, 0.5, 1.0, 1.0])
        assert out[3] == pytest.approx(1.0)

    def test_platt_pulls_an_overconfident_logit_back(self):
        logits = np.array([-12.0, -11.0, 11.0, 12.0])
        targets = np.array([0.0, 1.0, 0.0, 1.0])  # far from 0/1: badly calibrated
        a, b = fit_platt(logits, targets)
        p = 1.0 / (1.0 + np.exp(-(a * logits + b)))
        assert abs(p.mean() - 0.5) < 0.05  # base rate recovered

    def test_average_precision_and_roc_auc_known_values(self):
        y = [1, 1, 0, 0]
        assert average_precision(y, [0.9, 0.8, 0.3, 0.1]) == pytest.approx(1.0)
        assert roc_auc(y, [0.9, 0.8, 0.3, 0.1]) == pytest.approx(1.0)
        # Perfect ranking inverted: hits at ranks 3 and 4 of 4.
        assert average_precision(y, [0.1, 0.2, 0.8, 0.9]) == pytest.approx((1 / 3 + 2 / 4) / 2)
        assert average_precision([0, 0], [0.1, 0.2]) == 0.0  # no positives: not resolvable


def _synthetic(n_pos=60, n_neg=600, seed=7):
    rng = np.random.default_rng(seed)
    vectors, labels = [], []
    for _ in range(n_pos):
        row = dict.fromkeys(FEATURE_NAMES, 0.0)
        row.update(
            lex_typosquatting=1.0,
            con_credential_form=1.0,
            g_content=1.0,
            vis_brand_domain_mismatch=1.0,
            g_visual=1.0,
            g_capture=1.0,
            lex_tld_abuse=float(rng.uniform(0.5, 3.0)),
        )
        vectors.append(row)
        labels.append(1)
    for _ in range(n_neg):
        row = dict.fromkeys(FEATURE_NAMES, 0.0)
        row.update(g_content=1.0, g_visual=1.0, g_capture=1.0, g_domain=1.0)
        vectors.append(row)
        labels.append(0)
    return vectors, labels


class TestTraining:
    def test_trains_calibrates_and_records_metrics(self):
        vectors, labels = _synthetic()
        model, metrics = train_model(vectors, labels, dataset={"name": "synthetic"})
        assert metrics["cv"]["average_precision_oof"] > 0.9
        assert metrics["positives"] == 60 and metrics["samples"] == len(vectors)
        assert 0.50 <= model.thresholds["high"] <= 0.85
        assert model._calibration_kind == "platt"  # 60 positives < 150
        assert model.gate is None and not model.is_active()

    def test_needs_enough_positives(self):
        vectors, labels = _synthetic(n_pos=4)
        with pytest.raises(ValueError, match="positives"):
            train_model(vectors, labels)

    def test_threshold_keeps_the_asked_precision(self):
        vectors, labels = _synthetic()
        model, metrics = train_model(vectors, labels, min_precision=0.90)
        at = metrics["at_high_threshold"]
        precision = at["tp"] / (at["tp"] + at["fp"]) if (at["tp"] + at["fp"]) else 1.0
        assert precision >= 0.90


class TestFloorsAndLevels:
    def _trained(self):
        vectors, labels = _synthetic()
        model, _ = train_model(vectors, labels)
        return model

    def test_gsb_and_phishtank_listings_floor_at_97(self):
        model = self._trained()
        benign = dict.fromkeys(FEATURE_NAMES, 0.0)
        gsb = dict(benign, intel_gsb_listed=1.0)
        pt = dict(benign, intel_pt_verified=1.0)
        assert model.predict_vector(gsb)["probability"] >= 0.97
        assert model.predict_vector(gsb)["floors_applied"] == ["gsb_listed"]
        assert model.predict_vector(pt)["floors_applied"] == ["phishtank_verified"]

    def test_visual_mismatch_plus_form_floors_at_90(self):
        model = self._trained()
        row = dict.fromkeys(FEATURE_NAMES, 0.0)
        row.update(vis_brand_domain_mismatch=1.0, con_credential_form=1.0)
        result = model.predict_vector(row)
        assert result["probability"] >= 0.90
        assert result["floors_applied"] == ["visual_mismatch_form"]

    def test_mismatch_without_a_form_is_not_a_floor(self):
        model = self._trained()
        row = dict.fromkeys(FEATURE_NAMES, 0.0)
        row["vis_brand_domain_mismatch"] = 1.0
        assert "visual_mismatch_form" not in model.floors_of(row)

    def test_kit_family_floors_at_critical(self):
        model = self._trained()
        row = dict.fromkeys(FEATURE_NAMES, 0.0)
        row["kit_detected"] = 1.0
        result = model.predict_vector(row)
        # The rules short-circuit a kit to critical; the fusion floor (>= 0.9
        # per the plan) sits at 0.97 so an active fusion never downgrades it.
        assert result["floors_applied"] == ["kit_family"]
        assert result["probability"] >= 0.97 and result["level"] == "critical"

    def test_homoglyphs_floor_at_critical(self):
        model = self._trained()
        row = dict.fromkeys(FEATURE_NAMES, 0.0)
        row["lex_homoglyphs"] = 1.0
        result = model.predict_vector(row)
        assert result["floors_applied"] == ["homoglyphs"]
        assert result["probability"] >= 0.97

    def test_clean_requires_coverage(self):
        model = self._trained()
        poor = dict.fromkeys(FEATURE_NAMES, 0.0)  # lexical only
        well = dict.fromkeys(FEATURE_NAMES, 0.0)
        well.update(g_content=1.0, g_visual=1.0, g_capture=1.0, g_domain=1.0)
        assert model.predict_vector(poor)["level"] == "unknown"
        assert model.predict_vector(poor)["confidence"] == 0
        assert model.predict_vector(well)["level"] == "clean"
        assert model.predict_vector(well)["confidence"] >= 50

    def test_coverage_is_the_weighted_present_share(self):
        model = self._trained()
        row = dict.fromkeys(FEATURE_NAMES, 0.0)
        row.update(g_intel=1.0, g_capture=1.0)
        expected = (
            COVERAGE_WEIGHTS["lexical"] + COVERAGE_WEIGHTS["intel"] + COVERAGE_WEIGHTS["capture"]
        ) / sum(COVERAGE_WEIGHTS.values())
        assert model.coverage_of(row) == pytest.approx(expected, abs=1e-3)

    def test_level_thresholds(self):
        model = self._trained()
        model.thresholds = dict(DEFAULT_THRESHOLDS)  # the versioned defaults
        assert model.level_of(0.99, 1.0) == "critical"
        assert model.level_of(DEFAULT_THRESHOLDS["high"], 1.0) == "high"
        assert model.level_of(0.6, 1.0) == "medium"
        assert model.level_of(0.2, 1.0) == "low"
        assert model.level_of(0.01, 1.0) == "clean"
        assert model.level_of(0.01, 0.0) == "unknown"


class TestArtifact:
    def test_json_roundtrip_scores_identically(self, tmp_path):
        vectors, labels = _synthetic()
        model, _ = train_model(vectors, labels)
        path = tmp_path / "fusion-v1.json"
        model.save(path)
        reloaded = FusionModel.load(path)
        for vector in vectors[:20]:
            assert reloaded.predict_vector(vector) == model.predict_vector(vector)

    def test_artifact_carries_provenance_and_gate(self, tmp_path):
        vectors, labels = _synthetic()
        model, _ = train_model(
            vectors, labels, dataset={"name": "d", "version": "2", "split": "train"}
        )
        model.gate = {"passed": True}
        path = tmp_path / "fusion-v1.json"
        model.save(path)
        data = json.loads(path.read_text())
        assert data["dataset"] == {"name": "d", "version": "2", "split": "train"}
        assert data["gate"]["passed"] is True
        assert FusionModel.load(path).is_active() is True

    def test_thresholds_are_versioned_in_the_artifact(self, tmp_path):
        vectors, labels = _synthetic()
        model, _ = train_model(vectors, labels)
        path = tmp_path / "fusion-v1.json"
        model.save(path)
        data = json.loads(path.read_text())
        assert set(DEFAULT_THRESHOLDS) <= set(data["thresholds"])


class TestRuntime:
    def _model(self, passed):
        vectors, labels = _synthetic()
        model, _ = train_model(vectors, labels)
        model.gate = {"passed": passed} if passed is not None else None
        return model

    def test_no_model_no_fusion(self):
        with patch("src.detection.fusion.get_deployed_model", return_value=None):
            assert fuse_scan(_scan()) is None

    def test_shadow_mode_stores_but_does_not_report(self):
        model = self._model(passed=None)
        with patch("src.detection.fusion.get_deployed_model", return_value=model):
            result = fuse_scan(_scan())
        assert result is not None and result["active"] is False

    def test_active_gate_reports(self):
        model = self._model(passed=True)
        with patch("src.detection.fusion.get_deployed_model", return_value=model):
            result = fuse_scan(_scan())
        assert result["active"] is True

    def test_deployed_model_reads_the_artifact_and_the_switch(self, tmp_path):
        from src.config import settings
        from src.detection import fusion

        model = self._model(passed=True)
        artifact = tmp_path / "fusion-v1.json"
        model.save(artifact)
        with (
            patch.object(settings, "FUSION_MODEL_PATH", str(artifact)),
            patch.object(settings, "FUSION_ENABLED", True),
        ):
            fusion._cached_model.cache_clear()
            deployed = fusion.get_deployed_model()
            assert deployed is not None and deployed.is_active()
        with (
            patch.object(settings, "FUSION_MODEL_PATH", str(artifact)),
            patch.object(settings, "FUSION_ENABLED", False),
        ):
            fusion._cached_model.cache_clear()
            assert fusion.get_deployed_model() is None  # the kill switch wins
        fusion._cached_model.cache_clear()


class TestComprehensiveScanIntegration:
    def _validator(self):
        from src.eval.predictors import offline_validator

        return offline_validator()

    @staticmethod
    def _dead_capture(url):
        from src.capture.service import PageCapture

        return PageCapture(url=url, status="error", error="ConnectionError")

    def test_engine_mismatch_demotes_to_shadow(self):
        """A model trained on fetch captures must not report browser captures."""
        vectors, labels = _synthetic()
        model, _ = train_model(vectors, labels)
        model.gate = {"passed": True}
        model.dataset = {"capture_engine": "fetch"}
        browser_scan = _scan(capture_engine="browser", capture_profiles={"bot": {}})
        result = model.predict_scan(browser_scan)
        assert result["active"] is False
        assert "engine mismatch" in result["inactive_reason"]
        fetch_scan = _scan(capture_engine="fetch")
        assert model.predict_scan(fetch_scan)["active"] is True

    def test_scan_without_a_model_keeps_its_shape(self, monkeypatch):
        monkeypatch.setattr("src.detection.fusion.get_deployed_model", lambda: None)
        with patch("src.intelligence.multi_api_validator.fetch_page", self._dead_capture):
            scan = self._validator().comprehensive_scan("https://dead.example/")
        assert "fusion" not in scan
        assert "heuristic_level" not in scan
        assert scan["aggregated_threat_level"] == "unknown"  # phase 1 abstention

    def test_scan_with_shadow_fusion_keeps_the_rules_verdict(self, monkeypatch):
        vectors, labels = _synthetic()
        model, _ = train_model(vectors, labels)  # gate None -> shadow
        monkeypatch.setattr("src.detection.fusion.get_deployed_model", lambda: model)
        with patch("src.intelligence.multi_api_validator.fetch_page", self._dead_capture):
            scan = self._validator().comprehensive_scan("https://dead.example/")
        assert scan["fusion"]["active"] is False
        assert scan["aggregated_threat_level"] == "unknown"
        assert "heuristic_level" in scan and "heuristic_confidence" in scan
        assert "fusion" in scan["stage_timings_ms"]

    def test_scan_with_active_fusion_reports_its_level(self, monkeypatch):
        vectors, labels = _synthetic()
        model, _ = train_model(vectors, labels)
        model.gate = {"passed": True}
        monkeypatch.setattr("src.detection.fusion.get_deployed_model", lambda: model)
        # Force a confident phishing probability through the calibrator.
        monkeypatch.setattr(
            model,
            "predict_scan",
            lambda scan: {
                "model_id": model.model_id,
                "probability": 0.93,
                "coverage": 0.7,
                "level": "high",
                "confidence": 93,
                "floors_applied": [],
                "active": True,
            },
        )
        with patch("src.intelligence.multi_api_validator.fetch_page", self._dead_capture):
            scan = self._validator().comprehensive_scan("https://dead.example/")
        assert scan["aggregated_threat_level"] == "high"
        assert scan["confidence_score"] == 93
        assert scan["heuristic_level"] == "unknown"  # the rules still abstain
