"""Evaluation reports and the ``python -m src.eval`` command line."""

import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import patch

from src.eval.__main__ import main
from src.eval.dataset import make_sample
from src.eval.predictors import Prediction, ordinal_score
from src.eval.report import build_report, defang, render_html, stage_block, write_report


def _samples() -> List[Any]:
    rows = [
        ("https://paypal-login.example/", "feed_live_verified", "paypal"),
        ("https://nequi-pagos.example/", "feed_live_verified", "nequi"),
        ("https://www.paypal.com/", "official_brand", "paypal"),
        ("https://www.phase.com/", "homonym", None),
    ]
    samples = []
    for url, category, brand in rows:
        sample = make_sample(url, category, "test", brand=brand)
        assert sample is not None
        sample.split = "test"
        samples.append(sample)
    return samples


def _prediction(sample_id: str, level: str, heuristic: str, ms: float) -> Prediction:
    return Prediction(
        sample_id=sample_id,
        level=level,
        confidence=80,
        score=ordinal_score(level, 80),
        heuristic_level=heuristic,
        heuristic_score=ordinal_score(heuristic, 80),
        stage_timings_ms={"virustotal_url": ms, "whois": 2 * ms},
        stage_status={"virustotal_url": "listed" if level != "unknown" else "no_data"},
    )


def _report() -> Dict[str, Any]:
    samples = _samples()
    predictions = [
        _prediction(samples[0].id, "high", "high", 100.0),  # TP
        _prediction(samples[1].id, "unknown", "medium", 200.0),  # FN (not covered)
        _prediction(samples[2].id, "clean", "low", 300.0),  # TN
        _prediction(samples[3].id, "high", "high", 400.0),  # FP
    ]
    manifest = {"name": "unit", "version": "v1", "samples_sha256": "0" * 64}
    return build_report(
        manifest,
        "test",
        "live",
        samples,
        predictions,
        costs={"virustotal_url": 0.01},
        code_commit="abc1234",
        notes=["providers: virustotal=yes"],
    )


class TestReport:
    def test_operating_points_coverage_and_groups(self):
        report = _report()

        deployed = report["verdicts"]["deployed"]
        high = deployed["operating_points"]["level>=high"]
        assert (high["tp"], high["fp"], high["fn"], high["tn"]) == (1, 1, 1, 1)
        assert (high["precision"], high["recall"]) == (0.5, 0.5)
        assert deployed["coverage"] == {"covered": 3, "total": 4, "rate": 0.75}
        assert high["per_brand"]["paypal"]["samples"] == 2
        assert deployed["level_distribution"]["phishing"] == {"high": 1, "unknown": 1}
        assert [e["category"] for e in deployed["misclassified"]["false_positives"]] == ["homonym"]
        heuristic = report["verdicts"]["heuristic"]["operating_points"]["level>=medium"]
        assert heuristic["recall"] == 1.0  # the heuristics see the uncovered positive

    def test_stage_costs_count_only_real_calls(self):
        report = _report()

        stage = report["stages"]["virustotal_url"]
        assert stage["calls"] == 3  # the "no_data" stage asked nothing
        assert stage["cost_usd"] == 0.03
        assert stage["latency_ms"]["count"] == 4
        assert report["stages"]["total"]["cost_usd"] == 0.03

    def test_stage_block_without_predictions(self):
        assert stage_block([])["total"]["latency_ms"]["count"] == 0

    def test_overlapping_stages_report_the_wall_clock(self):
        sequential = _prediction("a", "high", "high", 100.0)  # stages 100 + 200 ms
        parallel = _prediction("b", "high", "high", 100.0)
        parallel.total_ms = 210.0  # the same stages, overlapping

        assert stage_block([sequential])["total"]["latency_ms"]["p50"] == 300.0
        assert stage_block([parallel])["total"]["latency_ms"]["p50"] == 210.0

    def test_html_is_self_contained_and_defangs_urls(self, tmp_path):
        report = _report()

        page = render_html(report)
        json_path, html_path = write_report(tmp_path, report)

        assert "<svg" in page and "Reliability" in page
        assert not re.search(r"""(src|href)=["']?https?://""", page)
        assert "hxxps[://]www[.]phase[.]com" in page
        assert json.loads(json_path.read_text())["counts"]["samples"] == 4
        assert html_path.read_text() == page

    def test_defang(self):
        assert defang("https://evil.example/x") == "hxxps[://]evil[.]example/x"

    def test_a_run_without_the_judge_has_no_judge_verdict(self):
        report = _report()

        assert "judge" not in report["verdicts"] and "judge" not in report
        assert "signals" not in report  # scans without captures carry no signals

    def test_signal_table(self):
        samples = _samples()
        predictions = [
            _prediction(s.id, "unknown", "unknown", 1.0) for s in samples
        ]  # TP-able, phishing, official, homonym
        predictions[0].signals = {"brand_domain_mismatch": True, "credential_form": True}
        predictions[1].signals = {"brand_domain_mismatch": False, "credential_form": True}
        predictions[2].signals = {"brand_domain_mismatch": False, "credential_form": True}
        predictions[3].signals = {"brand_domain_mismatch": False, "credential_form": False}
        manifest = {"name": "unit", "version": "v1", "samples_sha256": "0" * 64}

        report = build_report(manifest, "test", "live", samples, predictions)

        assert report["signals"] == {
            "brand_domain_mismatch": {
                "phishing": 1,
                "benign": 0,
                "precision": 1.0,
                "recall": 0.5,
                "fpr": 0.0,
            },
            "credential_form": {
                "phishing": 2,
                "benign": 1,
                "precision": 0.6667,
                "recall": 1.0,
                "fpr": 0.5,
            },
        }
        assert "Signals, each alone" in render_html(report)


def _judged_report() -> Dict[str, Any]:
    samples = _samples()
    predictions = [
        _prediction(samples[0].id, "high", "high", 100.0),
        _prediction(samples[1].id, "unknown", "medium", 200.0),
        _prediction(samples[2].id, "clean", "low", 300.0),
        _prediction(samples[3].id, "high", "high", 400.0),
    ]
    judged = [
        ("critical", 95, "ok", 0.002, "listed"),  # phishing, sure: auto-reported
        ("high", 80, "ok", 0.002, "listed"),  # phishing, below the auto-report confidence
        ("clean", 90, "ok", 0.002, "not_listed"),  # official brand page
        ("unknown", 0, "budget", 0.0, "no_data"),  # the budget was spent
    ]
    for prediction, (level, confidence, status, cost, stage) in zip(predictions, judged):
        prediction.judge_level, prediction.judge_confidence = level, confidence
        prediction.judge_status, prediction.judge_score = status, ordinal_score(level, confidence)
        prediction.stage_costs_usd = {"llm_judge": cost}
        prediction.stage_status["llm_judge"] = stage
        prediction.stage_timings_ms["llm_judge"] = 900.0
    manifest = {"name": "unit", "version": "v1", "samples_sha256": "0" * 64}
    return build_report(
        manifest,
        "test",
        "live+judge",
        samples,
        predictions,
        costs={"virustotal_url": 0.01, "llm_judge": 5.0},
        auto_report_min_confidence=85,
    )


class TestJudgeVerdict:
    def test_the_judge_is_scored_on_its_own(self):
        report = _judged_report()

        judge = report["verdicts"]["judge"]
        auto = judge["operating_points"]["auto_report"]
        assert (auto["tp"], auto["fp"], auto["fn"], auto["tn"]) == (1, 0, 1, 2)
        high = judge["operating_points"]["level>=high"]
        assert (high["precision"], high["recall"]) == (1.0, 1.0)
        assert judge["coverage"] == {"covered": 3, "total": 4, "rate": 0.75}
        # The deployed verdict is untouched by the judge.
        deployed = report["verdicts"]["deployed"]["operating_points"]["level>=high"]
        assert (deployed["tp"], deployed["fp"]) == (1, 1)

    def test_its_cost_is_the_measured_spend(self):
        report = _judged_report()

        assert report["judge"] == {
            "asked": 4,
            "status": {"ok": 3, "budget": 1},
            "decided": 3,
            "cost_usd": 0.006,
            "cost_per_decision_usd": 0.002,
        }
        assert report["stages"]["llm_judge"]["cost_usd"] == 0.006  # not 5.0 per call
        assert report["stages"]["total"]["cost_usd"] == round(0.03 + 0.006, 4)

    def test_html_shows_the_judge(self):
        page = render_html(_judged_report())

        assert "PR-AUC (LLM judge)" in page
        assert "Operating points — LLM judge alone" in page
        assert "budget 1" in page and "Evidence only" in page


class _CannedValidator:
    def comprehensive_scan(self, url: str) -> Dict[str, Any]:
        level = "high" if "pagos" in url or "login" in url else "clean"
        return {
            "aggregated_threat_level": level,
            "confidence_score": 75,
            "stage_timings_ms": {"url_analysis": 1.0},
            "stage_status": {"url_analysis": "not_listed"},
        }


class _JudgedValidator(_CannedValidator):
    """A canned scan that also carries the judge's verdict (what --judge adds)."""

    judge: Any = None

    def comprehensive_scan(self, url: str) -> Dict[str, Any]:
        scan = super().comprehensive_scan(url)
        phishing = "pagos" in url or "login" in url
        scan["llm_judge"] = {
            "status": "ok",
            "verdict": {"is_phishing": phishing, "confidence": 0.9},
            "cost_usd": 0.001,
        }
        return scan


def _seeds(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "official_brands.json").write_text(json.dumps({"brands": []}))
    (directory / "homonyms.txt").write_text("https://www.phase.com/\n")
    (directory / "benign_saas.txt").write_text("https://pages.github.com/\n")
    return directory


class TestCommandLine:
    def test_build_verify_and_run(self, tmp_path, capsys):
        seeds = _seeds(tmp_path / "seeds")
        out = tmp_path / "datasets"
        with patch(
            "src.intelligence.openphish.OpenPhishIntegration.fetch_feed",
            return_value={"https://nequi-pagos.example/", "https://bank-login.example/"},
        ):
            code = main(
                [
                    "build",
                    "--name",
                    "cli",
                    "--version",
                    "v1",
                    "--out",
                    str(out),
                    "--seeds",
                    str(seeds),
                    "--tranco-top",
                    "0",
                    "--no-db",
                    "--skip-liveness",
                    "--test-fraction",
                    "0.5",
                ]
            )
        assert code == 0
        dataset = out / "cli" / "v1"
        manifest = json.loads((dataset / "manifest.json").read_text())
        assert manifest["counts"]["by_label"]["phishing"] == 2
        assert main(["verify", str(dataset)]) == 0

        with patch("src.eval.predictors.offline_validator", return_value=_CannedValidator()):
            code = main(
                [
                    "run",
                    str(dataset),
                    "--predictor",
                    "heuristic",
                    "--split",
                    "all",
                    "--out",
                    str(tmp_path / "runs"),
                    "--cache",
                    str(tmp_path / "cache"),
                    "--workers",
                    "1",
                ]
            )
        assert code == 0
        summary = json.loads(_last_json(capsys))
        assert summary["counts"]["samples"] >= 3
        assert Path(summary["report_html"]).exists()
        # eval/targets.json is checked by default (tiny dataset: nothing is resolvable).
        assert summary["targets"]["operating_point"] == "auto_report"
        assert summary["targets"]["precision"] == "not_resolvable"

        # --reuse-cache scores with the earlier scans and never scans again.
        (cache_file,) = (tmp_path / "cache").glob("heuristic-cli-v1-*.jsonl")
        with patch("src.eval.predictors.offline_validator", side_effect=AssertionError("scan")):
            code = main(
                [
                    "run",
                    str(dataset),
                    "--predictor",
                    "heuristic",
                    "--split",
                    "all",
                    "--out",
                    str(tmp_path / "runs"),
                    "--reuse-cache",
                    str(cache_file),
                    "--targets",
                    "",
                    "--auto-report-confidence",
                    "70",
                ]
            )
        assert code == 0
        reused = json.loads(_last_json(capsys))
        assert reused["counts"] == summary["counts"]
        assert reused["targets"] is None
        report = json.loads(Path(reused["report_json"]).read_text())
        assert report["notes"][0].startswith(f"Predictions reused from {cache_file.name}")
        assert report["auto_report_rule"]["min_confidence"] == 70
        # The canned validator answers "high" with confidence 75: flagged at 70.
        assert report["verdicts"]["deployed"]["operating_points"]["auto_report"]["tp"] >= 1

    def test_run_with_the_judge(self, tmp_path, capsys):
        seeds = _seeds(tmp_path / "seeds")
        out = tmp_path / "datasets"
        with patch(
            "src.intelligence.openphish.OpenPhishIntegration.fetch_feed",
            return_value={"https://nequi-pagos.example/", "https://bank-login.example/"},
        ):
            main(
                [
                    "build",
                    "--name",
                    "judged",
                    "--version",
                    "v1",
                    "--out",
                    str(out),
                    "--seeds",
                    str(seeds),
                    "--tranco-top",
                    "0",
                    "--no-db",
                    "--skip-liveness",
                ]
            )
        dataset = str(out / "judged" / "v1")
        base = ["run", dataset, "--split", "all", "--out", str(tmp_path / "runs")]
        base += ["--cache", str(tmp_path / "cache"), "--workers", "1", "--targets", ""]

        assert main([*base, "--predictor", "stored", "--judge"]) == 2
        with patch(
            "src.eval.predictors.judge_from_settings",
            side_effect=ValueError("measuring the judge needs LLM_JUDGE_API_KEY"),
        ):
            assert main([*base, "--predictor", "heuristic", "--judge"]) == 2
        assert "LLM_JUDGE_API_KEY" in capsys.readouterr().err

        judge = SimpleNamespace(
            config=SimpleNamespace(
                provider="openai_compatible", model="deepseek-flash", daily_budget_usd=1.0
            )
        )
        with (
            patch("src.eval.predictors.offline_validator", side_effect=_JudgedValidator),
            patch("src.eval.predictors.judge_from_settings", return_value=judge),
        ):
            code = main([*base, "--predictor", "heuristic", "--judge"])
        assert code == 0
        summary = json.loads(_last_json(capsys))
        assert summary["judge_pr_auc"] is not None
        report = json.loads(Path(summary["report_json"]).read_text())
        assert report["predictor"] == "heuristic+judge"
        assert any(n.startswith("LLM judge measured: openai_compatible") for n in report["notes"])
        assert report["judge"]["asked"] == report["counts"]["samples"]
        assert list((tmp_path / "cache").glob("heuristic+judge-judged-v1-*.jsonl"))

    def test_verify_fails_on_a_tampered_dataset(self, tmp_path):
        seeds = _seeds(tmp_path / "seeds")
        out = tmp_path / "datasets"
        main(
            [
                "build",
                "--name",
                "cli",
                "--version",
                "v2",
                "--out",
                str(out),
                "--seeds",
                str(seeds),
                "--tranco-top",
                "0",
                "--no-db",
                "--no-feeds",
                "--skip-liveness",
            ]
        )
        samples = out / "cli" / "v2" / "samples.jsonl"
        samples.write_text(samples.read_text().replace("benign", "phishing", 1))

        assert main(["verify", str(out / "cli" / "v2")]) == 1


def _last_json(capsys) -> str:
    """Return the last top-level JSON document printed to stdout."""
    text = capsys.readouterr().out
    start = text.rfind("\n{")
    return text[start + 1 :] if start >= 0 else text[text.find("{") :]
