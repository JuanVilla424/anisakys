"""Evaluation reports and the ``python -m src.eval`` command line."""

import json
import re
from pathlib import Path
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


class _CannedValidator:
    def comprehensive_scan(self, url: str) -> Dict[str, Any]:
        level = "high" if "pagos" in url or "login" in url else "clean"
        return {
            "aggregated_threat_level": level,
            "confidence_score": 75,
            "stage_timings_ms": {"url_analysis": 1.0},
            "stage_status": {"url_analysis": "not_listed"},
        }


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
