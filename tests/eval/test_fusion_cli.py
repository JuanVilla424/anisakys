"""``train-fusion`` and ``gate``: fitting from a cache and the activation gate."""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from src.detection.fusion import FEATURE_NAMES
from src.eval import __main__ as cli


def _sample_id(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def build_dataset(directory: Path) -> Path:
    """A minimal valid dataset: 6 phishing + 20 benign train, 2 + 6 test."""
    directory.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, Any]] = []

    def add(url: str, label: str, split: str) -> None:
        rows.append(
            {
                "id": _sample_id(url),
                "url": url,
                "label": label,
                "category": "phish" if label == "phishing" else "tranco_top",
                "split": split,
                "registrable_domain": url.split("/")[2],
                "brand": None,
                "kit": None,
                "first_seen": "2026-10-06T00:00:00+00:00",
                "source": "test",
            }
        )

    for i in range(6):
        add(f"https://phish-{i}.example/login", "phishing", "train")
    for i in range(20):
        add(f"https://benign-{i}.example/", "benign", "train")
    for i in range(2):
        add(f"https://phish-test-{i}.example/login", "phishing", "test")
    for i in range(6):
        add(f"https://benign-test-{i}.example/", "benign", "test")

    payload = "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n"
    (directory / "samples.jsonl").write_text(payload, encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "name": "fusiontest",
        "version": "1",
        "created_at": "2026-10-06T00:00:00+00:00",
        "samples_file": "samples.jsonl",
        "samples_sha256": hashlib.sha256(payload.encode()).hexdigest(),
        "counts": {"total": len(rows)},
        "sources": ["test"],
        "parameters": {},
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return directory


def _phish_vector() -> Dict[str, float]:
    row = dict.fromkeys(FEATURE_NAMES, 0.0)
    row.update(
        lex_typosquatting=1.0,
        con_credential_form=1.0,
        g_content=1.0,
        vis_brand_domain_mismatch=1.0,
        g_visual=1.0,
        g_capture=1.0,
    )
    return row


def _benign_vector() -> Dict[str, float]:
    row = dict.fromkeys(FEATURE_NAMES, 0.0)
    row.update(g_content=1.0, g_visual=1.0, g_capture=1.0, g_domain=1.0)
    return row


def _split_urls(split: str):
    rows = []
    if split == "train":
        rows += [(f"https://phish-{i}.example/login", True) for i in range(6)]
        rows += [(f"https://benign-{i}.example/", False) for i in range(20)]
    else:
        rows += [(f"https://phish-test-{i}.example/login", True) for i in range(2)]
        rows += [(f"https://benign-test-{i}.example/", False) for i in range(6)]
    return rows


def write_cache(path: Path, split: str) -> Path:
    """A prediction cache whose records carry fusion_features."""
    lines = []
    for url, phishing in _split_urls(split):
        record = {
            "sample_id": _sample_id(url),
            "level": "unknown",
            "confidence": 0,
            "score": 0.0,
            "fusion_features": _phish_vector() if phishing else _benign_vector(),
        }
        lines.append(json.dumps(record, sort_keys=True))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_baseline(path: Path, tp=0, fp=0, fn=2, tn=6) -> Path:
    flagged = tp + fp
    report = {
        "predictor": "live",
        "verdicts": {
            "deployed": {
                "operating_points": {
                    "auto_report": {
                        "tp": tp,
                        "fp": fp,
                        "fn": fn,
                        "tn": tn,
                        "precision": (tp / flagged) if flagged else None,
                        "recall": tp / (tp + fn) if (tp + fn) else None,
                        "fpr": fp / (fp + tn) if (fp + tn) else None,
                    }
                },
                "pr_auc": 0.017,
            }
        },
    }
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


@pytest.fixture
def workspace(tmp_path: Path) -> Dict[str, Path]:
    dataset = build_dataset(tmp_path / "dataset")
    return {
        "dataset": dataset,
        "train_cache": write_cache(tmp_path / "heuristic-fusiontest-1-test.jsonl", "train"),
        "test_cache": write_cache(tmp_path / "heuristic-fusiontest-1-test2.jsonl", "test"),
        "artifact": tmp_path / "fusion-v1.json",
        "baseline": write_baseline(tmp_path / "baseline-report.json"),
    }


class TestTrainFusion:
    def test_trains_from_the_cache_and_writes_the_artifact(self, workspace):
        code = cli.main(
            [
                "train-fusion",
                str(workspace["dataset"]),
                "--split",
                "train",
                "--cache",
                str(workspace["train_cache"]),
                "--artifact",
                str(workspace["artifact"]),
            ]
        )
        assert code == 0
        artifact = json.loads(workspace["artifact"].read_text())
        assert artifact["dataset"]["split"] == "train"
        assert artifact["dataset"]["positives"] == 6
        assert artifact["gate"] is None
        assert len(artifact["features"]) == len(FEATURE_NAMES)

    def test_refuses_to_train_without_a_cache(self, workspace, monkeypatch):
        monkeypatch.setattr(cli, "DEFAULT_CACHE", workspace["dataset"])
        with pytest.raises(SystemExit, match="fusion_features"):
            cli.main(
                [
                    "train-fusion",
                    str(workspace["dataset"]),
                    "--split",
                    "train",
                    "--artifact",
                    str(workspace["artifact"]),
                ]
            )

    def test_cache_discovery_picks_the_newest_with_vectors(self, workspace, monkeypatch):
        cache_dir = workspace["train_cache"].parent
        monkeypatch.setattr(cli, "DEFAULT_CACHE", cache_dir)
        manifest = {"name": "fusiontest", "version": "1"}
        resolved = cli._resolve_vector_cache(manifest, None)
        # Both caches have vectors; the newest (the test one) wins.
        assert resolved is not None and resolved.name == workspace["test_cache"].name
        empty = cache_dir / "heuristic-fusiontest-1-000.jsonl"
        empty.write_text('{"sample_id": "x", "level": "unknown"}\n', encoding="utf-8")
        empty.touch()  # newest by mtime, but no vectors -> skipped
        resolved = cli._resolve_vector_cache(manifest, None)
        assert resolved.name == workspace["test_cache"].name


class TestGate:
    def _train(self, workspace, capsys):
        assert (
            cli.main(
                [
                    "train-fusion",
                    str(workspace["dataset"]),
                    "--split",
                    "train",
                    "--cache",
                    str(workspace["train_cache"]),
                    "--artifact",
                    str(workspace["artifact"]),
                ]
            )
            == 0
        )
        capsys.readouterr()  # drain the train output: the gate's JSON is parsed alone

    def test_passing_gate_activates_the_model(self, workspace, capsys):
        self._train(workspace, capsys)
        code = cli.main(
            [
                "gate",
                str(workspace["dataset"]),
                "--cache",
                str(workspace["test_cache"]),
                "--artifact",
                str(workspace["artifact"]),
                "--baseline",
                str(workspace["baseline"]),
            ]
        )
        assert code == 0
        artifact = json.loads(workspace["artifact"].read_text())
        assert artifact["gate"]["passed"] is True
        gate = json.loads(capsys.readouterr().out)
        assert gate["mode"] == "active"
        assert gate["fusion_auto_report"]["tp"] == 2
        assert gate["fusion_auto_report"]["fp"] == 0

    def test_failing_gate_leaves_it_in_shadow(self, workspace, capsys):
        self._train(workspace, capsys)
        # A baseline that already found both positives with no FP: its recall
        # (1.0) cannot be beaten, only matched -- and matching is not passing.
        write_baseline(workspace["baseline"], tp=2, fp=0, fn=0, tn=6)
        code = cli.main(
            [
                "gate",
                str(workspace["dataset"]),
                "--cache",
                str(workspace["test_cache"]),
                "--artifact",
                str(workspace["artifact"]),
                "--baseline",
                str(workspace["baseline"]),
            ]
        )
        assert code == 0
        artifact = json.loads(workspace["artifact"].read_text())
        assert artifact["gate"]["passed"] is False
        assert json.loads(capsys.readouterr().out)["mode"] == "shadow"

    def test_gate_needs_the_artifact(self, workspace):
        with pytest.raises(SystemExit, match="train-fusion"):
            cli.main(
                [
                    "gate",
                    str(workspace["dataset"]),
                    "--cache",
                    str(workspace["test_cache"]),
                    "--artifact",
                    str(workspace["artifact"]),
                    "--baseline",
                    str(workspace["baseline"]),
                ]
            )

    def test_gate_needs_a_baseline_report(self, workspace, capsys):
        self._train(workspace, capsys)
        with pytest.raises(SystemExit, match="baseline"):
            cli.main(
                [
                    "gate",
                    str(workspace["dataset"]),
                    "--cache",
                    str(workspace["test_cache"]),
                    "--artifact",
                    str(workspace["artifact"]),
                    "--baseline",
                    str(workspace["dataset"] / "nope.json"),
                ]
            )
