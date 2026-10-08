"""Per-TLD phishing log-odds (src/eval/tld_stats.py and ``python -m src.eval tld-stats``)."""

import json
import math
from pathlib import Path
from typing import Any, List

from src.eval.__main__ import main
from src.eval.dataset import make_sample, write_dataset
from src.eval.tld_stats import tld_log_odds, tld_of, tld_table


def _samples(rows) -> List[Any]:
    samples = []
    for url, label in rows:
        category = "feed_live_verified" if label == "phishing" else "tranco_top"
        sample = make_sample(url, category, "unit")
        assert sample is not None and sample.label == label
        samples.append(sample)
    return samples


ROWS = [
    *[(f"https://login-{n}.top/", "phishing") for n in range(6)],
    ("https://shop.top/", "benign"),
    *[(f"https://site{n}.com/", "benign") for n in range(8)],
    *[(f"https://pay-{n}.com/", "phishing") for n in range(2)],
    ("https://rare.xyz/", "phishing"),
    ("https://bank.com.co/", "benign"),
]


def test_tld_of_reads_the_last_suffix_label():
    assert tld_of("https://a.bank.com.co/x") == "co"
    assert tld_of("https://shop.vercel.app/") == "app"
    assert tld_of("http://203.0.113.9/login") is None


def test_log_odds_are_smoothed_and_rare_tlds_left_out():
    table = tld_log_odds(_samples(ROWS), min_samples=5)

    assert set(table) == {"top", "com"}  # xyz (1) and co (1) are too rare
    top, com = table["top"], table["com"]
    assert (top["phishing"], top["benign"]) == (6, 1)
    assert (com["phishing"], com["benign"]) == (2, 8)
    # 9 phishing and 10 benign samples over 4 TLDs, Laplace a = 1.
    expected = math.log(((6 + 1) / (9 + 4)) / ((1 + 1) / (10 + 4)))
    assert top["log_odds"] == round(expected, 4)
    assert top["log_odds"] > 0 > com["log_odds"]


def test_the_table_records_where_it_came_from():
    manifest = {"name": "phase2", "version": "2026-10-05", "samples_sha256": "a" * 64}

    table = tld_table(manifest, "train", _samples(ROWS), min_samples=5)

    assert table["source"] == {
        "dataset": "phase2",
        "version": "2026-10-05",
        "samples_sha256": "a" * 64,
        "split": "train",
    }
    assert table["counts"] == {"phishing": 9, "benign": 10, "tlds_kept": 2}
    assert table["generated_at"] and "Laplace" in table["method"]


def test_command_line(tmp_path, capsys):
    dataset = tmp_path / "ds"
    samples = _samples(ROWS)
    for sample in samples:
        sample.split = "train"
    write_dataset(dataset, samples, name="unit", version="v1", sources=[], parameters={})
    out = tmp_path / "tld_abuse.json"

    assert main(["tld-stats", str(dataset), "--out", str(out)]) == 0

    written = json.loads(out.read_text())
    assert set(written["tlds"]) == {"top", "com"}
    printed = json.loads(capsys.readouterr().out)
    assert list(printed["most_abused"]) == ["top", "com"]
    assert Path(printed["out"]) == out
