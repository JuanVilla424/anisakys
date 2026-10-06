"""Phishing log-odds per top-level domain, from a dataset split (``python -m src.eval tld-stats``).

The table feeds :func:`src.detection.normalize.tld_abuse`. Each TLD gets a Laplace-smoothed
log-odds ratio: how much more often it appears among the phishing samples than among the
benign ones, relative to the size of each class (0 = as common in both, > 0 = phishing
over-represented). TLDs seen fewer than ``min_samples`` times are left out, since their
estimate is noise; ``tld_abuse`` then answers None for them.

Build it from the **train** split only, so the test split stays unseen by anything
derived from it.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence

from src.detection.normalize import normalize_host
from src.eval.dataset import Sample, utc_now_iso

DEFAULT_MIN_SAMPLES = 5
DEFAULT_ALPHA = 1.0


def tld_of(url: str) -> Optional[str]:
    """The top-level domain of a URL, as :func:`~src.detection.normalize.tld_abuse` reads it.

    Args:
        url: Sample URL.

    Returns:
        The last label of the public suffix (``co`` for ``bank.com.co``), or None for IP
        addresses and hosts without a known suffix.
    """
    host = normalize_host(url)
    if host is None or host.is_ip or not host.suffix:
        return None
    return host.suffix.rsplit(".", 1)[-1]


def tld_log_odds(
    samples: Sequence[Sample],
    min_samples: int = DEFAULT_MIN_SAMPLES,
    alpha: float = DEFAULT_ALPHA,
) -> Dict[str, Dict[str, Any]]:
    """Smoothed phishing log-odds of every TLD seen often enough.

    Args:
        samples: Labelled samples.
        min_samples: Fewest samples (both labels) a TLD needs to be kept.
        alpha: Laplace smoothing added to every count.

    Returns:
        ``{tld: {"log_odds", "phishing", "benign"}}``, sorted by TLD.
    """
    counts: Dict[str, List[int]] = {}
    for sample in samples:
        tld = tld_of(sample.url)
        if tld is None:
            continue
        row = counts.setdefault(tld, [0, 0])
        row[0 if sample.is_positive else 1] += 1
    phishing = sum(row[0] for row in counts.values())
    benign = sum(row[1] for row in counts.values())
    kinds = len(counts)
    table: Dict[str, Dict[str, Any]] = {}
    for tld, (p, b) in sorted(counts.items()):
        if p + b < min_samples:
            continue
        share_phishing = (p + alpha) / (phishing + alpha * kinds)
        share_benign = (b + alpha) / (benign + alpha * kinds)
        table[tld] = {
            "log_odds": round(math.log(share_phishing / share_benign), 4),
            "phishing": p,
            "benign": b,
        }
    return table


def tld_table(
    manifest: Dict[str, Any],
    split: str,
    samples: Sequence[Sample],
    min_samples: int = DEFAULT_MIN_SAMPLES,
    alpha: float = DEFAULT_ALPHA,
) -> Dict[str, Any]:
    """The ``src/data/tld_abuse.json`` document, with its provenance.

    Args:
        manifest: Manifest of the dataset the samples come from.
        split: Split the samples were taken from.
        samples: The samples.
        min_samples: Fewest samples a TLD needs to be kept.
        alpha: Laplace smoothing.

    Returns:
        Source, method, counts and the per-TLD table.
    """
    tlds = tld_log_odds(samples, min_samples=min_samples, alpha=alpha)
    return {
        "source": {
            "dataset": manifest.get("name"),
            "version": manifest.get("version"),
            "samples_sha256": manifest.get("samples_sha256"),
            "split": split,
        },
        "generated_at": utc_now_iso(),
        "method": (
            "log((p + a) / (P + a*K)) - log((b + a) / (B + a*K)) per TLD: p/b phishing and "
            "benign samples of the TLD, P/B of every TLD, K TLDs seen, a Laplace smoothing; "
            "TLDs with fewer than min_samples samples are left out"
        ),
        "min_samples": min_samples,
        "alpha": alpha,
        "counts": {
            "phishing": sum(1 for s in samples if s.is_positive),
            "benign": sum(1 for s in samples if not s.is_positive),
            "tlds_kept": len(tlds),
        },
        "tlds": tlds,
    }
