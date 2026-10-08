"""Versioned evaluation datasets: samples, sanitisation, de-duplication and splits.

A dataset lives in ``<root>/<name>/<version>/``:

* ``samples.jsonl`` — one :class:`Sample` per line, sorted by id;
* ``manifest.json`` — schema version, sources, build parameters, counts and the
  SHA-256 of ``samples.jsonl`` (``verify`` recomputes it).

Samples hold no personal data: URLs keep scheme, host and path only (query,
fragment, credentials and port are dropped) and path segments that look like
e-mail addresses or tokens are redacted. Page content is never stored.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote, unquote, urlsplit

from src.reporting.recipient_policy import registrable_domain

SCHEMA_VERSION = 1
SAMPLES_FILE = "samples.jsonl"
MANIFEST_FILE = "manifest.json"

PHISHING = "phishing"
BENIGN = "benign"
LABELS = (PHISHING, BENIGN)
TRAIN = "train"
TEST = "test"
SPLITS = (TRAIN, TEST)

# Where a sample came from (``category``) and which label it carries.
CATEGORY_LABELS: Dict[str, str] = {
    "analyst_confirmed": PHISHING,
    "feed_live_verified": PHISHING,
    "analyst_dismissed": BENIGN,
    "official_brand": BENIGN,
    "homonym": BENIGN,
    "benign_saas": BENIGN,
    "tranco_top": BENIGN,
}

_HOST = re.compile(r"^[a-z0-9._:\-]+$")
_EMAIL_SEGMENT = re.compile(r"[^/@\s]+@[^/@\s]+\.[A-Za-z]{2,}")
_HEX_TOKEN = re.compile(r"^[0-9a-fA-F]{16,}$")
_LONG_TOKEN = re.compile(r"^[A-Za-z0-9_\-=.~%]{24,}$")


class DatasetError(ValueError):
    """The dataset is malformed or does not match its manifest."""


def _is_token(segment: str) -> bool:
    """Tell whether a path segment looks like an identifier or secret.

    Args:
        segment: One path segment (already URL-decoded).

    Returns:
        ``True`` for long hex strings and long mixed letter/digit strings.
    """
    if _HEX_TOKEN.match(segment):
        return True
    if _LONG_TOKEN.match(segment):
        has_digit = any(ch.isdigit() for ch in segment)
        has_alpha = any(ch.isalpha() for ch in segment)
        return has_digit and has_alpha
    return False


def sanitize_url(raw: str) -> Optional[str]:
    """Reduce a URL to scheme, host and a redacted path.

    Args:
        raw: URL as found in a feed, label or seed list.

    Returns:
        ``scheme://host/path`` with query, fragment, credentials and port
        removed and e-mail/token path segments replaced by ``[email]`` and
        ``[token]``; ``None`` when the URL is not http(s) or has no host.
    """
    value = (raw or "").strip()
    if not value:
        return None
    if "://" not in value:
        value = "http://" + value
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").rstrip(".").lower()
    if scheme not in ("http", "https") or not host:
        return None
    try:
        # Internationalised (e.g. homoglyph) hosts are kept in punycode form.
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not _HOST.match(host):
        return None
    segments: List[str] = []
    for segment in parts.path.split("/"):
        decoded = unquote(segment)
        if _EMAIL_SEGMENT.search(decoded):
            segments.append("[email]")
        elif _is_token(decoded):
            segments.append("[token]")
        else:
            segments.append(quote(decoded, safe="-._~!$&'()*+,;=:@[]"))
    path = "/".join(segments) or "/"
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{host}{path}"


def sample_id(url: str) -> str:
    """Stable id of a sanitised URL.

    Args:
        url: Sanitised URL.

    Returns:
        The first 16 hex characters of its SHA-256.
    """
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


@dataclass
class Sample:
    """One labelled URL of an evaluation dataset."""

    id: str
    url: str
    registrable_domain: str
    label: str
    category: str
    source: str
    first_seen: str
    brand: Optional[str] = None
    kit: Optional[str] = None
    split: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_positive(self) -> bool:
        """Whether the sample is phishing.

        Returns:
            ``True`` for the ``phishing`` label.
        """
        return self.label == PHISHING

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for ``samples.jsonl``.

        Returns:
            The sample as a dict (``extra`` omitted when empty).
        """
        data = asdict(self)
        if not data["extra"]:
            data.pop("extra")
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Sample":
        """Build from a ``samples.jsonl`` record.

        Args:
            data: Decoded record.

        Returns:
            The sample.

        Raises:
            DatasetError: When a required field is missing or invalid.
        """
        try:
            sample = cls(
                id=data["id"],
                url=data["url"],
                registrable_domain=data["registrable_domain"],
                label=data["label"],
                category=data["category"],
                source=data["source"],
                first_seen=data["first_seen"],
                brand=data.get("brand"),
                kit=data.get("kit"),
                split=data.get("split"),
                extra=data.get("extra") or {},
            )
        except KeyError as exc:
            raise DatasetError(f"sample is missing {exc}") from None
        if sample.label not in LABELS:
            raise DatasetError(f"sample {sample.id} has an unknown label {sample.label!r}")
        return sample


def make_sample(
    url: str,
    category: str,
    source: str,
    first_seen: Optional[str] = None,
    brand: Optional[str] = None,
    kit: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Optional[Sample]:
    """Create a sample from a raw URL, or ``None`` when the URL is unusable.

    Args:
        url: Raw URL.
        category: One of :data:`CATEGORY_LABELS` (decides the label).
        source: Where the URL came from (feed name, seed file, ``labels``).
        first_seen: ISO-8601 time it was first seen; defaults to now (UTC).
        brand: Impersonated (positives) or owning (negatives) brand.
        kit: Phishing kit, when fingerprinted.
        extra: Additional non-personal metadata (e.g. the liveness class).

    Returns:
        The sample.

    Raises:
        ValueError: For an unknown category.
    """
    if category not in CATEGORY_LABELS:
        raise ValueError(f"unknown category {category!r}")
    clean = sanitize_url(url)
    if clean is None:
        return None
    return Sample(
        id=sample_id(clean),
        url=clean,
        registrable_domain=registrable_domain(clean),
        label=CATEGORY_LABELS[category],
        category=category,
        source=source,
        first_seen=first_seen or utc_now_iso(),
        brand=brand or None,
        kit=kit or None,
        extra=dict(extra or {}),
    )


def utc_now_iso() -> str:
    """Current time as ISO-8601 UTC, to the second.

    Returns:
        E.g. ``2026-10-04T05:00:00+00:00``.
    """
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def dedupe(samples: Iterable[Sample], max_per_kit: Optional[int] = None) -> List[Sample]:
    """Drop near-duplicates.

    Positives keep one sample per eTLD+1 (the earliest seen), so one phishing
    domain cannot dominate the metrics; at most ``max_per_kit`` positives share
    a fingerprinted kit. Negatives keep one sample per (category, eTLD+1). A URL
    that appears in both classes keeps its analyst label.

    Args:
        samples: Candidate samples.
        max_per_kit: Cap of positives per kit (``None`` = no cap).

    Returns:
        The kept samples, ordered by id.
    """
    ordered = sorted(samples, key=lambda s: (s.first_seen, s.id))
    by_id: Dict[str, Sample] = {}
    for sample in ordered:
        current = by_id.get(sample.id)
        if current is None or (
            sample.category.startswith("analyst_") and not current.category.startswith("analyst_")
        ):
            by_id[sample.id] = sample

    kept: List[Sample] = []
    seen_keys = set()
    per_kit: Counter = Counter()
    for sample in sorted(by_id.values(), key=lambda s: (s.first_seen, s.id)):
        key: Tuple[str, ...] = (
            (PHISHING, sample.registrable_domain)
            if sample.is_positive
            else (BENIGN, sample.category, sample.registrable_domain)
        )
        if key in seen_keys:
            continue
        if sample.is_positive and sample.kit and max_per_kit is not None:
            if per_kit[sample.kit] >= max_per_kit:
                continue
            per_kit[sample.kit] += 1
        seen_keys.add(key)
        kept.append(sample)
    return sorted(kept, key=lambda s: s.id)


def assign_splits(samples: Sequence[Sample], test_fraction: float = 0.3) -> List[Sample]:
    """Split by time: the newest ``test_fraction`` of each class is the test set.

    Samples are grouped by eTLD+1 so a domain never sits in both splits. Groups
    are ordered by their earliest ``first_seen`` and, for equal times, by a hash
    of the domain, which keeps the split deterministic when a snapshot gives
    every sample the same time.

    Args:
        samples: De-duplicated samples.
        test_fraction: Share of each class (by group) that goes to ``test``.

    Returns:
        The samples with ``split`` set, ordered by id.

    Raises:
        ValueError: If ``test_fraction`` is not in ``(0, 1)``.
    """
    if not 0 < test_fraction < 1:
        raise ValueError("test_fraction must be between 0 and 1")
    result: List[Sample] = []
    for label in LABELS:
        groups: Dict[str, List[Sample]] = {}
        for sample in samples:
            if sample.label == label:
                groups.setdefault(sample.registrable_domain, []).append(sample)
        ordered = sorted(
            groups.items(),
            key=lambda item: (
                min(s.first_seen for s in item[1]),
                hashlib.sha256(item[0].encode("utf-8")).hexdigest(),
            ),
        )
        test_groups = round(len(ordered) * test_fraction)
        cutoff = len(ordered) - test_groups
        for index, (_domain, members) in enumerate(ordered):
            split = TEST if index >= cutoff else TRAIN
            for sample in members:
                sample.split = split
                result.append(sample)
    return sorted(result, key=lambda s: s.id)


def _counts(samples: Sequence[Sample]) -> Dict[str, Any]:
    """Count samples by label, split, category and split×label.

    Args:
        samples: Dataset samples.

    Returns:
        Nested counters as plain dicts.
    """
    return {
        "total": len(samples),
        "by_label": dict(Counter(s.label for s in samples)),
        "by_split": dict(Counter(s.split or "none" for s in samples)),
        "by_category": dict(Counter(s.category for s in samples)),
        "by_split_label": {
            f"{split}/{label}": count
            for (split, label), count in Counter(
                (s.split or "none", s.label) for s in samples
            ).items()
        },
        "with_brand": sum(1 for s in samples if s.brand),
        "with_kit": sum(1 for s in samples if s.kit),
    }


def serialize_samples(samples: Sequence[Sample]) -> bytes:
    """Render samples as canonical JSON lines (sorted keys, sorted by id).

    Args:
        samples: Samples to write.

    Returns:
        The UTF-8 bytes of ``samples.jsonl``.
    """
    lines = [
        json.dumps(sample.to_dict(), sort_keys=True, ensure_ascii=False)
        for sample in sorted(samples, key=lambda s: s.id)
    ]
    return ("\n".join(lines) + "\n").encode("utf-8") if lines else b""


def write_dataset(
    directory: Path,
    samples: Sequence[Sample],
    *,
    name: str,
    version: str,
    sources: Sequence[Dict[str, Any]],
    parameters: Dict[str, Any],
    code_commit: Optional[str] = None,
) -> Dict[str, Any]:
    """Write ``samples.jsonl`` and ``manifest.json``.

    Args:
        directory: Target directory (created).
        samples: Samples with their split assigned.
        name: Dataset name.
        version: Dataset version (e.g. the build date).
        sources: Description of every source (name, url, counts, licence note).
        parameters: Build parameters.
        code_commit: Commit of the code that built the dataset.

    Returns:
        The manifest.
    """
    directory.mkdir(parents=True, exist_ok=True)
    payload = serialize_samples(samples)
    (directory / SAMPLES_FILE).write_bytes(payload)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "name": name,
        "version": version,
        "created_at": utc_now_iso(),
        "code_commit": code_commit,
        "samples_file": SAMPLES_FILE,
        "samples_sha256": hashlib.sha256(payload).hexdigest(),
        "counts": _counts(samples),
        "sources": list(sources),
        "parameters": parameters,
        "privacy": (
            "URLs keep scheme, host and path only; query, fragment, credentials and "
            "port are dropped and e-mail/token path segments are redacted. No page "
            "content is stored."
        ),
    }
    (directory / MANIFEST_FILE).write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return manifest


def verify_dataset(directory: Path) -> List[str]:
    """Check a dataset against its manifest.

    Args:
        directory: Dataset directory.

    Returns:
        Problems found (empty when the dataset is intact).
    """
    problems: List[str] = []
    manifest_path = directory / MANIFEST_FILE
    if not manifest_path.exists():
        return [f"{manifest_path} does not exist"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        return [f"manifest is not valid JSON: {exc}"]
    if manifest.get("schema_version") != SCHEMA_VERSION:
        problems.append(f"unsupported schema_version {manifest.get('schema_version')!r}")
    samples_path = directory / manifest.get("samples_file", SAMPLES_FILE)
    if not samples_path.exists():
        return problems + [f"{samples_path} does not exist (feed samples are not in git)"]
    payload = samples_path.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if digest != manifest.get("samples_sha256"):
        problems.append(
            f"samples SHA-256 {digest} does not match the manifest "
            f"({manifest.get('samples_sha256')})"
        )
    try:
        samples = parse_samples(payload)
    except DatasetError as exc:
        return problems + [str(exc)]
    expected = manifest.get("counts", {}).get("total")
    if expected is not None and expected != len(samples):
        problems.append(f"manifest counts {expected} samples, file has {len(samples)}")
    ids = [s.id for s in samples]
    if len(ids) != len(set(ids)):
        problems.append("duplicate sample ids")
    for sample in samples:
        if sample_id(sample.url) != sample.id:
            problems.append(f"sample {sample.id} id does not match its URL")
            break
    return problems


def parse_samples(payload: bytes) -> List[Sample]:
    """Decode ``samples.jsonl`` content.

    Args:
        payload: File bytes.

    Returns:
        The samples.

    Raises:
        DatasetError: On invalid JSON or a malformed sample.
    """
    samples: List[Sample] = []
    for number, line in enumerate(payload.decode("utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            samples.append(Sample.from_dict(json.loads(line)))
        except ValueError as exc:
            raise DatasetError(f"line {number}: {exc}") from None
    return samples


def load_dataset(directory: Path) -> Tuple[Dict[str, Any], List[Sample]]:
    """Load a dataset after verifying it.

    Args:
        directory: Dataset directory.

    Returns:
        ``(manifest, samples)``.

    Raises:
        DatasetError: When ``verify_dataset`` finds a problem.
    """
    problems = verify_dataset(directory)
    if problems:
        raise DatasetError("; ".join(problems))
    manifest = json.loads((directory / MANIFEST_FILE).read_text(encoding="utf-8"))
    samples = parse_samples((directory / manifest.get("samples_file", SAMPLES_FILE)).read_bytes())
    return manifest, samples


def select_split(samples: Sequence[Sample], split: str) -> List[Sample]:
    """Pick the samples of one split.

    Args:
        samples: Dataset samples.
        split: ``train``, ``test`` or ``all``.

    Returns:
        The selected samples.

    Raises:
        ValueError: For an unknown split.
    """
    if split == "all":
        return list(samples)
    if split not in SPLITS:
        raise ValueError(f"split must be one of: all, {', '.join(SPLITS)}")
    return [s for s in samples if s.split == split]
