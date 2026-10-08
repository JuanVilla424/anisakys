"""Where evaluation samples come from.

* **Analyst labels** (``labels`` table): the latest decision per URL —
  ``phishing`` → ``analyst_confirmed``, ``benign`` → ``analyst_dismissed``.
* **OpenPhish community feed** (public, free for non-commercial use): positives,
  kept only when the site is serving content right now (``liveness.probe_site``
  class ``up``), with the phishing kit fingerprinted when recognisable.
* **Seed lists** committed in ``eval/seeds/``: official brand homepages and
  logins, legitimate sites whose names look like brands or credentials pages
  (homonyms) and legitimate pages on free hosting (SaaS).
* **Tranco top sites** (research list, by list id): popular legitimate homepages.

Negatives are also probed and dropped when the host is gone (a dead negative
measures nothing); a WAF challenge still counts as a live negative.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import requests

from src.eval.dataset import Sample, make_sample, utc_now_iso

logger = logging.getLogger(__name__)

TRANCO_LATEST_URL = "https://tranco-list.eu/api/lists/date/latest"
TRANCO_DOWNLOAD_URL = "https://tranco-list.eu/download/{list_id}/{top}"
HTTP_TIMEOUT = 30


@dataclass
class SourceReport:
    """What a source contributed, for the dataset manifest."""

    name: str
    description: str
    fetched: int = 0
    kept: int = 0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for the manifest.

        Returns:
            The report as a dict.
        """
        return {
            "name": self.name,
            "description": self.description,
            "fetched": self.fetched,
            "kept": self.kept,
            **({"details": self.details} if self.details else {}),
        }


# ---------------------------------------------------------------------------
# Brand catalogue (seeds)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Brand:
    """A brand of the seed catalogue."""

    name: str
    aliases: Tuple[str, ...]
    urls: Tuple[str, ...]


def _unique(values: Iterable[str]) -> Tuple[str, ...]:
    """Drop empty values and duplicates, keeping order.

    Args:
        values: Values.

    Returns:
        The unique values.
    """
    seen: Dict[str, None] = {}
    for value in values:
        if value and value not in seen:
            seen[value] = None
    return tuple(seen)


def load_brand_catalog(seeds_dir: Path) -> List[Brand]:
    """Build the brand catalogue: the detector's brands plus the seed file.

    Official domains come from ``KNOWN_BRANDS`` (``src/detection/url_analyzer``),
    the same list the lexical analyser uses, so the dataset and the detector
    agree on what "official" means. ``official_brands.json`` adds login pages,
    extra aliases and brands the detector does not list yet.

    Args:
        seeds_dir: Directory with the seed files.

    Returns:
        The brands, by name.
    """
    from src.detection.url_analyzer import KNOWN_BRANDS

    seeds: Dict[str, Dict[str, Any]] = {}
    path = seeds_dir / "official_brands.json"
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        seeds = {item["name"].lower(): item for item in data.get("brands", [])}
    brands = []
    for name in sorted(set(KNOWN_BRANDS) | set(seeds)):
        seed = seeds.get(name, {})
        aliases = _unique(a.lower() for a in (name, *seed.get("aliases", [])))
        urls = _unique(
            [f"https://{domain}/" for domain in KNOWN_BRANDS.get(name, [])]
            + list(seed.get("urls", []))
        )
        brands.append(Brand(name=name, aliases=aliases, urls=urls))
    return brands


def _matcher(catalog: Sequence[Brand]) -> Any:
    """The detector's brand matcher (src/detection/normalize.py) over the eval catalogue.

    Args:
        catalog: Brand catalogue.

    Returns:
        A :class:`src.detection.normalize.BrandCatalog`.
    """
    from src.detection.normalize import Brand as MatchBrand
    from src.detection.normalize import BrandCatalog

    key = tuple((b.name, b.aliases, b.urls) for b in catalog)
    cached = _MATCHERS.get(key)
    if cached is None:
        cached = BrandCatalog(
            [
                MatchBrand(
                    slug=b.name,
                    name=b.name,
                    aliases=b.aliases,
                    official_domains=tuple(u.split("://", 1)[-1].split("/", 1)[0] for u in b.urls),
                )
                for b in catalog
            ]
        )
        _MATCHERS.clear()
        _MATCHERS[key] = cached
    return cached


_MATCHERS: Dict[Tuple[Any, ...], Any] = {}


def infer_brand(url: str, catalog: Sequence[Brand]) -> Optional[str]:
    """Guess which brand a URL is about from its host.

    Uses the detector's own matcher (token boundaries, UTS-39 look-alikes, typos;
    short aliases only as whole tokens) so the dataset and the detector agree. A
    brand's official pages are attributed to that brand.

    Args:
        url: Sanitised URL.
        catalog: Brand catalogue.

    Returns:
        The brand name, or ``None``.
    """
    from src.detection.normalize import normalize_host

    matcher = _matcher(catalog)
    host = normalize_host(url)
    official = matcher.official_brand(host)
    if official:
        return official
    matches = matcher.match(host)
    return matches[0].brand if matches else None


def _read_url_list(path: Path) -> List[str]:
    """Read a seed list: one URL per line, ``#`` comments allowed.

    Args:
        path: Seed file.

    Returns:
        The URLs (empty when the file is missing).
    """
    if not path.exists():
        return []
    urls = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.split("#", 1)[0].strip()
        if value:
            urls.append(value)
    return urls


def seed_samples(seeds_dir: Path) -> Tuple[List[Sample], List[SourceReport]]:
    """Build the hard negatives committed in ``eval/seeds/``.

    Args:
        seeds_dir: Directory with ``official_brands.json``, ``homonyms.txt`` and
            ``benign_saas.txt``.

    Returns:
        ``(samples, source reports)``.
    """
    catalog = load_brand_catalog(seeds_dir)
    now = utc_now_iso()
    samples: List[Sample] = []
    official = SourceReport(
        "seeds/official_brands.json", "Official brand homepages and login pages"
    )
    for brand in catalog:
        for url in brand.urls:
            official.fetched += 1
            sample = make_sample(url, "official_brand", "seeds", first_seen=now, brand=brand.name)
            if sample:
                samples.append(sample)
                official.kept += 1
    reports = [official]
    for filename, category, description in (
        ("homonyms.txt", "homonym", "Legitimate sites whose names look like brands or logins"),
        ("benign_saas.txt", "benign_saas", "Legitimate pages on free hosting platforms"),
    ):
        report = SourceReport(f"seeds/{filename}", description)
        for url in _read_url_list(seeds_dir / filename):
            report.fetched += 1
            sample = make_sample(url, category, "seeds", first_seen=now)
            if sample:
                sample.brand = infer_brand(sample.url, catalog) if category == "homonym" else None
                samples.append(sample)
                report.kept += 1
        reports.append(report)
    return samples, reports


# ---------------------------------------------------------------------------
# Analyst labels
# ---------------------------------------------------------------------------


def analyst_samples(engine: Any) -> Tuple[List[Sample], SourceReport]:
    """Turn the latest label of every URL into a sample.

    Args:
        engine: Engine of the database holding ``labels``.

    Returns:
        ``(samples, source report)``.
    """
    from src.labels import LabelRepository

    report = SourceReport("labels", "Latest analyst label per URL (labels table)")
    samples: List[Sample] = []
    for label in LabelRepository(engine).latest_per_url():
        report.fetched += 1
        category = "analyst_confirmed" if label.verdict == "phishing" else "analyst_dismissed"
        first_seen = label.detector_snapshot.get("first_seen") or (
            label.created_at.isoformat() if label.created_at else None
        )
        sample = make_sample(
            label.url,
            category,
            "labels",
            first_seen=first_seen,
            brand=label.brand,
            kit=label.kit,
            extra={"label_id": label.id, "action": label.action},
        )
        if sample:
            samples.append(sample)
            report.kept += 1
    return samples, report


# ---------------------------------------------------------------------------
# Public feeds
# ---------------------------------------------------------------------------


def openphish_samples(
    catalog: Sequence[Brand],
    limit: Optional[int] = None,
    fetch: Optional[Callable[[], Iterable[str]]] = None,
) -> Tuple[List[Sample], SourceReport]:
    """Read the OpenPhish community feed as (not yet verified) positives.

    Args:
        catalog: Brand catalogue for brand inference.
        limit: Keep at most this many URLs (feed order).
        fetch: Feed reader; defaults to ``OpenPhishIntegration().fetch_feed``.

    Returns:
        ``(samples, source report)``.
    """
    reader: Callable[[], Iterable[str]]
    if fetch is not None:
        reader = fetch
    else:
        from src.intelligence.openphish import OpenPhishIntegration

        reader = OpenPhishIntegration().fetch_feed
    report = SourceReport(
        "openphish",
        "OpenPhish community feed (github.com/openphish/public_feed), "
        "free for non-commercial use; kept only when live",
    )
    urls = sorted(set(reader()))
    report.fetched = len(urls)
    if limit is not None:
        urls = urls[:limit]
    now = utc_now_iso()
    samples = []
    for url in urls:
        sample = make_sample(url, "feed_live_verified", "openphish", first_seen=now)
        if sample:
            sample.brand = infer_brand(sample.url, catalog)
            samples.append(sample)
    report.kept = len(samples)
    return samples, report


def tranco_samples(
    top: int,
    cache_dir: Path,
    list_id: Optional[str] = None,
    session: Optional[requests.Session] = None,
) -> Tuple[List[Sample], SourceReport]:
    """Popular legitimate homepages from the Tranco research list.

    Args:
        top: How many top-ranked domains to take.
        cache_dir: Where the downloaded list is cached.
        list_id: Tranco list id (default: the latest daily list).
        session: HTTP session (tests inject one).

    Returns:
        ``(samples, source report)``.

    Raises:
        requests.RequestException: When the list cannot be downloaded.
    """
    http = session or requests.Session()
    if not list_id:
        response = http.get(TRANCO_LATEST_URL, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        list_id = str(response.json()["list_id"])
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"tranco-{list_id}-{top}.csv"
    if cache_file.exists():
        content = cache_file.read_text(encoding="utf-8")
    else:
        response = http.get(
            TRANCO_DOWNLOAD_URL.format(list_id=list_id, top=top), timeout=HTTP_TIMEOUT
        )
        response.raise_for_status()
        content = response.text
        cache_file.write_text(content, encoding="utf-8")
    report = SourceReport(
        "tranco",
        f"Tranco top {top} (list {list_id}, tranco-list.eu), popular legitimate domains",
        details={"list_id": list_id},
    )
    now = utc_now_iso()
    samples = []
    for row in csv.reader(io.StringIO(content)):
        if len(row) < 2:
            continue
        if report.fetched >= top:
            break
        report.fetched += 1
        sample = make_sample(f"https://{row[1].strip()}/", "tranco_top", "tranco", first_seen=now)
        if sample:
            sample.extra["rank"] = int(row[0]) if row[0].isdigit() else None
            samples.append(sample)
    report.kept = len(samples)
    return samples, report


# ---------------------------------------------------------------------------
# Liveness verification
# ---------------------------------------------------------------------------


def _default_probe(url: str, timeout: int) -> str:
    """Classify a URL with the takedown monitor's liveness probe.

    Args:
        url: URL to probe.
        timeout: Per-request timeout in seconds.

    Returns:
        The probe class (``up``, ``nxdomain``, ``waf_challenge``, ...).
    """
    from src.detection.liveness import probe_site

    return probe_site(url, timeout=timeout).result.classification.value


def _default_kit(url: str, timeout: int, brand: Optional[str]) -> Optional[str]:
    """Fingerprint the phishing kit of a live page, if recognisable.

    Args:
        url: Live URL.
        timeout: Request timeout in seconds.
        brand: Inferred brand (a hint for brand-specific checks).

    Returns:
        The kit type, or ``None``.
    """
    from src.detection.kit_fingerprint import score_kit_indicators
    from src.detection.url_analyzer import KNOWN_BRANDS
    from src.dns.network_utils import safe_get_with_redirects

    response = safe_get_with_redirects(url, timeout=timeout)
    hint = brand.lower() if brand and brand.lower() in KNOWN_BRANDS else None
    return score_kit_indicators(url, response, brand_hint=hint).get("kit_type")


def verify_live(
    samples: Sequence[Sample],
    *,
    workers: int = 8,
    timeout: int = 10,
    probe: Callable[[str, int], str] = _default_probe,
    kit: Optional[Callable[[str, int, Optional[str]], Optional[str]]] = _default_kit,
) -> Tuple[List[Sample], Dict[str, int]]:
    """Keep the samples whose site is live, recording the probe class.

    Positives must serve content (``up``); negatives may also answer with a bot
    challenge (``waf_challenge``). Live positives are kit-fingerprinted.

    Args:
        samples: Samples to verify.
        workers: Parallel probes.
        timeout: Per-request timeout in seconds.
        probe: Liveness classifier (injectable for tests).
        kit: Kit fingerprinter (``None`` disables it).

    Returns:
        ``(live samples, count of samples per probe class)``.
    """

    def check(sample: Sample) -> Tuple[Sample, str]:
        try:
            classification = probe(sample.url, timeout)
        except Exception as exc:
            logger.debug(f"probe failed for {sample.url}: {exc}")
            classification = "probe_error"
        if sample.is_positive and classification == "up" and kit is not None:
            try:
                sample.kit = kit(sample.url, timeout, sample.brand) or sample.kit
            except Exception as exc:
                logger.debug(f"kit fingerprint failed for {sample.url}: {exc}")
        return sample, classification

    accepted = {"up"}
    live: List[Sample] = []
    classes: Dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for sample, classification in pool.map(check, samples):
            classes[classification] = classes.get(classification, 0) + 1
            allowed = accepted if sample.is_positive else accepted | {"waf_challenge"}
            if classification in allowed:
                sample.extra["probe"] = classification
                live.append(sample)
    return live, classes
