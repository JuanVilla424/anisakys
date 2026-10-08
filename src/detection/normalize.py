"""One normalisation module for hosts and brand matching (docs/ROADMAP.md, phase 2, D27).

* Host: IDNA UTS-46 (``idna``), lower-case ASCII (punycode) and Unicode forms, without
  credentials, port or path.
* Registrable domain (eTLD+1) from the Public Suffix List *including* its private section,
  so ``shop.vercel.app`` or ``user.github.io`` is its own registrable domain, not the platform.
* UTS-39 skeleton (``src/data/confusables.txt``, Unicode 16.0) to compare look-alike strings:
  ``rnicrosoft`` and ``microsoft`` share a skeleton, so do Cyrillic ``раураl`` and ``paypal``.
* Brand matching on token boundaries against a brand catalogue, official domains first: a
  brand's own domain never impersonates it, and a short alias only matches a whole token
  (``meridian`` does not contain the brand ``dian``).
* Context: free hosting and form platforms (``src/data/saas_hosting.json``) and the TLD
  abuse table (``src/data/tld_abuse.json``, written by ``python -m src.eval tld-stats``).
"""

from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

import idna
import tldextract
from rapidfuzz.distance import DamerauLevenshtein

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
CONFUSABLES_FILE = DATA_DIR / "confusables.txt"
SAAS_HOSTING_FILE = DATA_DIR / "saas_hosting.json"
TLD_ABUSE_FILE = DATA_DIR / "tld_abuse.json"

# Aliases shorter than this only match a whole token (no prefix/suffix, no typos).
MIN_PARTIAL_ALIAS = 5
_SEPARATORS = re.compile(r"[.\-_]+")
_ALPHA_RUNS = re.compile(r"[a-z]+")
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})

# Offline PSL snapshot bundled with tldextract; private suffixes on (see module docstring).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


@dataclass(frozen=True)
class Host:
    """A normalised host name."""

    ascii: str
    unicode: str
    registrable: str
    suffix: str
    subdomain: str
    is_ip: bool
    is_idn: bool

    @property
    def label(self) -> str:
        """The registrable label (``paypal-secure`` in ``login.paypal-secure.com``)."""
        if self.is_ip or not self.suffix:
            return self.registrable
        return self.registrable[: -len(self.suffix) - 1] if self.registrable else ""

    @property
    def segments(self) -> Tuple[str, ...]:
        """Labels left of the public suffix, split on ``.``, ``-`` and ``_`` (Unicode form)."""
        if self.is_ip:
            return ()
        unicode_label = _strip_suffix(self.unicode, self.suffix)
        return tuple(s for s in _SEPARATORS.split(unicode_label.lower()) if s)


def _strip_suffix(name: str, suffix: str) -> str:
    if suffix and name.endswith("." + suffix):
        return name[: -len(suffix) - 1]
    return name


def host_of(url_or_host: str) -> str:
    """Extract the host of a URL, a host name or an e-mail domain.

    Args:
        url_or_host: ``https://user@Host:8443/path``, ``Host``, ``user@host``...

    Returns:
        The host, without credentials, port, trailing dot or brackets ("" when none).
    """
    text = (url_or_host or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "//" + text.split("@")[-1] if "@" in text and "/" not in text else "//" + text
    try:
        parts = urlsplit(text)
        host = parts.hostname or ""
    except ValueError:
        return ""
    return host.strip(".").lower()


def _to_ascii(host: str) -> Optional[str]:
    try:
        return idna.encode(host, uts46=True, transitional=False).decode("ascii")
    except (idna.IDNAError, UnicodeError, ValueError):
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError:
            return None


def _to_unicode(ascii_host: str) -> str:
    try:
        return idna.decode(ascii_host)
    except (idna.IDNAError, UnicodeError, ValueError):
        return ascii_host


def normalize_host(url_or_host: str) -> Optional[Host]:
    """Normalise a URL or host name.

    Args:
        url_or_host: URL or host name, Unicode or punycode.

    Returns:
        The :class:`Host`, or ``None`` when there is no usable host name.
    """
    raw = host_of(url_or_host)
    if not raw:
        return None
    try:
        ipaddress.ip_address(raw)
        return Host(raw, raw, raw, "", "", True, False)
    except ValueError:
        pass
    ascii_host = _to_ascii(raw)
    if not ascii_host:
        return None
    extracted = _EXTRACT(ascii_host)
    suffix = extracted.suffix
    registrable = f"{extracted.domain}.{suffix}" if extracted.domain and suffix else ascii_host
    unicode_host = _to_unicode(ascii_host)
    return Host(
        ascii=ascii_host,
        unicode=unicode_host,
        registrable=registrable,
        suffix=suffix,
        subdomain=extracted.subdomain,
        is_ip=False,
        is_idn="xn--" in ascii_host,
    )


@lru_cache(maxsize=1)
def _confusables() -> Dict[str, str]:
    """Load the UTS-39 prototype of every confusable character.

    Returns:
        ``{source character: prototype string}``.
    """
    table: Dict[str, str] = {}
    with CONFUSABLES_FILE.open(encoding="utf-8-sig") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            fields = [f.strip() for f in line.split(";")]
            if len(fields) < 2:
                continue
            source = "".join(chr(int(cp, 16)) for cp in fields[0].split())
            target = "".join(chr(int(cp, 16)) for cp in fields[1].split())
            if len(source) == 1:
                table[source] = target
    return table


def skeleton(text: str) -> str:
    """UTS-39 skeleton (lower-cased): equal skeletons mean visually confusable strings.

    Args:
        text: Any string.

    Returns:
        ``NFD(map(NFD(text)))`` with the confusable prototypes, lower-cased.
    """
    table = _confusables()
    decomposed = unicodedata.normalize("NFD", text)
    mapped = "".join(table.get(char, char) for char in decomposed)
    return unicodedata.normalize("NFD", mapped).lower()


@dataclass(frozen=True)
class BrandAsset:
    """A reference favicon or logo of a brand (hashes only)."""

    kind: str  # favicon | logo
    mmh3: Optional[int]
    phash: str
    dhash: str


@dataclass(frozen=True)
class Brand:
    """One brand of the catalogue, as the matcher needs it."""

    slug: str
    name: str
    aliases: Tuple[str, ...]
    official_domains: Tuple[str, ...]
    assets: Tuple[BrandAsset, ...] = ()
    priority: int = 3
    lure_keywords: Tuple[str, ...] = ()


@dataclass(frozen=True)
class BrandMatch:
    """A brand that a host appears to impersonate."""

    brand: str
    kind: str  # brand_label | combo | homoglyph | typo
    token: str
    score: float
    alias: str = ""


def _alias_key(alias: str) -> str:
    return re.sub(r"[^0-9a-z]", "", alias.lower())


@dataclass
class BrandCatalog:
    """Brands with their aliases and official domains, matched on token boundaries."""

    brands: Sequence[Brand]
    _official: Dict[str, str] = field(init=False, default_factory=dict)
    _official_suffixes: Dict[str, str] = field(init=False, default_factory=dict)
    _aliases: List[Tuple[str, str, str]] = field(init=False, default_factory=list)
    _by_slug: Dict[str, Brand] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        for brand in self.brands:
            self._by_slug[brand.slug] = brand
            for domain in brand.official_domains:
                host = normalize_host(domain)
                if not host:
                    continue
                if host.registrable == host.suffix:
                    # A public suffix (``gov.co``): every registrable domain under it.
                    self._official_suffixes.setdefault(host.suffix, brand.slug)
                else:
                    self._official.setdefault(host.registrable, brand.slug)
            keys = {_alias_key(a) for a in (brand.slug, brand.name, *brand.aliases)}
            for key in sorted(k for k in keys if len(k) >= 3):
                self._aliases.append((brand.slug, key, skeleton(key)))

    @classmethod
    def from_known_brands(cls) -> "BrandCatalog":
        """The built-in catalogue (``KNOWN_BRANDS``), used until the database one loads.

        Returns:
            A catalogue of the built-in brands.
        """
        from src.detection.url_analyzer import KNOWN_BRANDS

        return cls(
            [
                Brand(slug=slug, name=slug, aliases=(), official_domains=tuple(domains))
                for slug, domains in KNOWN_BRANDS.items()
            ]
        )

    def official_brand(self, host: Optional[Host]) -> Optional[str]:
        """The brand whose official registrable domain this host belongs to.

        Args:
            host: Normalised host.

        Returns:
            The brand slug, or ``None``.
        """
        if host is None or host.is_ip:
            return None
        slug = self._official.get(host.registrable)
        if slug:
            return slug
        for suffix, owner in self._official_suffixes.items():
            if host.suffix == suffix or host.suffix.endswith("." + suffix):
                return owner
        return None

    def official_domains(self, slug: str) -> List[str]:
        """Official registrable domains (and public suffixes) of a brand.

        Args:
            slug: Brand slug.

        Returns:
            Sorted domains.
        """
        return sorted(
            [d for d, s in self._official.items() if s == slug]
            + [d for d, s in self._official_suffixes.items() if s == slug]
        )

    def get(self, slug: str) -> Optional[Brand]:
        """One brand by slug.

        Args:
            slug: Brand slug.

        Returns:
            The brand, or ``None``.
        """
        return self._by_slug.get(slug)

    def __len__(self) -> int:
        return len(self.brands)

    def match(self, host: Optional[Host]) -> List[BrandMatch]:
        """Brands this host impersonates, strongest first (its own official brand excluded).

        Args:
            host: Normalised host.

        Returns:
            Matches with kind ``brand_label`` (the registrable label is the brand),
            ``combo`` (brand plus other words), ``homoglyph`` (confusable spelling) or
            ``typo`` (one or two edits away).
        """
        if host is None or host.is_ip:
            return []
        official = self.official_brand(host)
        segments = host.segments
        label_segments = tuple(
            s
            for s in _SEPARATORS.split(
                _strip_suffix(_to_unicode(host.registrable), host.suffix).lower()
            )
            if s
        )
        best: Dict[str, BrandMatch] = {}

        def keep(match: BrandMatch) -> None:
            current = best.get(match.brand)
            if current is None or match.score > current.score:
                best[match.brand] = match

        for brand, key, key_skeleton in self._aliases:
            if brand == official:
                continue
            for segment in segments:
                ascii_segment = segment if segment.isascii() else ""
                alpha_tokens = _ALPHA_RUNS.findall(ascii_segment)
                if ascii_segment == key or key in alpha_tokens:
                    alone = label_segments == (key,) and segment == key
                    keep(BrandMatch(brand, "brand_label" if alone else "combo", segment, 1.0, key))
                    continue
                # Brand glued to another word ("securepaypal"); one extra letter is a typo.
                if (
                    len(key) >= MIN_PARTIAL_ALIAS
                    and len(ascii_segment) - len(key) >= 2
                    and (ascii_segment.startswith(key) or ascii_segment.endswith(key))
                ):
                    keep(BrandMatch(brand, "combo", segment, 0.9, key))
                    continue
                if len(key) >= MIN_PARTIAL_ALIAS - 1 and skeleton(segment) == key_skeleton:
                    keep(BrandMatch(brand, "homoglyph", segment, 0.95, key))
                    continue
                if len(key) >= MIN_PARTIAL_ALIAS and ascii_segment:
                    candidate = ascii_segment.translate(_LEET)
                    if candidate == key:
                        keep(BrandMatch(brand, "homoglyph", segment, 0.95, key))
                        continue
                    allowed = 1 if len(key) < 9 else 2
                    distance = DamerauLevenshtein.distance(candidate, key)
                    if 0 < distance <= allowed and abs(len(candidate) - len(key)) <= allowed:
                        score = round(1 - distance / max(len(key), len(candidate)), 3)
                        keep(BrandMatch(brand, "typo", segment, score, key))
        return sorted(best.values(), key=lambda m: (-m.score, m.brand))


@lru_cache(maxsize=1)
def _saas_platforms() -> Dict[str, str]:
    data = json.loads(SAAS_HOSTING_FILE.read_text(encoding="utf-8"))
    return {
        domain.lower(): kind for kind, domains in data["platforms"].items() for domain in domains
    }


def saas_platform(host: Optional[Host]) -> Optional[str]:
    """The kind of free hosting or form platform serving this host, if any.

    Args:
        host: Normalised host.

    Returns:
        ``hosting``, ``forms``, ``storage``, ``ipfs``..., or ``None``.
    """
    if host is None or host.is_ip:
        return None
    platforms = _saas_platforms()
    labels = host.ascii.split(".")
    for start in range(len(labels) - 1):
        kind = platforms.get(".".join(labels[start:]))
        if kind:
            return kind
    return None


@lru_cache(maxsize=1)
def _tld_abuse() -> Mapping[str, float]:
    if not TLD_ABUSE_FILE.exists():
        return {}
    data = json.loads(TLD_ABUSE_FILE.read_text(encoding="utf-8"))
    return {tld: float(row["log_odds"]) for tld, row in data.get("tlds", {}).items()}


def tld_abuse(host: Optional[Host]) -> Optional[float]:
    """Smoothed log-odds of phishing for the host's top-level domain.

    Args:
        host: Normalised host.

    Returns:
        The log-odds from ``src/data/tld_abuse.json``, or ``None`` when unknown.
    """
    if host is None or host.is_ip or not host.suffix:
        return None
    return _tld_abuse().get(host.suffix.rsplit(".", 1)[-1])


def tokens(host: Optional[Host]) -> Iterable[str]:
    """Alphabetic tokens of a host's labels (for keyword and brand scans).

    Args:
        host: Normalised host.

    Returns:
        Lower-case ASCII alphabetic runs, left to right.
    """
    if host is None:
        return []
    return [t for segment in host.segments for t in _ALPHA_RUNS.findall(segment)]
