"""Brand catalogue in the database (migration 007), managed from the console.

The catalogue starts empty: brands are added from the console (or the API) by the people
who protect them. :mod:`src.brands.catalog` merges these brands with the built-in
``KNOWN_BRANDS`` list for detection.

A brand has aliases, official domains (registrable domains it owns; ``login``/``app``
domains are its sign-in and app hosts), lure vocabulary in Spanish and English, takedown
preferences, a priority (1 = protect first) and reference images (favicons, logos) kept as
hashes only: SHA-256, MurmurHash3 (favicons, Shodan-compatible) and perceptual hashes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError

from src.detection.imagehash import ImageRejected, favicon_mmh3, fingerprint
from src.detection.normalize import Brand, BrandAsset, normalize_host

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
DOMAIN_KINDS = ("official", "login", "app")
ASSET_KINDS = ("favicon", "logo")
LURE_LANGUAGES = ("es", "en")
MAX_NAME_LENGTH = 100
MAX_SHORT_TEXT = 40
MAX_ALIASES = 20
MAX_ALIAS_LENGTH = 64
MAX_DOMAINS = 50
MAX_LURES_PER_LANGUAGE = 30
MAX_LURE_LENGTH = 80
MAX_PREFERENCES_BYTES = 4096
MAX_URL_LENGTH = 2048
MAX_ASSET_BYTES = 1024 * 1024
MAX_ASSETS_PER_BRAND = 20


class BrandValidationError(ValueError):
    """A brand field is invalid."""

    def __init__(self, field_name: str, message: str) -> None:
        super().__init__(f"{field_name}: {message}")
        self.field = field_name
        self.message = message


class BrandNotFoundError(LookupError):
    """No brand has that slug."""


class BrandConflictError(ValueError):
    """The slug, a domain or an asset already belongs to a brand."""


@dataclass
class BrandRecord:
    """One brand with its domains and reference assets."""

    id: int
    slug: str
    name: str
    category: Optional[str]
    country: Optional[str]
    priority: int
    aliases: List[str]
    lure_keywords: Dict[str, List[str]]
    takedown_preferences: Dict[str, Any]
    active: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    domains: List[Dict[str, Any]] = field(default_factory=list)
    assets: List[Dict[str, Any]] = field(default_factory=list)

    def to_catalog(self) -> Brand:
        """The brand as the detector's matcher needs it.

        Returns:
            A :class:`src.detection.normalize.Brand`.
        """
        lures = tuple(
            keyword
            for language in LURE_LANGUAGES
            for keyword in self.lure_keywords.get(language, [])
        )
        return Brand(
            slug=self.slug,
            name=self.name,
            aliases=tuple(self.aliases),
            official_domains=tuple(d["domain"] for d in self.domains),
            assets=tuple(
                BrandAsset(kind=a["kind"], mmh3=a["mmh3"], phash=a["phash"], dhash=a["dhash"])
                for a in self.assets
            ),
            priority=self.priority,
            lure_keywords=lures,
        )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _text(
    data: Mapping[str, Any], name: str, max_length: int, required: bool = False
) -> Optional[str]:
    value = data.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise BrandValidationError(name, "is required")
        return None
    if not isinstance(value, str) or len(value.strip()) > max_length:
        raise BrandValidationError(name, f"must be a string of at most {max_length} characters")
    return value.strip()


def _aliases(value: Any) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_ALIASES:
        raise BrandValidationError("aliases", f"must be a list of at most {MAX_ALIASES} strings")
    cleaned: List[str] = []
    for alias in value:
        if not isinstance(alias, str) or not alias.strip() or len(alias) > MAX_ALIAS_LENGTH:
            raise BrandValidationError(
                "aliases", f"every alias must be a string of at most {MAX_ALIAS_LENGTH} characters"
            )
        key = alias.strip().lower()
        if key not in cleaned:
            cleaned.append(key)
    return cleaned


def _lures(value: Any) -> Dict[str, List[str]]:
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) - set(LURE_LANGUAGES):
        raise BrandValidationError("lure_keywords", 'must be {"es": [...], "en": [...]}')
    cleaned: Dict[str, List[str]] = {}
    for language, keywords in value.items():
        if not isinstance(keywords, list) or len(keywords) > MAX_LURES_PER_LANGUAGE:
            raise BrandValidationError(
                "lure_keywords", f"at most {MAX_LURES_PER_LANGUAGE} keywords per language"
            )
        items: List[str] = []
        for keyword in keywords:
            if (
                not isinstance(keyword, str)
                or not keyword.strip()
                or len(keyword) > MAX_LURE_LENGTH
            ):
                raise BrandValidationError(
                    "lure_keywords", f"keywords are strings of at most {MAX_LURE_LENGTH} characters"
                )
            if keyword.strip().lower() not in items:
                items.append(keyword.strip().lower())
        cleaned[language] = items
    return cleaned


def _preferences(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise BrandValidationError("takedown_preferences", "must be a JSON object")
    if len(json.dumps(value)) > MAX_PREFERENCES_BYTES:
        raise BrandValidationError(
            "takedown_preferences", f"must be at most {MAX_PREFERENCES_BYTES} bytes of JSON"
        )
    return value


def _http_url(value: Any, name: str) -> Optional[str]:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or len(value) > MAX_URL_LENGTH:
        raise BrandValidationError(name, "must be an http(s) URL")
    try:
        parts = urlsplit(value.strip())
    except ValueError as e:
        raise BrandValidationError(name, "must be an http(s) URL") from e
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise BrandValidationError(name, "must be an http(s) URL")
    return value.strip()


def _domains(value: Any) -> List[Dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_DOMAINS:
        raise BrandValidationError("domains", f"must be a list of at most {MAX_DOMAINS} entries")
    cleaned: Dict[str, Dict[str, Any]] = {}
    for entry in value:
        item = {"domain": entry} if isinstance(entry, str) else entry
        if not isinstance(item, dict) or not isinstance(item.get("domain"), str):
            raise BrandValidationError("domains", 'entries are "domain" or {"domain", "kind"}')
        host = normalize_host(item["domain"])
        if host is None or host.is_ip or not host.suffix:
            raise BrandValidationError("domains", f"{item['domain']!r} is not a domain name")
        kind = item.get("kind", "official")
        if kind not in DOMAIN_KINDS:
            raise BrandValidationError("domains", "kind must be one of: " + ", ".join(DOMAIN_KINDS))
        domain = host.registrable if kind == "official" else host.ascii
        cleaned[domain] = {
            "domain": domain,
            "kind": kind,
            "login_url": _http_url(item.get("login_url"), "domains.login_url"),
        }
    return list(cleaned.values())


def _priority(value: Any) -> int:
    if value is None:
        return 3
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 5:
        raise BrandValidationError("priority", "must be an integer from 1 (highest) to 5")
    return value


def validate_brand(data: Mapping[str, Any], partial: bool = False) -> Dict[str, Any]:
    """Validate and normalise a brand body.

    Args:
        data: Request body.
        partial: ``PATCH`` semantics: only the fields present are validated and returned
            (``slug`` cannot change).

    Returns:
        The cleaned fields.

    Raises:
        BrandValidationError: On the first invalid field.
    """
    if not isinstance(data, Mapping):
        raise BrandValidationError("body", "must be a JSON object")
    cleaned: Dict[str, Any] = {}
    if not partial:
        slug = data.get("slug")
        if not isinstance(slug, str) or not SLUG_RE.match(slug):
            raise BrandValidationError(
                "slug", "must be 2-63 lower-case letters, digits or hyphens, starting alphanumeric"
            )
        cleaned["slug"] = slug
    elif "slug" in data:
        raise BrandValidationError("slug", "cannot be changed")
    checks = {
        "name": lambda: _text(data, "name", MAX_NAME_LENGTH, required=True),
        "category": lambda: _text(data, "category", MAX_SHORT_TEXT),
        "country": lambda: _text(data, "country", MAX_SHORT_TEXT),
        "priority": lambda: _priority(data.get("priority")),
        "aliases": lambda: _aliases(data.get("aliases")),
        "lure_keywords": lambda: _lures(data.get("lure_keywords")),
        "takedown_preferences": lambda: _preferences(data.get("takedown_preferences")),
        "domains": lambda: _domains(data.get("domains")),
    }
    for name, check in checks.items():
        if partial and name not in data:
            continue
        cleaned[name] = check()
    if partial and "active" in data:
        if not isinstance(data["active"], bool):
            raise BrandValidationError("active", "must be true or false")
        cleaned["active"] = data["active"]
    return cleaned


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------

_BRAND_COLUMNS = (
    "id, slug, name, category, country, priority, aliases, lure_keywords, "
    "takedown_preferences, active, created_at, updated_at"
)


def _record(row: Mapping[Any, Any]) -> BrandRecord:
    return BrandRecord(
        id=int(row["id"]),
        slug=row["slug"],
        name=row["name"],
        category=row["category"],
        country=row["country"],
        priority=int(row["priority"]),
        aliases=list(row["aliases"] or []),
        lure_keywords=dict(row["lure_keywords"] or {}),
        takedown_preferences=dict(row["takedown_preferences"] or {}),
        active=bool(row["active"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class BrandRepository:
    """CRUD of the brand catalogue."""

    def __init__(self, engine: Engine) -> None:
        """Create a repository.

        Args:
            engine: Engine of the shared database.
        """
        self.engine = engine

    def _attach(self, conn: Connection, records: Sequence[BrandRecord]) -> None:
        if not records:
            return
        ids = [r.id for r in records]
        by_id = {r.id: r for r in records}
        for row in conn.execute(
            text(
                "SELECT id, brand_id, domain, kind, login_url FROM brand_domains "
                "WHERE brand_id = ANY(:ids) ORDER BY domain"
            ),
            {"ids": ids},
        ).mappings():
            by_id[row["brand_id"]].domains.append(
                {
                    "id": int(row["id"]),
                    "domain": row["domain"],
                    "kind": row["kind"],
                    "login_url": row["login_url"],
                }
            )
        for row in conn.execute(
            text(
                "SELECT id, brand_id, kind, source_url, sha256, mmh3, phash, dhash, width, height, "
                "created_at FROM brand_assets WHERE brand_id = ANY(:ids) ORDER BY id"
            ),
            {"ids": ids},
        ).mappings():
            by_id[row["brand_id"]].assets.append(
                {key: row[key] for key in row.keys() if key != "brand_id"}
            )

    def list(
        self,
        search: Optional[str] = None,
        include_inactive: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[BrandRecord], int]:
        """List brands by priority, then name.

        Args:
            search: Case-insensitive match on slug, name, alias or domain.
            include_inactive: Also list deactivated brands.
            limit: Page size.
            offset: Page start.

        Returns:
            ``(brands, total)``.
        """
        where = ["TRUE"]
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if not include_inactive:
            where.append("b.active")
        if search:
            params["q"] = f"%{search.strip().lower()}%"
            where.append(
                "(b.slug ILIKE :q OR b.name ILIKE :q OR b.aliases::text ILIKE :q OR EXISTS "
                "(SELECT 1 FROM brand_domains d WHERE d.brand_id = b.id AND d.domain ILIKE :q))"
            )
        clause = " AND ".join(where)
        with self.engine.connect() as conn:
            total = int(
                conn.execute(
                    text(f"SELECT COUNT(*) FROM brands b WHERE {clause}"), params
                ).scalar_one()
            )
            rows = conn.execute(
                text(
                    f"SELECT {_BRAND_COLUMNS} FROM brands b WHERE {clause} "
                    "ORDER BY b.priority, lower(b.name), b.id LIMIT :limit OFFSET :offset"
                ),
                params,
            ).mappings()
            records = [_record(row) for row in rows]
            self._attach(conn, records)
        return records, total

    def _load(self, conn: Connection, slug: str, lock: bool = False) -> BrandRecord:
        row = (
            conn.execute(
                text(
                    f"SELECT {_BRAND_COLUMNS} FROM brands WHERE slug = :slug"
                    + (" FOR UPDATE" if lock else "")
                ),
                {"slug": slug},
            )
            .mappings()
            .first()
        )
        if row is None:
            raise BrandNotFoundError(slug)
        record = _record(row)
        self._attach(conn, [record])
        return record

    def get(self, slug: str) -> BrandRecord:
        """One brand.

        Args:
            slug: Brand slug.

        Returns:
            The brand with its domains and assets.

        Raises:
            BrandNotFoundError: Unknown slug.
        """
        with self.engine.connect() as conn:
            return self._load(conn, slug)

    @staticmethod
    def _replace_domains(
        conn: Connection, brand_id: int, domains: Sequence[Dict[str, Any]]
    ) -> None:
        conn.execute(text("DELETE FROM brand_domains WHERE brand_id = :id"), {"id": brand_id})
        for item in domains:
            owner = conn.execute(
                text(
                    "SELECT b.slug FROM brand_domains d JOIN brands b ON b.id = d.brand_id "
                    "WHERE d.domain = :domain"
                ),
                {"domain": item["domain"]},
            ).scalar()
            if owner:
                raise BrandConflictError(f"{item['domain']} already belongs to brand {owner}")
            conn.execute(
                text(
                    "INSERT INTO brand_domains (brand_id, domain, kind, login_url) "
                    "VALUES (:brand_id, :domain, :kind, :login_url)"
                ),
                {"brand_id": brand_id, **item},
            )

    def create(self, data: Mapping[str, Any]) -> BrandRecord:
        """Create a brand.

        Args:
            data: Request body (see :func:`validate_brand`).

        Returns:
            The new brand.

        Raises:
            BrandValidationError: Invalid body.
            BrandConflictError: The slug or a domain is taken.
        """
        fields = validate_brand(data)
        try:
            with self.engine.begin() as conn:
                brand_id = conn.execute(
                    text(
                        "INSERT INTO brands (slug, name, category, country, priority, aliases, "
                        "lure_keywords, takedown_preferences) VALUES (:slug, :name, :category, "
                        ":country, :priority, CAST(:aliases AS JSONB), CAST(:lure_keywords AS JSONB), "
                        "CAST(:takedown_preferences AS JSONB)) RETURNING id"
                    ),
                    {
                        **{
                            k: fields[k]
                            for k in ("slug", "name", "category", "country", "priority")
                        },
                        "aliases": json.dumps(fields["aliases"]),
                        "lure_keywords": json.dumps(fields["lure_keywords"]),
                        "takedown_preferences": json.dumps(fields["takedown_preferences"]),
                    },
                ).scalar_one()
                self._replace_domains(conn, int(brand_id), fields["domains"])
                return self._load(conn, fields["slug"])
        except IntegrityError as e:
            raise BrandConflictError(f"brand {fields['slug']} already exists") from e

    def update(self, slug: str, data: Mapping[str, Any]) -> BrandRecord:
        """Change some fields of a brand (``domains`` replaces the whole list).

        Args:
            slug: Brand slug.
            data: Fields to change.

        Returns:
            The updated brand.

        Raises:
            BrandValidationError: Invalid body.
            BrandNotFoundError: Unknown slug.
            BrandConflictError: A domain belongs to another brand.
        """
        fields = validate_brand(data, partial=True)
        with self.engine.begin() as conn:
            record = self._load(conn, slug, lock=True)
            sets: List[str] = []
            params: Dict[str, Any] = {"id": record.id}
            for name in ("name", "category", "country", "priority", "active"):
                if name in fields:
                    sets.append(f"{name} = :{name}")
                    params[name] = fields[name]
            for name in ("aliases", "lure_keywords", "takedown_preferences"):
                if name in fields:
                    sets.append(f"{name} = CAST(:{name} AS JSONB)")
                    params[name] = json.dumps(fields[name])
            if sets:
                conn.execute(
                    text(f"UPDATE brands SET {', '.join(sets)}, updated_at = now() WHERE id = :id"),
                    params,
                )
            if "domains" in fields:
                self._replace_domains(conn, record.id, fields["domains"])
            return self._load(conn, slug)

    def deactivate(self, slug: str) -> BrandRecord:
        """Stop using a brand for detection (kept for history).

        Args:
            slug: Brand slug.

        Returns:
            The deactivated brand.

        Raises:
            BrandNotFoundError: Unknown slug.
        """
        return self.update(slug, {"active": False})

    def add_asset(
        self, slug: str, kind: str, data: bytes, source_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Store the hashes of a reference favicon or logo (the image itself is not kept).

        Args:
            slug: Brand slug.
            kind: ``favicon`` or ``logo``.
            data: Image bytes (at most 1 MiB).
            source_url: Where the image came from.

        Returns:
            The asset row.

        Raises:
            BrandValidationError: Bad kind, size or image.
            BrandNotFoundError: Unknown slug.
            BrandConflictError: The same image is already an asset of the brand.
        """
        if kind not in ASSET_KINDS:
            raise BrandValidationError("kind", "must be one of: " + ", ".join(ASSET_KINDS))
        if len(data) > MAX_ASSET_BYTES:
            raise BrandValidationError("file", f"must be at most {MAX_ASSET_BYTES} bytes")
        try:
            print_ = fingerprint(data)
        except ImageRejected as e:
            raise BrandValidationError("file", str(e)) from e
        source = _http_url(source_url, "source_url")
        try:
            with self.engine.begin() as conn:
                record = self._load(conn, slug, lock=True)
                if len(record.assets) >= MAX_ASSETS_PER_BRAND:
                    raise BrandValidationError(
                        "file", f"a brand keeps at most {MAX_ASSETS_PER_BRAND} reference images"
                    )
                row = (
                    conn.execute(
                        text(
                            "INSERT INTO brand_assets (brand_id, kind, source_url, sha256, mmh3, phash, "
                            "dhash, width, height) VALUES (:brand_id, :kind, :source_url, :sha256, :mmh3, "
                            ":phash, :dhash, :width, :height) RETURNING id, kind, source_url, sha256, mmh3, "
                            "phash, dhash, width, height, created_at"
                        ),
                        {
                            "brand_id": record.id,
                            "kind": kind,
                            "source_url": source,
                            "sha256": print_.sha256,
                            "mmh3": favicon_mmh3(data) if kind == "favicon" else None,
                            "phash": print_.phash,
                            "dhash": print_.dhash,
                            "width": print_.width,
                            "height": print_.height,
                        },
                    )
                    .mappings()
                    .one()
                )
                return dict(row)
        except IntegrityError as e:
            raise BrandConflictError("this image is already a reference of the brand") from e

    def delete_asset(self, slug: str, asset_id: int) -> None:
        """Remove a reference image.

        Args:
            slug: Brand slug.
            asset_id: Asset id.

        Raises:
            BrandNotFoundError: Unknown slug or asset.
        """
        with self.engine.begin() as conn:
            record = self._load(conn, slug)
            deleted = conn.execute(
                text("DELETE FROM brand_assets WHERE id = :id AND brand_id = :brand_id"),
                {"id": asset_id, "brand_id": record.id},
            ).rowcount
            if not deleted:
                raise BrandNotFoundError(f"{slug}/assets/{asset_id}")

    def active_brands(self) -> List[BrandRecord]:
        """Every active brand with domains and assets (for the detection catalogue).

        Returns:
            Active brands.
        """
        with self.engine.connect() as conn:
            rows = conn.execute(
                text(f"SELECT {_BRAND_COLUMNS} FROM brands WHERE active ORDER BY priority, slug")
            ).mappings()
            records = [_record(row) for row in rows]
            self._attach(conn, records)
        return records
