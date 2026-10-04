"""Value formatting shared by the Anisakys REST API responses.

Timestamps:
    The schema stores ``TIMESTAMP WITHOUT TIME ZONE`` columns written both by
    PostgreSQL ``NOW()`` (database session time zone) and by ``datetime.now()``
    (process local time). Every supported deployment (the Docker images, CI)
    runs the database and the application in UTC, so naive values read from the
    database are taken to be UTC and serialised with an explicit ``+00:00``
    offset. Clients must not guess a time zone: a value without an offset is
    never returned by the helpers below.

Threat levels:
    ``phishing_sites.multi_api_threat_level`` holds the aggregated verdict of
    ``MultiAPIValidator`` (``clean`` < ``low`` < ``medium`` < ``high`` <
    ``critical``) or ``unknown`` when no provider returned data. ``unknown`` is
    the absence of a verdict, not a level, so it is reported as ``null``.

Usage:
    >>> iso_utc(datetime.datetime(2026, 1, 2, 3, 4, 5))
    '2026-01-02T03:04:05+00:00'
    >>> severest_threat_level(["low", "unknown", "high"])
    'high'
"""

import datetime
from typing import Any, Dict, FrozenSet, Iterable, Optional

# Order of the stored threat levels, least to most severe.
THREAT_LEVEL_RANK: Dict[str, int] = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Every value MultiAPIValidator stores in phishing_sites.multi_api_threat_level.
STORED_THREAT_LEVELS: FrozenSet[str] = frozenset(THREAT_LEVEL_RANK) | {"unknown"}


def as_utc(value: Any, *, naive_is_local: bool = False) -> Optional[datetime.datetime]:
    """Normalise a timestamp to an aware UTC ``datetime``.

    Args:
        value: A ``datetime``, a ``date``, an ISO-8601 string (e.g. the text of a
            ``::text`` cast), or None.
        naive_is_local: Interpret naive values as this process's local time
            (values produced in-process by ``datetime.now()``) instead of UTC
            (values read from the database, see the module docstring).

    Returns:
        The aware UTC value, or None when ``value`` is None or not a
        recognisable timestamp.
    """
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.datetime.fromisoformat(value.strip())
        except ValueError:
            return None
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None and not naive_is_local:
            return value.replace(tzinfo=datetime.UTC)
        return value.astimezone(datetime.UTC)
    if isinstance(value, datetime.date):
        return datetime.datetime.combine(value, datetime.time(), datetime.UTC)
    return None


def iso_utc(value: Any, *, naive_is_local: bool = False) -> Optional[str]:
    """Format a timestamp as ISO-8601 with an explicit UTC offset.

    Args:
        value: Anything :func:`as_utc` accepts.
        naive_is_local: See :func:`as_utc`.

    Returns:
        ``YYYY-MM-DDTHH:MM:SS[.ffffff]+00:00``, or None when ``value`` is None
        or not a recognisable timestamp.
    """
    normalised = as_utc(value, naive_is_local=naive_is_local)
    return normalised.isoformat() if normalised is not None else None


def threat_level_or_none(value: Any) -> Optional[str]:
    """Return a stored threat level, or None when it carries no verdict.

    Args:
        value: Raw ``multi_api_threat_level`` value.

    Returns:
        The lower-cased level when it is a ranked level; None for NULL,
        ``unknown`` and unrecognised values.
    """
    if not isinstance(value, str):
        return None
    level = value.strip().lower()
    return level if level in THREAT_LEVEL_RANK else None


def severest_threat_level(values: Iterable[Any]) -> Optional[str]:
    """Return the most severe ranked threat level among ``values``.

    Args:
        values: Raw ``multi_api_threat_level`` values (None and ``unknown``
            are ignored).

    Returns:
        The severest level, or None when no value carries a verdict.
    """
    best: Optional[str] = None
    for raw in values:
        level = threat_level_or_none(raw)
        if level is not None and (
            best is None or THREAT_LEVEL_RANK[level] > THREAT_LEVEL_RANK[best]
        ):
            best = level
    return best
