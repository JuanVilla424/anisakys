"""
Server-side STIX 2.1 validation, TLP marking and indicator bundles for Anisakys.

``build_indicator_bundle`` (behind ``POST /api/v2/stix/bundle``) produces STIX
2.1 bundles marked with the official TLP 2.0 marking definitions; the older
``add_tlp_marking`` helper keeps using the TLP 1.0 definitions built into STIX.

The existing "Export STIX" (anisakys-frontend GraphView.vue) builds a bundle
entirely client-side and only ever triggers a local file download -- no
server-side validation, no TLP, no sharing. This module is the missing
server-side half: validate a bundle (from the frontend or any other source)
before it's trusted enough to push anywhere, and apply a TLP marking.

Uses the official OASIS `stix2` library for validation rather than
hand-rolling STIX 2.1 spec conformance checking.
"""

import ipaddress
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import stix2
from stix2.exceptions import STIXError

from src.logger import logger

# Fixed, well-known STIX 2.1 marking-definition IDs (confirmed from the
# official OASIS cti-python-stix2 library source, stix2/v21/common.py --
# these are spec-defined constants, not generated per-bundle).
TLP_MARKING_IDS = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def validate_stix_bundle(bundle: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate a STIX 2.1 bundle using the official stix2 library.

    Returns (True, []) if valid, (False, [error messages]) otherwise.
    allow_custom=True: anisakys's own bundle (from GraphView.vue) uses plain
    STIX types (indicator/identity/relationship), but a permissive default
    avoids rejecting a bundle over harmless extra vendor properties from
    other tools, which isn't the kind of validity this check cares about.
    """
    try:
        stix2.parse(bundle, allow_custom=True)
        return True, []
    except STIXError as e:
        logger.warning(f"⚠️  STIX bundle validation failed: {e}")
        return False, [str(e)]


def add_tlp_marking(bundle: Dict[str, Any], level: str) -> Dict[str, Any]:
    """Return a new bundle with a TLP marking-definition object added and
    object_marking_refs set on every non-marking-definition object.

    Raises ValueError for an unknown TLP level -- this is a caller
    programming error (a fixed, small set of valid levels), not a runtime
    condition to degrade gracefully from.
    """
    level = level.lower()
    if level not in TLP_MARKING_IDS:
        raise ValueError(f"Unknown TLP level: {level!r} (must be one of {sorted(TLP_MARKING_IDS)})")

    marking_id = TLP_MARKING_IDS[level]
    objects = list(bundle.get("objects", []))

    if not any(obj.get("id") == marking_id for obj in objects):
        objects.append(
            {
                "type": "marking-definition",
                "spec_version": "2.1",
                "id": marking_id,
                "created": "2017-01-20T00:00:00.000Z",
                "definition_type": "tlp",
                "name": f"TLP:{level.upper()}",
                "definition": {"tlp": level},
            }
        )

    marked_objects = []
    for obj in objects:
        if obj.get("type") == "marking-definition":
            marked_objects.append(obj)
            continue
        marked = dict(obj)
        refs = list(marked.get("object_marking_refs", []))
        if marking_id not in refs:
            refs.append(marking_id)
        marked["object_marking_refs"] = refs
        marked_objects.append(marked)

    return {**bundle, "objects": marked_objects}


# ---------------------------------------------------------------------------
# Server-side indicator bundles (POST /api/v2/stix/bundle) with TLP 2.0
# ---------------------------------------------------------------------------

# TLP 2.0 marking definitions published by the OASIS CTI TC as a STIX 2.1
# property extension (oasis-open/cti-stix-common-objects,
# extension-definition-specifications/tlp-2.0). IDs and "created" are fixed by
# that publication; consumers recognise the markings by ID.
TLP2_EXTENSION_DEFINITION_ID = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"
TLP2_MARKING_CREATED = "2022-10-01T00:00:00.000Z"
TLP2_MARKING_IDS = {
    "clear": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "green": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    "amber": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    "amber+strict": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
    "red": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}
DEFAULT_TLP2_LEVEL = "amber"
DEFAULT_CONFIDENCE = 50

# Request indicator type -> STIX cyber-observable used in the pattern.
INDICATOR_OBSERVABLE_TYPES = {
    "domain": "domain-name",
    "url": "url",
    "ipv4": "ipv4-addr",
    "ipv6": "ipv6-addr",
    "email-addr": "email-addr",
}
MAX_BUNDLE_INDICATORS = 5000
MAX_INDICATOR_VALUE_LENGTH = 8192
MAX_LABELS = 50
MAX_TEXT_LENGTH = 10000

# One stable producer identity, so every bundle we emit references the same SDO.
ANISAKYS_IDENTITY_ID = "identity--" + str(uuid.uuid5(uuid.NAMESPACE_URL, "anisakys:producer"))
ANISAKYS_IDENTITY_CREATED = "2026-01-01T00:00:00.000Z"


class BundleRequestError(ValueError):
    """The bundle request is invalid.

    Attributes:
        message: Summary safe to return to the client.
        details: Per-indicator problems as ``{"index": int, "error": str}``.
    """

    def __init__(self, message: str, details: Optional[List[Dict[str, Any]]] = None) -> None:
        """Create the error.

        Args:
            message: Summary safe to return to the client.
            details: Per-indicator problems (index into ``indicators``).
        """
        super().__init__(message)
        self.message = message
        self.details = details or []


def escape_pattern_value(value: str) -> str:
    """Escape a string for use inside a single-quoted STIX pattern literal.

    STIX patterning escapes only the backslash and the single quote inside
    string literals; the backslash must be escaped first.

    Args:
        value: Raw indicator value.

    Returns:
        The escaped value.
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")


def indicator_pattern(indicator_type: str, value: str) -> str:
    """Build the STIX pattern matching one indicator value.

    Args:
        indicator_type: One of ``INDICATOR_OBSERVABLE_TYPES``.
        value: Indicator value.

    Returns:
        A pattern such as ``[domain-name:value = 'evil.example']``.

    Raises:
        KeyError: If ``indicator_type`` is unknown.
    """
    observable = INDICATOR_OBSERVABLE_TYPES[indicator_type]
    return f"[{observable}:value = '{escape_pattern_value(value)}']"


def tlp2_marking_definition(level: str) -> Dict[str, Any]:
    """Return the official TLP 2.0 marking-definition object for ``level``.

    Args:
        level: One of ``TLP2_MARKING_IDS`` (``clear`` ... ``red``).

    Returns:
        The marking-definition as a STIX 2.1 dict.

    Raises:
        KeyError: If ``level`` is not a TLP 2.0 level.
    """
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": TLP2_MARKING_IDS[level],
        "created": TLP2_MARKING_CREATED,
        "name": f"TLP:{level.upper()}",
        "extensions": {
            TLP2_EXTENSION_DEFINITION_ID: {
                "extension_type": "property-extension",
                "tlp_2_0": level,
            }
        },
    }


def _parse_timestamp(raw: Any) -> datetime:
    """Parse an ISO-8601 timestamp; naive values are taken as UTC.

    Args:
        raw: Candidate timestamp string.

    Returns:
        A timezone-aware datetime.

    Raises:
        ValueError: If ``raw`` is not an ISO-8601 string.
    """
    if not isinstance(raw, str):
        raise ValueError("first_seen must be an ISO-8601 string")
    parsed = datetime.fromisoformat(raw.strip())
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _value_error(indicator_type: str, value: str) -> Optional[str]:
    """Check a value against its indicator type.

    Args:
        indicator_type: Validated indicator type.
        value: Stripped, non-empty value.

    Returns:
        An error message, or None when the value is acceptable.
    """
    if len(value) > MAX_INDICATOR_VALUE_LENGTH:
        return f"value longer than {MAX_INDICATOR_VALUE_LENGTH} characters"
    if indicator_type in ("ipv4", "ipv6"):
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return f"value is not a valid {indicator_type} address"
        if network.version != (4 if indicator_type == "ipv4" else 6):
            return f"value is not a valid {indicator_type} address"
    elif indicator_type == "email-addr" and (
        value.count("@") != 1 or any(c.isspace() for c in value)
    ):
        return "value is not an e-mail address"
    elif indicator_type == "domain" and (any(c.isspace() for c in value) or "/" in value):
        return "value is not a domain name"
    return None


def _validate_indicator(item: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Validate and normalise one requested indicator.

    Args:
        item: The raw indicator object.

    Returns:
        ``(normalised, None)`` when valid, else ``(None, error message)``.
    """
    if not isinstance(item, dict):
        return None, "indicator must be an object"
    indicator_type = item.get("type")
    if indicator_type not in INDICATOR_OBSERVABLE_TYPES:
        allowed = ", ".join(sorted(INDICATOR_OBSERVABLE_TYPES))
        return None, f"unknown type {indicator_type!r} (allowed: {allowed})"
    value = item.get("value")
    if not isinstance(value, str) or not value.strip():
        return None, "value must be a non-empty string"
    value = value.strip()
    problem = _value_error(indicator_type, value)
    if problem:
        return None, problem

    valid_from = None
    if item.get("first_seen") is not None:
        try:
            valid_from = _parse_timestamp(item["first_seen"])
        except ValueError:
            return None, "first_seen must be an ISO-8601 timestamp"

    labels = item.get("labels") or []
    if (
        not isinstance(labels, list)
        or len(labels) > MAX_LABELS
        or not all(isinstance(label, str) and label.strip() for label in labels)
    ):
        return None, f"labels must be a list of up to {MAX_LABELS} non-empty strings"

    description = item.get("description")
    if description is not None and (
        not isinstance(description, str) or len(description) > MAX_TEXT_LENGTH
    ):
        return None, f"description must be a string of at most {MAX_TEXT_LENGTH} characters"

    return {
        "type": indicator_type,
        "value": value,
        "valid_from": valid_from,
        "labels": [label.strip() for label in labels],
        "description": description or None,
    }, None


def validate_bundle_request(payload: Any) -> Dict[str, Any]:
    """Validate a ``POST /api/v2/stix/bundle`` body and apply defaults.

    Args:
        payload: The decoded JSON body.

    Returns:
        ``{"indicators": [...], "tlp": str, "confidence": int, "name": str|None}``
        with normalised indicators.

    Raises:
        BundleRequestError: With every offending indicator index in ``details``.
    """
    if not isinstance(payload, dict):
        raise BundleRequestError("Request body must be a JSON object")
    indicators = payload.get("indicators")
    if not isinstance(indicators, list) or not indicators:
        raise BundleRequestError("indicators must be a non-empty list")
    if len(indicators) > MAX_BUNDLE_INDICATORS:
        raise BundleRequestError(f"At most {MAX_BUNDLE_INDICATORS} indicators per bundle")

    tlp = payload.get("tlp", DEFAULT_TLP2_LEVEL)
    tlp = tlp.strip().lower() if isinstance(tlp, str) else tlp
    if tlp not in TLP2_MARKING_IDS:
        raise BundleRequestError(f"tlp must be one of: {', '.join(TLP2_MARKING_IDS)}")

    confidence = payload.get("confidence", DEFAULT_CONFIDENCE)
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, int)
        or not 0 <= confidence <= 100
    ):
        raise BundleRequestError("confidence must be an integer from 0 to 100")

    name = payload.get("name")
    if name is not None and (not isinstance(name, str) or not name.strip() or len(name) > 256):
        raise BundleRequestError("name must be a non-empty string of at most 256 characters")

    normalised, errors = [], []
    for index, item in enumerate(indicators):
        indicator, error = _validate_indicator(item)
        if error:
            errors.append({"index": index, "error": error})
        else:
            normalised.append(indicator)
    if errors:
        raise BundleRequestError("Invalid indicators", errors)

    return {
        "indicators": normalised,
        "tlp": tlp,
        "confidence": confidence,
        "name": name.strip() if name else None,
    }


def build_indicator_bundle(
    indicators: List[Dict[str, Any]],
    *,
    tlp: str = DEFAULT_TLP2_LEVEL,
    confidence: int = DEFAULT_CONFIDENCE,
    name: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build a STIX 2.1 bundle of indicators marked with a TLP 2.0 level.

    The bundle holds the Anisakys producer identity, one indicator per item
    (``indicator_types: ["malicious-activity"]``, escaped STIX pattern,
    ``valid_from`` = ``first_seen`` or now), the TLP 2.0 marking-definition and,
    when ``name`` is given, a report referencing every indicator. Every object
    except the marking-definition carries ``object_marking_refs``.

    Args:
        indicators: Normalised indicators from :func:`validate_bundle_request`.
        tlp: TLP 2.0 level (``clear``, ``green``, ``amber``, ``amber+strict``, ``red``).
        confidence: STIX confidence (0-100) applied to every indicator.
        name: Optional report name; a report object is added when set.
        now: Timestamp used for defaults (tests); defaults to the current time.

    Returns:
        The bundle as a JSON-serialisable dict.

    Raises:
        KeyError: If ``tlp`` is not a TLP 2.0 level.
        stix2.exceptions.STIXError: If the stix2 library rejects an object.
    """
    now = now or datetime.now(timezone.utc)
    marking = tlp2_marking_definition(tlp)
    markings = [marking["id"]]

    identity = stix2.Identity(
        id=ANISAKYS_IDENTITY_ID,
        created=ANISAKYS_IDENTITY_CREATED,
        modified=ANISAKYS_IDENTITY_CREATED,
        name="Anisakys",
        identity_class="system",
        description="Anisakys phishing detection and takedown engine",
        object_marking_refs=markings,
    )
    stix_indicators = []
    for item in indicators:
        optional: Dict[str, Any] = {}
        if item.get("labels"):
            optional["labels"] = item["labels"]
        if item.get("description"):
            optional["description"] = item["description"]
        stix_indicators.append(
            stix2.Indicator(
                created_by_ref=identity.id,
                name=item["value"][:256],
                indicator_types=["malicious-activity"],
                pattern=indicator_pattern(item["type"], item["value"]),
                pattern_type="stix",
                valid_from=item.get("valid_from") or now,
                confidence=confidence,
                object_marking_refs=markings,
                **optional,
            )
        )
    objects: List[Any] = [identity, *stix_indicators]
    if name:
        objects.append(
            stix2.Report(
                created_by_ref=identity.id,
                name=name,
                published=now,
                report_types=["threat-report"],
                object_refs=[indicator.id for indicator in stix_indicators],
                confidence=confidence,
                object_marking_refs=markings,
            )
        )
    objects.append(stix2.MarkingDefinition(**marking))
    bundle = stix2.Bundle(objects=objects)
    return json.loads(bundle.serialize())
