"""
Server-side STIX 2.1 validation + TLP marking for Anisakys Phishing Detection Engine.

The existing "Export STIX" (anisakys-frontend GraphView.vue) builds a bundle
entirely client-side and only ever triggers a local file download -- no
server-side validation, no TLP, no sharing. This module is the missing
server-side half: validate a bundle (from the frontend or any other source)
before it's trusted enough to push anywhere, and apply a TLP marking.

Uses the official OASIS `stix2` library for validation rather than
hand-rolling STIX 2.1 spec conformance checking.
"""

from typing import Any, Dict, List, Tuple

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
