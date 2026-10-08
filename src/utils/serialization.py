"""JSON serialization helpers."""

from __future__ import annotations

import datetime
from typing import Any


def serialize_for_json(obj: Any) -> Any:
    """Convert an object graph into JSON-serializable primitives.

    Datetimes become ISO-8601 strings, objects with ``__dict__`` become dicts,
    and lists/dicts are converted recursively. Anything else is returned as-is.

    Args:
        obj: Value to convert (WHOIS results, dataclasses, dicts, lists, ...).

    Returns:
        A structure that ``json.dumps`` can serialize, or ``None`` for ``None``.
    """
    if obj is None:
        return None
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {key: serialize_for_json(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [serialize_for_json(item) for item in obj]
    if hasattr(obj, "__dict__"):
        return {key: serialize_for_json(value) for key, value in vars(obj).items()}
    return obj
