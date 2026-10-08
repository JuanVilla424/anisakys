"""Validated query-string parameters for the Anisakys REST API.

Route handlers used to call ``int(request.args.get(...))`` directly: a
non-numeric value raised outside any error handling (a 500 with a traceback)
and negative limits/offsets reached SQL. The helpers below parse and bound
every parameter and raise :class:`InvalidParameterError`, which the API turns
into a ``400`` response naming the offending parameter.

Usage:
    >>> limit = int_arg(request.args, "limit", default=100, minimum=1, maximum=500)
    >>> status = enum_arg(request.args, "status", {"up", "down"})
"""

from typing import AbstractSet, Mapping, Optional

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


class InvalidParameterError(ValueError):
    """A query parameter is missing, malformed or out of range.

    Attributes:
        parameter: Name of the offending query parameter.
        message: Human-readable explanation safe to return to the client.
    """

    def __init__(self, parameter: str, message: str) -> None:
        """Create the error.

        Args:
            parameter: Name of the offending query parameter.
            message: Explanation safe to return to the client.
        """
        super().__init__(message)
        self.parameter = parameter
        self.message = message


def int_arg(
    args: Mapping[str, str],
    name: str,
    *,
    default: int,
    minimum: int = 0,
    maximum: Optional[int] = None,
    clamp_to_maximum: bool = True,
) -> int:
    """Read a bounded integer query parameter.

    Args:
        args: The request's query arguments (``request.args``).
        name: Parameter name.
        default: Value used when the parameter is absent or empty.
        minimum: Smallest accepted value; anything lower is rejected.
        maximum: Largest accepted value, or None for no upper bound.
        clamp_to_maximum: When True, values above ``maximum`` are lowered to it
            (the historical behaviour of ``limit``); otherwise they are rejected.

    Returns:
        The parsed integer.

    Raises:
        InvalidParameterError: If the value is not an integer or is out of range.
    """
    raw = args.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = int(str(raw).strip())
    except ValueError:
        raise InvalidParameterError(name, f"'{name}' must be an integer") from None
    if value < minimum:
        raise InvalidParameterError(name, f"'{name}' must be >= {minimum}")
    if maximum is not None and value > maximum:
        if clamp_to_maximum:
            return maximum
        raise InvalidParameterError(name, f"'{name}' must be <= {maximum}")
    return value


def enum_arg(
    args: Mapping[str, str],
    name: str,
    allowed: AbstractSet[str],
    *,
    default: Optional[str] = None,
) -> Optional[str]:
    """Read a query parameter restricted to a fixed set of values.

    Args:
        args: The request's query arguments (``request.args``).
        name: Parameter name.
        allowed: Accepted values (compared case-insensitively, returned lower-cased).
        default: Value used when the parameter is absent or empty.

    Returns:
        The lower-cased value, or ``default`` when absent.

    Raises:
        InvalidParameterError: If the value is not one of ``allowed``.
    """
    raw = args.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    value = str(raw).strip().lower()
    if value not in allowed:
        raise InvalidParameterError(name, f"'{name}' must be one of: {', '.join(sorted(allowed))}")
    return value


def bool_arg(args: Mapping[str, str], name: str, *, default: bool = False) -> bool:
    """Read a boolean query parameter (true/false, 1/0, yes/no, on/off).

    Args:
        args: The request's query arguments (``request.args``).
        name: Parameter name.
        default: Value used when the parameter is absent or empty.

    Returns:
        The parsed boolean.

    Raises:
        InvalidParameterError: If the value is not a recognised boolean.
    """
    raw = args.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    value = str(raw).strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise InvalidParameterError(name, f"'{name}' must be a boolean (true or false)")


def str_arg(args: Mapping[str, str], name: str, *, max_length: int = 256) -> Optional[str]:
    """Read an optional free-text query parameter with a length bound.

    Args:
        args: The request's query arguments (``request.args``).
        name: Parameter name.
        max_length: Longest accepted value after stripping whitespace.

    Returns:
        The stripped value, or None when absent or empty.

    Raises:
        InvalidParameterError: If the value is longer than ``max_length``.
    """
    raw = args.get(name)
    if raw is None:
        return None
    value = str(raw).strip()
    if not value:
        return None
    if len(value) > max_length:
        raise InvalidParameterError(name, f"'{name}' must be at most {max_length} characters")
    return value
