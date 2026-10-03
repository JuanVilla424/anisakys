"""Secret redaction for log messages and error strings.

Exception messages raised by ``requests``/``urllib3`` embed the request URL
(``... Max retries exceeded with url: /v4/threatMatches:find?key=...``), so any
error text that may contain a provider URL must go through
:func:`redact_secrets` before it reaches a log line, a stored result or an API
response. The module is dependency-free so every package can import it without
creating import cycles.
"""

from __future__ import annotations

import re

REDACTED = "REDACTED"

# Query-string parameters that carry credentials in the providers we talk to
# (Google APIs use ``key``, PhishTank ``app_key``, URLVoid/APIVoid ``key``...).
_SECRET_PARAM_NAMES = (
    "key",
    "api_key",
    "apikey",
    "app_key",
    "access_token",
    "token",
    "secret",
    "password",
)
_QUERY_SECRET_RE = re.compile(
    r"(?P<prefix>[?&;](?:" + "|".join(_SECRET_PARAM_NAMES) + r")=)(?P<value>[^&#\s'\"]+)",
    re.IGNORECASE,
)

# ``Header: value`` / ``'header': 'value'`` pairs for credential headers.
_HEADER_SECRET_RE = re.compile(
    r"(?P<prefix>(?:x-goog-api-key|x-apikey|x-api-key|api-key|authorization)['\"]?\s*[:=]\s*"
    r"['\"]?(?:bearer\s+|basic\s+)?)(?P<value>[^\s'\",}]+)",
    re.IGNORECASE,
)

# ``scheme://user:password@host`` credentials.
_USERINFO_RE = re.compile(r"(?P<prefix>[a-z][a-z0-9+.-]*://)(?P<value>[^/@\s:]+:[^/@\s]+)@", re.I)


def redact_secrets(text: object) -> str:
    """Return ``text`` with credentials replaced by ``REDACTED``.

    Covers secret-looking query parameters, credential headers rendered into
    a string, and ``user:password@`` URL userinfo. Non-string input is
    converted with ``str()`` first so exceptions can be passed directly.

    Args:
        text: A log message, URL, exception or any object to stringify.

    Returns:
        The redacted string.
    """
    value = text if isinstance(text, str) else str(text)
    value = _QUERY_SECRET_RE.sub(lambda m: m.group("prefix") + REDACTED, value)
    value = _HEADER_SECRET_RE.sub(lambda m: m.group("prefix") + REDACTED, value)
    value = _USERINFO_RE.sub(lambda m: m.group("prefix") + REDACTED + "@", value)
    return value
