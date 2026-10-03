"""Request IDs and leak-free error responses for the Anisakys REST API.

Every request gets a request ID: a client-supplied ``X-Request-ID`` when it is
a short, safe token, otherwise a fresh UUID. It is echoed in the
``X-Request-ID`` response header, bound to the structured-logging correlation
ID, and included in error bodies so an operator can find the server-side log
line for a failed call. Exception details are logged, never returned.

Usage:
    >>> install_request_ids(app)
    >>> try:
    ...     ...
    ... except SQLAlchemyError as exc:
    ...     return internal_error("get_sites", exc)
"""

import re
import uuid
from typing import Any, Dict, Optional, Tuple

from flask import Flask, Response, g, has_request_context, jsonify, request
from werkzeug.exceptions import InternalServerError

from src.logger import logger
from src.observability.structured_logger import set_correlation_id

REQUEST_ID_HEADER = "X-Request-ID"
GENERIC_ERROR_MESSAGE = "Internal server error"

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

# Keys under which integration clients put raw exception text in their results.
_PROVIDER_ERROR_DETAIL_KEYS = ("details", "message")


def current_request_id() -> Optional[str]:
    """Return the ID of the request being handled.

    Returns:
        The request ID, or None outside a request context.
    """
    if not has_request_context():
        return None
    request_id = getattr(g, "request_id", None)
    if request_id is None:
        request_id = _assign_request_id()
    return request_id


def _assign_request_id() -> str:
    """Pick the ID for the current request and bind it to the log context.

    Returns:
        The client's ``X-Request-ID`` when it is a safe token, else a new UUID.
    """
    supplied = request.headers.get(REQUEST_ID_HEADER, "")
    request_id = supplied if _SAFE_REQUEST_ID.match(supplied) else uuid.uuid4().hex
    g.request_id = request_id
    set_correlation_id(request_id)
    return request_id


def _start_request() -> None:
    """``before_request`` hook: assign the request ID before the view runs.

    Returns None on purpose: a non-None value would replace the response.
    """
    _assign_request_id()


def _echo_request_id(response: Response) -> Response:
    """Add the request ID header to an outgoing response.

    Args:
        response: The response about to be sent.

    Returns:
        The same response with ``X-Request-ID`` set.
    """
    request_id = current_request_id()
    if request_id:
        response.headers[REQUEST_ID_HEADER] = request_id
    return response


def _unhandled_error(exc: InternalServerError) -> Tuple[Response, int]:
    """Render an unhandled exception as a generic JSON 500.

    Args:
        exc: Werkzeug's wrapper; ``original_exception`` holds the real error.

    Returns:
        A generic ``(response, 500)`` tuple carrying the request ID.
    """
    original = getattr(exc, "original_exception", None) or exc
    return internal_error("unhandled request error", original)


def install_request_ids(app: Flask) -> None:
    """Register request-ID handling and the generic 500 handler on ``app``.

    Args:
        app: The Flask application to configure.
    """
    app.before_request(_start_request)
    app.after_request(_echo_request_id)
    app.register_error_handler(InternalServerError, _unhandled_error)


def internal_error(
    context: str,
    exc: Optional[BaseException] = None,
    *,
    status: int = 500,
    message: str = GENERIC_ERROR_MESSAGE,
    extra: Optional[Dict[str, Any]] = None,
) -> Tuple[Response, int]:
    """Log a failure server-side and build a response that does not leak it.

    Args:
        context: Short name of the failing operation (route name), for the log.
        exc: The exception that caused the failure, if any. Logged, not returned.
        status: HTTP status code of the response.
        message: Client-facing message; must not contain exception details.
        extra: Additional safe fields to include in the body (e.g. the URL).

    Returns:
        ``(response, status)`` with ``{"error": message, "request_id": ...}``.
    """
    request_id = current_request_id()
    if exc is not None:
        logger.error(
            f"❌ API error in {context} [request_id={request_id}]: " f"{type(exc).__name__}: {exc}"
        )
    else:
        logger.error(f"❌ API error in {context} [request_id={request_id}]")
    body: Dict[str, Any] = {"error": message, "request_id": request_id}
    if extra:
        body.update(extra)
    return jsonify(body), status


def scrub_provider_errors(result: Dict[str, Any], generic: str = "Lookup failed") -> Dict[str, Any]:
    """Replace raw exception text that integrations put in their results.

    Threat-intel clients return ``{"error": str(exc), "details": str(exc)}`` on
    failure; that text can contain internal hostnames or request URLs (some
    providers carry the API key in the URL). The error flag is kept so clients
    still see the lookup failed, but its text becomes ``generic``.

    Args:
        result: A provider result dict, or a dict of provider results (one level).
        generic: Replacement text for error messages.

    Returns:
        A copy of ``result`` with error texts replaced and detail keys removed.
    """

    def _scrub(entry: Dict[str, Any]) -> Dict[str, Any]:
        if not entry.get("error"):
            return entry
        cleaned = {k: v for k, v in entry.items() if k not in _PROVIDER_ERROR_DETAIL_KEYS}
        cleaned["error"] = generic
        return cleaned

    scrubbed = _scrub(dict(result))
    for key, value in list(scrubbed.items()):
        if isinstance(value, dict):
            scrubbed[key] = _scrub(value)
    return scrubbed
