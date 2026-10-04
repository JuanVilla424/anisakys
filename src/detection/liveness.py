"""
Liveness probing for reported phishing sites.

A probe classifies what one observation of a site looked like; it never
decides on its own that a site was taken down (the takedown monitor does
that after several consecutive failing cycles). Classes:

- ``up``: the site served a page (2xx, not a parking placeholder);
- ``waf_challenge``: a bot-protection challenge/block page (Cloudflare,
  Akamai, Sucuri, Imperva, DDoS-Guard, AWS WAF, Vercel, captcha walls on
  403/429/503); the site is alive behind it;
- ``parked``: a well-known parking/registrar placeholder (conservative,
  service-specific markers only);
- ``nxdomain``: the host name does not resolve to any address;
- ``connection_error``: DNS failure other than NXDOMAIN, refused/reset
  connection, timeout, TLS failure without a usable answer, or a Cloudflare
  "origin unreachable" error (521/522/523/530);
- ``http_error``: any other HTTP error status (404/410 count as failures,
  the rest are inconclusive);
- ``ssrf_blocked``: the host (or a redirect hop) points to a non-public
  address, so it was not fetched.

Pages are fetched with several client profiles (desktop and mobile browsers)
through the SSRF-safe redirect helper; the most "alive" observation wins, so
cloaking towards one profile cannot make a live site look dead. Page content
is never searched for generic words such as "suspended", which phishing kits
use as lures.
"""

from __future__ import annotations

import ipaddress
import socket
import warnings
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlparse

import requests
from urllib3.exceptions import InsecureRequestWarning

from src.dns.network_utils import SSRFRedirectError, _ip_is_public, safe_get_with_redirects
from src.logger import logger

# Bytes of body inspected for challenge/parking markers.
MAX_BODY_BYTES = 256 * 1024


class ProbeClass(str, Enum):
    """Classification of one liveness observation."""

    UP = "up"
    NXDOMAIN = "nxdomain"
    CONNECTION_ERROR = "connection_error"
    HTTP_ERROR = "http_error"
    WAF_CHALLENGE = "waf_challenge"
    PARKED = "parked"
    SSRF_BLOCKED = "ssrf_blocked"


# HTTP statuses that, repeated over consecutive cycles, mean the content is gone.
DEFINITIVE_HTTP_FAILURES = frozenset({404, 410})

# Cloudflare edge errors meaning the origin server is unreachable/down.
CLOUDFLARE_ORIGIN_DOWN = frozenset({521, 522, 523, 530})

CHALLENGE_STATUSES = frozenset({403, 429, 503})

# Lower-case body markers of bot-challenge / WAF block pages.
CHALLENGE_BODY_MARKERS: Tuple[str, ...] = (
    # Cloudflare
    "/cdn-cgi/challenge-platform/",
    "cf-chl-",
    "cf_chl_opt",
    "cf-browser-verification",
    "attention required! | cloudflare",
    "<title>just a moment...</title>",
    "challenges.cloudflare.com/turnstile",
    # Akamai Bot Manager / edge denial
    "/akam/1",
    "bm-verify",
    "errors.edgesuite.net",
    # Sucuri
    "sucuri website firewall",
    "cloudproxy@sucuri.net",
    # Imperva / Incapsula
    "_incapsula_resource",
    "incapsula incident id",
    # DDoS-Guard
    "ddos-guard",
    # AWS WAF
    "awswafintegration",
    "aws-waf-token",
    # Vercel
    "vercel security checkpoint",
    # Generic captcha walls served with a blocking status
    "g-recaptcha",
    "h-captcha",
    "hcaptcha.com/1/api.js",
    "cf-turnstile",
)

# Server header values of WAF/CDN edges that answer 403/429/503 on bot blocks.
WAF_SERVER_MARKERS: Tuple[str, ...] = (
    "cloudflare",
    "akamaighost",
    "sucuri",
    "ddos-guard",
    "incapsula",
    "imperva",
)

# Lower-case body markers of parking services and registrar placeholders.
# Deliberately service-specific: generic phrases ("for sale", "suspended")
# also appear on live phishing pages.
PARKING_BODY_MARKERS: Tuple[str, ...] = (
    "sedoparking.com",
    "parkingcrew.net",
    "img1.wsimg.com/parking-lander",
    "parkingpage.namecheap.com",
    'window.location.href="/lander"',
    "parked free, courtesy of godaddy",
    "bodis.com/",
    "afternic.com/forsale",
    "hugedomains.com/domain_profile",
    "dan.com/buy-domain",
    "above.com/marketing",
)

# A credential form means the page is not a parking placeholder.
PASSWORD_FIELD_MARKERS: Tuple[str, ...] = (
    'type="password"',
    "type='password'",
    "type=password",
)

_NXDOMAIN_ERRNOS = frozenset(
    code
    for code in (
        getattr(socket, "EAI_NONAME", None),
        getattr(socket, "EAI_NODATA", None),
        getattr(socket, "EAI_ADDRFAMILY", None),
    )
    if code is not None
)


@dataclass(frozen=True)
class ClientProfile:
    """A browser identity used to fetch a page.

    Attributes:
        name: Short identifier stored with probe results.
        headers: Request headers sent with this profile.
    """

    name: str
    headers: Mapping[str, str]


_COMMON_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Upgrade-Insecure-Requests": "1",
}

DESKTOP_CHROME = ClientProfile(
    name="desktop_chrome",
    headers={
        **_COMMON_HEADERS,
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
    },
)

MOBILE_SAFARI = ClientProfile(
    name="mobile_safari",
    headers={
        **_COMMON_HEADERS,
        "User-Agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
        ),
    },
)

DEFAULT_PROFILES: Tuple[ClientProfile, ...] = (DESKTOP_CHROME, MOBILE_SAFARI)

# Most "alive" first: the combined result of a cycle is the best observation.
_PRECEDENCE: Dict[ProbeClass, int] = {
    ProbeClass.UP: 0,
    ProbeClass.WAF_CHALLENGE: 1,
    ProbeClass.PARKED: 2,
    ProbeClass.HTTP_ERROR: 3,  # adjusted below for 404/410
    ProbeClass.SSRF_BLOCKED: 3,
    ProbeClass.CONNECTION_ERROR: 5,
    ProbeClass.NXDOMAIN: 6,
}


@dataclass(frozen=True)
class ProbeResult:
    """One classified observation.

    Attributes:
        classification: The :class:`ProbeClass`.
        profile: Client profile name (``"dns"`` for resolution-only results).
        status_code: Final HTTP status, when a response was received.
        detail: Short machine-readable reason (e.g. ``"timeout"``).
    """

    classification: ProbeClass
    profile: str
    status_code: Optional[int] = None
    detail: str = ""

    @property
    def is_alive(self) -> bool:
        """``True`` when the site served content or a bot challenge."""
        return self.classification in (ProbeClass.UP, ProbeClass.WAF_CHALLENGE)

    @property
    def is_failure(self) -> bool:
        """``True`` when this observation counts towards a takedown."""
        if self.classification in (ProbeClass.NXDOMAIN, ProbeClass.CONNECTION_ERROR):
            return True
        return (
            self.classification == ProbeClass.HTTP_ERROR
            and self.status_code in DEFINITIVE_HTTP_FAILURES
        )

    def precedence(self) -> int:
        """Rank for combining profiles (lower is more alive).

        Returns:
            Precedence value; definitive HTTP failures rank with connection errors.
        """
        if self.classification == ProbeClass.HTTP_ERROR and self.is_failure:
            return 4
        return _PRECEDENCE[self.classification]


@dataclass(frozen=True)
class SiteProbe:
    """Outcome of probing a site with every profile for one cycle.

    Attributes:
        result: The combined (most alive) observation.
        observations: Per-profile observations, in probing order.
        resolved_ips: Addresses the host resolved to (empty if none).
    """

    result: ProbeResult
    observations: Tuple[ProbeResult, ...] = field(default_factory=tuple)
    resolved_ips: Tuple[str, ...] = field(default_factory=tuple)


def combine(observations: Sequence[ProbeResult]) -> ProbeResult:
    """Pick the most "alive" observation of a cycle.

    A cycle is a failure only if every profile failed.

    Args:
        observations: Non-empty list of per-profile observations.

    Returns:
        The observation with the lowest precedence (first one on ties).

    Raises:
        ValueError: If ``observations`` is empty.
    """
    if not observations:
        raise ValueError("combine() needs at least one observation")
    return min(observations, key=lambda o: o.precedence())


def _header(headers: Mapping[str, str], name: str) -> str:
    """Case-insensitive header lookup returning a lower-case value.

    Args:
        headers: Response headers.
        name: Header name.

    Returns:
        The lower-cased value, or ``""``.
    """
    for key, value in headers.items():
        if key.lower() == name.lower():
            return str(value).lower()
    return ""


def is_waf_challenge(status_code: int, headers: Mapping[str, str], body: str) -> bool:
    """Tell whether a response is a bot-challenge or WAF block page.

    Args:
        status_code: HTTP status.
        headers: Response headers.
        body: Decoded body (any case).

    Returns:
        ``True`` for explicit challenge headers, or a 403/429/503 carrying a
        challenge marker or served by a known WAF/CDN edge.
    """
    if _header(headers, "cf-mitigated") == "challenge":
        return True
    if _header(headers, "x-amzn-waf-action") in ("challenge", "captcha"):
        return True
    if _header(headers, "x-vercel-mitigated") == "challenge":
        return True
    if status_code not in CHALLENGE_STATUSES:
        return False
    lowered = body.lower()
    if any(marker in lowered for marker in CHALLENGE_BODY_MARKERS):
        return True
    if _header(headers, "x-sucuri-id") or _header(headers, "x-iinfo"):
        return True
    server = _header(headers, "server")
    return any(marker in server for marker in WAF_SERVER_MARKERS)


def is_parked(body: str) -> bool:
    """Tell whether a 2xx page is a parking/registrar placeholder.

    Args:
        body: Decoded body (any case).

    Returns:
        ``True`` only for a known parking-service marker on a page without a
        password field.
    """
    lowered = body.lower()
    if any(marker in lowered for marker in PASSWORD_FIELD_MARKERS):
        return False
    return any(marker in lowered for marker in PARKING_BODY_MARKERS)


def classify_response(
    status_code: int, headers: Mapping[str, str], body: str, profile: str
) -> ProbeResult:
    """Classify a final (non-redirect) HTTP response.

    Args:
        status_code: HTTP status.
        headers: Response headers.
        body: Decoded body (possibly truncated).
        profile: Name of the client profile that fetched it.

    Returns:
        The classified observation.
    """
    if is_waf_challenge(status_code, headers, body):
        return ProbeResult(ProbeClass.WAF_CHALLENGE, profile, status_code, "challenge")
    if 200 <= status_code < 300:
        if is_parked(body):
            return ProbeResult(ProbeClass.PARKED, profile, status_code, "parking_marker")
        return ProbeResult(ProbeClass.UP, profile, status_code)
    if status_code in CLOUDFLARE_ORIGIN_DOWN and "cloudflare" in _header(headers, "server"):
        return ProbeResult(
            ProbeClass.CONNECTION_ERROR, profile, status_code, "cloudflare_origin_unreachable"
        )
    return ProbeResult(ProbeClass.HTTP_ERROR, profile, status_code, f"http_{status_code}")


def resolve_host(host: str) -> Tuple[Optional[ProbeResult], Tuple[str, ...]]:
    """Resolve a host name and classify resolution problems.

    Args:
        host: Host name or IP literal.

    Returns:
        ``(failure, ips)``: ``failure`` is ``None`` when the host resolved to
        public addresses only; otherwise an ``nxdomain``, ``connection_error``
        or ``ssrf_blocked`` observation.
    """
    try:
        ipaddress.ip_address(host)
        ips: Tuple[str, ...] = (host,)
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as e:
            if e.errno in _NXDOMAIN_ERRNOS:
                return ProbeResult(ProbeClass.NXDOMAIN, "dns", None, "nxdomain"), ()
            return ProbeResult(ProbeClass.CONNECTION_ERROR, "dns", None, f"dns_error_{e.errno}"), ()
        except UnicodeError:
            return ProbeResult(ProbeClass.NXDOMAIN, "dns", None, "invalid_hostname"), ()
        except OSError as e:
            return ProbeResult(ProbeClass.CONNECTION_ERROR, "dns", None, f"dns_oserror_{e}"), ()
        ips = tuple(dict.fromkeys(str(info[4][0]) for info in infos))
        if not ips:
            return ProbeResult(ProbeClass.NXDOMAIN, "dns", None, "no_address"), ()
    if any(not _ip_is_public(ip) for ip in ips):
        return ProbeResult(ProbeClass.SSRF_BLOCKED, "dns", None, "non_public_address"), ips
    return None, ips


def _read_body(response: requests.Response, limit: int = MAX_BODY_BYTES) -> str:
    """Read at most ``limit`` bytes of a streamed response and close it.

    Args:
        response: Response fetched with ``stream=True``.
        limit: Maximum number of bytes to read.

    Returns:
        The decoded (possibly truncated) body; a transfer cut short returns
        what was received.
    """
    chunks: List[bytes] = []
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=16384):
            chunks.append(chunk)
            total += len(chunk)
            if total >= limit:
                break
    except requests.RequestException as e:
        logger.debug(f"Liveness probe body read cut short: {type(e).__name__}")
    finally:
        response.close()
    encoding = response.encoding or "utf-8"
    try:
        return b"".join(chunks)[:limit].decode(encoding, errors="replace")
    except LookupError:
        return b"".join(chunks)[:limit].decode("utf-8", errors="replace")


def _fetch(url: str, profile: ClientProfile, timeout: int, verify: bool) -> requests.Response:
    """Fetch ``url`` through the SSRF-safe redirect helper.

    Args:
        url: URL to fetch.
        profile: Client profile whose headers are sent.
        timeout: Per-request timeout in seconds.
        verify: Verify TLS certificates.

    Returns:
        The final response (streamed).
    """
    if verify:
        return safe_get_with_redirects(
            url, headers=dict(profile.headers), timeout=timeout, stream=True
        )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureRequestWarning)
        return safe_get_with_redirects(
            url, headers=dict(profile.headers), timeout=timeout, stream=True, verify=False
        )


def probe_with_profile(url: str, profile: ClientProfile, timeout: int) -> ProbeResult:
    """Fetch a URL with one client profile and classify the outcome.

    A TLS failure is retried once without certificate verification: an
    expired or self-signed certificate does not mean the content is gone.

    Args:
        url: URL to probe.
        profile: Client profile to use.
        timeout: Per-request timeout in seconds.

    Returns:
        The classified observation (never raises for network errors).
    """
    response: Optional[requests.Response] = None
    try:
        try:
            response = _fetch(url, profile, timeout, verify=True)
        except requests.exceptions.SSLError:
            response = _fetch(url, profile, timeout, verify=False)
    except SSRFRedirectError as e:
        return ProbeResult(ProbeClass.SSRF_BLOCKED, profile.name, None, f"ssrf_{e.verdict}")
    except requests.TooManyRedirects:
        return ProbeResult(ProbeClass.HTTP_ERROR, profile.name, None, "too_many_redirects")
    except requests.exceptions.SSLError:
        return ProbeResult(ProbeClass.CONNECTION_ERROR, profile.name, None, "tls_error")
    except requests.Timeout:
        return ProbeResult(ProbeClass.CONNECTION_ERROR, profile.name, None, "timeout")
    except requests.ConnectionError:
        return ProbeResult(ProbeClass.CONNECTION_ERROR, profile.name, None, "connection_failed")
    except (requests.exceptions.InvalidURL, requests.exceptions.InvalidSchema) as e:
        return ProbeResult(ProbeClass.HTTP_ERROR, profile.name, None, f"invalid_url_{e}")
    except requests.RequestException as e:
        return ProbeResult(
            ProbeClass.CONNECTION_ERROR, profile.name, None, f"request_error_{type(e).__name__}"
        )

    body = _read_body(response)
    return classify_response(response.status_code, response.headers, body, profile.name)


def probe_site(
    url: str,
    timeout: int,
    profiles: Iterable[ClientProfile] = DEFAULT_PROFILES,
    resolver: Callable[[str], Tuple[Optional[ProbeResult], Tuple[str, ...]]] = resolve_host,
) -> SiteProbe:
    """Probe a site once per cycle with every client profile.

    DNS problems short-circuit (they do not depend on the client profile);
    otherwise profiles are tried in order until one sees the site alive.

    Args:
        url: Reported phishing URL.
        timeout: Per-request timeout in seconds.
        profiles: Client profiles to try.
        resolver: Host resolver (injectable for tests).

    Returns:
        The combined :class:`SiteProbe`.
    """
    candidate = url if "://" in url else f"http://{url}"
    try:
        host = urlparse(candidate).hostname
    except ValueError:
        host = None
    if not host:
        result = ProbeResult(ProbeClass.HTTP_ERROR, "dns", None, "invalid_url")
        return SiteProbe(result, (result,), ())

    dns_failure, ips = resolver(host)
    if dns_failure is not None:
        return SiteProbe(dns_failure, (dns_failure,), ips)

    observations: List[ProbeResult] = []
    for profile in profiles:
        observation = probe_with_profile(candidate, profile, timeout)
        observations.append(observation)
        if observation.is_alive:
            break
    if not observations:
        raise ValueError("probe_site() needs at least one client profile")
    return SiteProbe(combine(observations), tuple(observations), ips)


def network_is_healthy(canary_urls: Sequence[str], timeout: float) -> bool:
    """Check that this host can reach the Internet before counting failures.

    Without this, a local outage would make every monitored site fail at once
    and, after enough cycles, be reported as taken down.

    Args:
        canary_urls: Well-known URLs that should always answer. An empty list
            disables the check.
        timeout: Per-request timeout in seconds.

    Returns:
        ``True`` if any canary answered with a non-5xx HTTP status (or no
        canary is configured).
    """
    if not canary_urls:
        return True
    for canary in canary_urls:
        try:
            response = requests.get(canary, timeout=timeout, allow_redirects=False)
        except requests.RequestException as e:
            logger.debug(f"Connectivity canary failed: {canary}: {type(e).__name__}")
            continue
        response.close()
        if response.status_code < 500:
            return True
    return False
