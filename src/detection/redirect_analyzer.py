"""
Redirect Chain Analysis Module

Analyzes HTTP redirect chains to detect phishing evasion techniques.
Follows up to 5 hops of redirects and calculates risk scores based on:
- Number of redirects
- Cloudflare intermediary usage
- Suspicious TLDs
- Cross-domain redirects
- URL shorteners
"""

import logging
import time
from dataclasses import dataclass
from typing import List, Optional, Set
from urllib.parse import urlparse

import requests

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    ".ru",
    ".cn",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".pw",
    ".cc",
    ".ws",
    ".info",
    ".biz",
    ".top",
}

# Known URL shortener domains
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "t.co",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "bit.do",
    "short.io",
}

# HTTP redirect status codes
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}

logger = logging.getLogger(__name__)


@dataclass
class RedirectHop:
    """Represents a single redirect hop in the chain."""

    url: str
    status_code: int
    headers: dict
    response_time_ms: float
    is_cloudflare: bool
    timestamp: str


@dataclass
class RedirectChain:
    """Complete redirect chain analysis result."""

    original_url: str
    final_url: str
    hops: List[RedirectHop]
    hop_count: int
    risk_score: int
    has_cloudflare: bool
    has_suspicious_tld: bool
    has_url_shortener: bool
    has_cross_domain: bool
    has_loop: bool
    total_time_ms: float
    chain_urls: List[str]
    status_codes: List[int]


class RedirectAnalyzer:
    """
    Analyzes HTTP redirect chains for phishing detection.

    Features:
    - Follows HTTP 3xx redirects up to configurable max hops
    - Detects redirect loops
    - Identifies Cloudflare proxying
    - Calculates risk score (0-100)
    - Comprehensive logging with structured context
    """

    def __init__(
        self, max_hops: int = 5, timeout_per_hop: int = 10, follow_redirects: bool = False
    ):
        """
        Initialize RedirectAnalyzer.

        Args:
            max_hops: Maximum number of redirects to follow (default: 5)
            timeout_per_hop: Timeout in seconds for each hop (default: 10)
            follow_redirects: Let requests handle redirects automatically (default: False)
        """
        self.max_hops = max_hops
        self.timeout_per_hop = timeout_per_hop
        self.follow_redirects = follow_redirects
        self.logger = logging.getLogger(f"{__name__}.RedirectAnalyzer")

    def analyze(self, url: str, headers: Optional[dict] = None) -> RedirectChain:
        """
        Analyze redirect chain for given URL.

        Args:
            url: Starting URL to analyze
            headers: Optional custom headers for requests

        Returns:
            RedirectChain object with complete analysis

        Raises:
            requests.RequestException: On network errors
            ValueError: On invalid URL
        """
        if not url or not url.startswith(("http://", "https://")):
            raise ValueError(f"Invalid URL: {url}")

        start_time = time.time()
        hops: List[RedirectHop] = []
        seen_urls: Set[str] = set()
        current_url = url
        has_loop = False

        # Default headers to simulate browser behavior
        if headers is None:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "DNT": "1",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }

        self.logger.info(f"Starting redirect analysis for: {url}")

        # Follow redirect chain
        for hop_num in range(self.max_hops):
            # Check for redirect loop
            if current_url in seen_urls:
                has_loop = True
                self.logger.warning(f"Redirect loop detected at hop {hop_num}: {current_url}")
                break

            seen_urls.add(current_url)

            try:
                hop_start = time.time()
                response = requests.get(
                    current_url,
                    headers=headers,
                    allow_redirects=False,
                    timeout=self.timeout_per_hop,
                    verify=True,
                )
                hop_time = (time.time() - hop_start) * 1000  # Convert to ms

                # Check if Cloudflare is involved
                is_cloudflare = self._is_cloudflare(response.headers)

                # Create hop record
                hop = RedirectHop(
                    url=current_url,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    response_time_ms=hop_time,
                    is_cloudflare=is_cloudflare,
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                )
                hops.append(hop)

                self.logger.debug(
                    f"Hop {hop_num + 1}: {current_url} -> {response.status_code} "
                    f"({hop_time:.0f}ms) {'[CF]' if is_cloudflare else ''}"
                )

                # Check if this is a redirect
                if response.status_code not in REDIRECT_STATUS_CODES:
                    # Reached final destination
                    break

                # Get next URL from Location header
                next_url = response.headers.get("Location")
                if not next_url:
                    self.logger.warning(f"Redirect without Location header at hop {hop_num}")
                    break

                # Handle relative URLs
                if not next_url.startswith(("http://", "https://")):
                    from urllib.parse import urljoin

                    next_url = urljoin(current_url, next_url)

                current_url = next_url

            except requests.Timeout:
                self.logger.error(f"Timeout at hop {hop_num}: {current_url}")
                break
            except requests.RequestException as e:
                self.logger.error(f"Request error at hop {hop_num}: {current_url} - {e}")
                break

        total_time = (time.time() - start_time) * 1000

        # Build chain analysis
        chain = RedirectChain(
            original_url=url,
            final_url=current_url,
            hops=hops,
            hop_count=len(hops),
            risk_score=0,  # Calculated below
            has_cloudflare=any(h.is_cloudflare for h in hops),
            has_suspicious_tld=self._has_suspicious_tld([h.url for h in hops]),
            has_url_shortener=self._has_url_shortener([h.url for h in hops]),
            has_cross_domain=self._has_cross_domain([h.url for h in hops]),
            has_loop=has_loop,
            total_time_ms=total_time,
            chain_urls=[h.url for h in hops],
            status_codes=[h.status_code for h in hops],
        )

        # Calculate risk score
        chain.risk_score = self._calculate_risk_score(chain)

        self.logger.info(
            f"Redirect analysis complete: {len(hops)} hops, "
            f"risk_score={chain.risk_score}, time={total_time:.0f}ms"
        )

        return chain

    def _is_cloudflare(self, headers: dict) -> bool:
        """Check if response is from Cloudflare."""
        server = headers.get("Server", "").lower()
        cf_ray = headers.get("CF-RAY")
        return "cloudflare" in server or cf_ray is not None

    def _has_suspicious_tld(self, urls: List[str]) -> bool:
        """Check if any URL has a suspicious TLD."""
        for url in urls:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                return True
        return False

    def _has_url_shortener(self, urls: List[str]) -> bool:
        """Check if any URL is from a known shortener."""
        for url in urls:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            # Remove 'www.' prefix
            domain = domain.replace("www.", "")
            if domain in URL_SHORTENERS:
                return True
        return False

    def _has_cross_domain(self, urls: List[str]) -> bool:
        """Check if redirect chain crosses domains."""
        if len(urls) < 2:
            return False

        domains = set()
        for url in urls:
            parsed = urlparse(url)
            # Extract base domain (remove subdomains for comparison)
            parts = parsed.netloc.split(".")
            if len(parts) >= 2:
                base_domain = ".".join(parts[-2:])
                domains.add(base_domain)

        return len(domains) > 1

    def _calculate_risk_score(self, chain: RedirectChain) -> int:
        """
        Calculate risk score (0-100) based on redirect characteristics.

        Scoring factors:
        - Number of hops: +10 per hop
        - Cloudflare intermediary: +15
        - Suspicious TLD: +20
        - URL shortener: +10
        - Cross-domain redirect: +15
        - Redirect loop: +30
        """
        score = 0

        # Base score from number of hops
        score += min(chain.hop_count * 10, 50)  # Max 50 from hops

        # Cloudflare intermediary (not as final destination)
        if chain.has_cloudflare and chain.hop_count > 1:
            score += 15

        # Suspicious TLD
        if chain.has_suspicious_tld:
            score += 20

        # URL shortener
        if chain.has_url_shortener:
            score += 10

        # Cross-domain redirect
        if chain.has_cross_domain:
            score += 15

        # Redirect loop
        if chain.has_loop:
            score += 30

        # Cap at 100
        return min(score, 100)
