"""
AiTM/Evilginx reverse-proxy phishing kit fingerprinting.

Confirmed against real, current security research (not assumed) -- Deepwatch
"Catching the Phish" writeup, Microsoft Security Blog's AiTM campaign
analysis, Group-IB/SentinelOne AiTM writeups. Three concrete signals a
reverse-proxy AiTM kit (Evilginx and similar) leaves behind:

1. A leaked `X-Evilginx` response header -- a documented, real IoC some
   deployments expose directly.
2. Missing Strict-Transport-Security/Content-Security-Policy headers on a
   domain that lexically targets a known brand -- Evilginx (a Go reverse
   proxy) commonly fails to faithfully replicate these from the real site,
   since relaying them correctly would break its own injected proxy
   behavior. Weak alone (many legitimate small sites also lack these); only
   scored when a brand_hint is given, since without one this would just be
   "site doesn't set security headers," true of huge swathes of the web.
3. The impersonated brand's own real domain leaking into the candidate
   page's rendered content -- Evilginx rewrites domain references
   throughout HTML/JS/CSS/headers to route through the phishing domain, but
   this rewriting is frequently incomplete (dynamically-built URLs,
   WebSocket endpoints, hardcoded absolute paths). The real brand domain
   still appearing in the candidate's own content is a strong, specific
   reverse-proxy leftover.

Explicitly NOT attempted (out of reach for an external HTTP-client-based
scanner): JA3/JA4 TLS fingerprinting of the phishing server's own outbound
connections (requires being positioned in the network path) and IdP
sign-in-log/"impossible travel" correlation (requires access to the
*targeted organization's own* identity telemetry).
"""

from typing import Any, Dict, List, Optional

import requests

from src.detection.url_analyzer import KNOWN_BRANDS

# Content read cap for the brand-domain-leak scan -- large enough to catch
# footer/script-tag references without buffering an entire huge page.
_CONTENT_SCAN_CAP = 200_000

_HEADER_IOC_WEIGHT = 90
_MISSING_HSTS_WEIGHT = 20
_MISSING_CSP_WEIGHT = 15
# The single most specific, hardest-to-fake signal of the three -- the real
# brand's own domain appearing in the candidate's content is sufficient on
# its own to cross _GENERIC_AITM_THRESHOLD, unlike the two header checks
# above (which are individually weak and only meaningful combined).
_BRAND_DOMAIN_LEAK_WEIGHT = 60
_GENERIC_AITM_THRESHOLD = 50

# Known leaked internal headers -- structured as a set so more can be added
# without redesigning the check itself.
_LEAKED_HEADER_IOCS = {"x-evilginx"}


def score_kit_indicators(
    url: str, response: requests.Response, brand_hint: Optional[str] = None
) -> Dict[str, Any]:
    """Score a fetched response for AiTM/Evilginx reverse-proxy indicators.

    brand_hint: a KNOWN_BRANDS key (e.g. "nequi"), or None. The HSTS/CSP and
    brand-domain-leak checks only run when a hint is given -- without a
    specific brand being targeted, "missing security headers" is true of a
    huge fraction of the legitimate web and isn't a meaningful signal here.
    """
    indicators: List[str] = []
    score = 0

    header_names = {k.lower() for k in response.headers.keys()}
    if header_names & _LEAKED_HEADER_IOCS:
        indicators.append("x_evilginx_header")
        score += _HEADER_IOC_WEIGHT

    if brand_hint:
        if "strict-transport-security" not in header_names:
            indicators.append("missing_hsts")
            score += _MISSING_HSTS_WEIGHT
        if "content-security-policy" not in header_names:
            indicators.append("missing_csp")
            score += _MISSING_CSP_WEIGHT

        real_domains = KNOWN_BRANDS.get(brand_hint, [])
        candidate_domain = _domain_of(url)
        if real_domains:
            try:
                content = response.text[:_CONTENT_SCAN_CAP]
            except Exception:
                content = ""
            for real_domain in real_domains:
                if real_domain in content and real_domain != candidate_domain:
                    indicators.append(f"brand_domain_leak:{real_domain}")
                    score += _BRAND_DOMAIN_LEAK_WEIGHT
                    break

    score = min(score, 100)
    if "x_evilginx_header" in indicators:
        kit_type = "evilginx"
    elif score >= _GENERIC_AITM_THRESHOLD:
        kit_type = "generic_aitm"
    else:
        kit_type = None

    return {"kit_type": kit_type, "confidence": score, "indicators": indicators}


def _domain_of(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).netloc.lower().split(":")[0]
