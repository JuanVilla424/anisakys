"""Who may receive an abuse report, and in which order.

The rules exist because a wrong recipient is worse than no recipient: an
e-mail to a registrant address tips off the attacker, and a complaint to a
provider that does not host the site wastes the report and that provider's
time.

* Only abuse-role contacts are accepted from WHOIS/RDAP: the RDAP ``abuse``
  entity, labelled ``... Abuse Contact Email`` lines and addresses whose local
  part is abuse-like. Registrant, admin and tech addresses are never used.
* A recipient on the same registrable domain (eTLD+1, Public Suffix List) as
  the reported site is rejected, as is any address published in the site's
  own content: both are controlled by the attacker.
* Candidates are ordered by trust — RDAP abuse > curated database > ASN/IP
  abuse-c — instead of the arbitrary order of a ``set``.

The PSL comes from the snapshot bundled with ``tldextract``; it never fetches
the list over the network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum
from typing import Iterable, List, Optional
from urllib.parse import urlsplit

import tldextract

# Bundled Public Suffix List snapshot only: no network fetch, no cache writes.
_PSL = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_ABUSE_LOCAL_PART_RE = re.compile(r"abuse", re.IGNORECASE)

# WHOIS line labels that carry the contact data of the domain holder. Any
# address that appears on such a line is never a valid recipient.
_HOLDER_LABEL_RE = re.compile(
    r"^\s*(registrant|admin|administrative|tech|technical|billing|owner)[\w\s-]*:",
    re.IGNORECASE,
)
# Labels that explicitly carry an abuse contact (gTLD WHOIS, RIR objects).
_ABUSE_LABEL_RE = re.compile(
    r"^\s*(registrar\s+abuse\s+contact\s+email|abuse[\w\s-]*|orgabuseemail)\s*:\s*(.+)$",
    re.IGNORECASE,
)


class ContactTier(IntEnum):
    """Trust tiers of abuse contacts; lower values are more trusted."""

    MANUAL = 0
    RDAP_ABUSE = 1
    CURATED = 2
    ASN_ABUSE = 3


@dataclass(frozen=True)
class ContactCandidate:
    """An abuse contact candidate with the tier and source it came from."""

    email: str
    tier: ContactTier
    source: str


def normalize_email(email: str) -> str:
    """Trim and lowercase an e-mail address.

    Args:
        email: Raw address.

    Returns:
        The normalised address (empty string for falsy input).
    """
    return (email or "").strip().strip("<>").lower()


def host_of(url_or_host: str) -> str:
    """Return the lowercase host of a URL, or the input itself when it is a host.

    Args:
        url_or_host: ``https://a.b/c`` style URL or a bare host name.

    Returns:
        Host name without port, ``www.`` is kept (the PSL handles it).
    """
    value = (url_or_host or "").strip()
    if "://" not in value:
        value = "//" + value
    host = urlsplit(value).hostname or ""
    return host.lower().rstrip(".")


def registrable_domain(url_or_host: str) -> str:
    """Return the registrable domain (eTLD+1) of a URL, host or e-mail domain.

    Args:
        url_or_host: URL, host name or e-mail domain.

    Returns:
        ``example.co.uk`` for ``a.b.example.co.uk``; the bare host when the
        PSL has no registrable part (IP addresses, single labels).
    """
    host = host_of(url_or_host)
    extracted = _PSL(host)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return host


def is_abuse_role_address(email: str) -> bool:
    """Whether the local part of ``email`` names an abuse role.

    Args:
        email: Address to inspect.

    Returns:
        ``True`` for ``abuse@``, ``abuse-desk@``, ``domainabuse@`` and similar.
    """
    local, _, domain = normalize_email(email).partition("@")
    return bool(domain) and bool(_ABUSE_LOCAL_PART_RE.search(local))


def emails_in_text(content: Optional[str]) -> List[str]:
    """Extract normalised e-mail addresses from free text.

    Args:
        content: Any text (page HTML, WHOIS dump); ``None`` is allowed.

    Returns:
        Unique addresses in order of appearance.
    """
    if not content:
        return []
    return _dedupe(normalize_email(match) for match in _EMAIL_RE.findall(content))


def holder_emails_in_whois(whois_text: Optional[str]) -> List[str]:
    """Addresses that appear on registrant/admin/tech/billing WHOIS lines.

    Args:
        whois_text: Raw WHOIS text.

    Returns:
        Addresses that belong to the domain holder and must never be e-mailed.
    """
    found: List[str] = []
    for line in (whois_text or "").splitlines():
        if _HOLDER_LABEL_RE.match(line):
            found.extend(emails_in_text(line))
    return _dedupe(found)


def labelled_abuse_emails_in_whois(whois_text: Optional[str]) -> List[str]:
    """Addresses on WHOIS lines whose label names an abuse contact.

    Args:
        whois_text: Raw WHOIS text.

    Returns:
        Addresses such as the value of ``Registrar Abuse Contact Email:``.
    """
    found: List[str] = []
    for line in (whois_text or "").splitlines():
        match = _ABUSE_LABEL_RE.match(line)
        if match:
            found.extend(emails_in_text(match.group(2)))
    return _dedupe(found)


def recipient_rejection_reason(
    email: str, site: str, site_content: Optional[str] = None
) -> Optional[str]:
    """Explain why ``email`` must not receive a report about ``site``.

    Args:
        email: Candidate recipient.
        site: Reported URL or host.
        site_content: Content served by the site, when available.

    Returns:
        A short reason, or ``None`` when the recipient is acceptable.
    """
    address = normalize_email(email)
    local, _, domain = address.partition("@")
    if not local or not domain or "." not in domain:
        return "malformed address"
    site_domain = registrable_domain(site)
    if site_domain and registrable_domain(domain) == site_domain:
        return f"recipient is on the reported site's registrable domain ({site_domain})"
    if site_content and address in emails_in_text(site_content):
        return "address is published by the reported site itself"
    return None


def is_acceptable_recipient(email: str, site: str, site_content: Optional[str] = None) -> bool:
    """Whether ``email`` may receive a report about ``site``.

    Args:
        email: Candidate recipient.
        site: Reported URL or host.
        site_content: Content served by the site, when available.

    Returns:
        ``True`` when :func:`recipient_rejection_reason` finds nothing.
    """
    return recipient_rejection_reason(email, site, site_content) is None


def order_by_trust(candidates: Iterable[ContactCandidate]) -> List[str]:
    """Order candidates by trust tier, keeping discovery order inside a tier.

    Args:
        candidates: Candidates in discovery order.

    Returns:
        Unique normalised addresses, most trusted first.
    """
    indexed = list(enumerate(candidates))
    indexed.sort(key=lambda item: (item[1].tier, item[0]))
    return _dedupe(normalize_email(candidate.email) for _, candidate in indexed)


def _dedupe(values: Iterable[str]) -> List[str]:
    """Drop empty values and duplicates while preserving order.

    Args:
        values: Values to filter.

    Returns:
        The unique, non-empty values.
    """
    seen = set()
    result: List[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result
