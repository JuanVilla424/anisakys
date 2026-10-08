"""Render abuse reports and build the MIME messages that carry them.

Every report is a ``multipart/alternative`` message with a ``text/plain`` part
and an HTML part (wrapped in ``multipart/mixed`` when files are attached).
Both parts come from Jinja2 templates under ``templates/``: ``.html``
templates are autoescaped, so WHOIS/RDAP values and analyst-provided text are
inert; ``.txt`` templates are plain text and never interpreted as markup.

The reported URL is always defanged (``hxxps://example[.]com/path``) and never
rendered as a link, and subjects and evidence lines are stripped of emoji.
"""

from __future__ import annotations

import ipaddress
import mimetypes
import os
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from src.logger import logger
from src.reporting.recipient_policy import host_of

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"
WHOIS_EXCERPT_MAX_CHARS = 4000
_SCHEME_RE = re.compile(r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://")

_environment: Optional[Environment] = None


def _templates() -> Environment:
    """Return the shared Jinja2 environment (autoescape for .html/.xml).

    Returns:
        The lazily created environment.
    """
    global _environment
    if _environment is None:
        _environment = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
            undefined=StrictUndefined,
            keep_trailing_newline=True,
        )
    return _environment


def defang_host(host: str) -> str:
    """Defang a host name or IP address (``example[.]com``).

    Args:
        host: Host name or IP literal.

    Returns:
        The host with every dot bracketed.
    """
    return (host or "").replace(".", "[.]")


def defang_url(url: str) -> str:
    """Defang a URL so it is neither clickable nor auto-linked.

    ``https://login.example.com/path?a=1`` becomes
    ``hxxps://login[.]example[.]com/path?a=1``: the scheme loses its ``t`` and
    the dots of the host are bracketed. The path is left readable.

    Args:
        url: URL as reported.

    Returns:
        The defanged URL.
    """
    value = (url or "").strip()
    match = _SCHEME_RE.match(value)
    scheme = ""
    rest = value
    if match:
        scheme = match.group("scheme").lower()
        rest = value[match.end() :]
        scheme = scheme.replace("http", "hxxp").replace("ftp", "fxp")
    authority, sep, tail = rest.partition("/")
    if "@" in authority:
        userinfo, _, hostport = authority.rpartition("@")
        authority = f"{userinfo}[@]{defang_host(hostport)}"
    else:
        authority = defang_host(authority)
    defanged = f"{authority}{sep}{tail}"
    return f"{scheme}://{defanged}" if scheme else defanged


def strip_emoji(value: str) -> str:
    """Remove emoji and pictographic symbols from text.

    Args:
        value: Text that may contain emoji (e.g. legacy recommendation lines).

    Returns:
        The text without symbol-other characters, variation selectors or
        zero-width joiners, with whitespace collapsed.
    """
    kept = [
        char
        for char in value or ""
        if unicodedata.category(char) not in ("So", "Cs", "Co") and char not in ("️", "︎", "‍")
    ]
    return re.sub(r"\s+", " ", "".join(kept)).strip()


def utc_text(moment: Optional[datetime]) -> str:
    """Format a timestamp as ``YYYY-MM-DD HH:MM UTC``.

    Naive values are assumed to already be UTC.

    Args:
        moment: Timestamp to format.

    Returns:
        The formatted value, or an empty string for ``None``.
    """
    if moment is None:
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def evidence_lines(
    multi_api_results: Optional[Dict[str, Any]],
    detection_keywords: Optional[str] = None,
) -> List[str]:
    """Summarise multi-source detection results as plain evidence lines.

    Args:
        multi_api_results: Aggregated results (``virustotal``, ``urlvoid``,
            ``phishtank``, ``google_safe_browsing``, ``recommendations``...).
        detection_keywords: Keywords that triggered detection, if any.

    Returns:
        Short human-readable lines without emoji.
    """
    lines: List[str] = []
    results = multi_api_results or {}
    vt = results.get("virustotal") or {}
    if isinstance(vt, dict) and not vt.get("error") and vt.get("total_engines"):
        lines.append(
            f"VirusTotal: {vt.get('malicious', 0)} of {vt.get('total_engines')} engines "
            "flag the URL as malicious"
        )
    uv = results.get("urlvoid") or {}
    if isinstance(uv, dict) and not uv.get("error") and uv.get("blacklists"):
        lines.append(f"URLVoid: listed on {len(uv['blacklists'])} blocklist(s)")
    pt = results.get("phishtank") or {}
    if isinstance(pt, dict) and not pt.get("error") and pt.get("is_phishing"):
        lines.append(
            "PhishTank: verified phishing" if pt.get("verified") else "PhishTank: reported phishing"
        )
    gsb = results.get("google_safe_browsing") or results.get("gsb") or {}
    if isinstance(gsb, dict) and (gsb.get("threat_type") or gsb.get("is_threat")):
        lines.append(f"Google Safe Browsing: {gsb.get('threat_type') or 'listed as unsafe'}")
    if detection_keywords:
        lines.append(f"Detection keywords: {strip_emoji(str(detection_keywords))}")
    for recommendation in results.get("recommendations") or []:
        text = strip_emoji(str(recommendation))
        if text and text not in lines:
            lines.append(text)
    return lines[:12]


@dataclass
class ReportEvidence:
    """Everything a report says about a site, stored with the tracked report.

    It is rendered into the initial report and re-rendered, unchanged, into
    every follow-up, so follow-ups carry the same evidence and report id.
    """

    site_url: str
    origin: str = "automated"
    brand_name: Optional[str] = None
    first_seen_utc: Optional[str] = None
    threat_level: Optional[str] = None
    confidence_score: Optional[int] = None
    evidence: List[str] = field(default_factory=list)
    resolved_ip: Optional[str] = None
    asn: Optional[str] = None
    hosting_provider: Optional[str] = None
    registrar: Optional[str] = None
    whois_excerpt: Optional[str] = None
    attachments: List[str] = field(default_factory=list)
    reproduction_note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for the ``abuse_reports.evidence`` JSONB column.

        Returns:
            A JSON-compatible dict.
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]], site_url: str) -> "ReportEvidence":
        """Rebuild evidence stored by :meth:`to_dict`, tolerating missing keys.

        Args:
            data: Stored evidence (may be ``None`` for legacy reports).
            site_url: URL to fall back on when ``data`` lacks it.

        Returns:
            The evidence object.
        """
        data = dict(data or {})
        known = {name for name in cls.__dataclass_fields__}
        values = {key: value for key, value in data.items() if key in known}
        values.setdefault("site_url", site_url)
        return cls(**values)


def build_evidence(
    site_url: str,
    *,
    origin: str,
    brand_name: Optional[str],
    multi_api_results: Optional[Dict[str, Any]],
    detection_keywords: Optional[str] = None,
    first_seen: Optional[datetime] = None,
    resolved_ip: Optional[str] = None,
    asn: Optional[str] = None,
    hosting_provider: Optional[str] = None,
    registrar: Optional[str] = None,
    whois_text: Optional[str] = None,
    attachments: Sequence[str] = (),
    reproduction_note: Optional[str] = None,
) -> ReportEvidence:
    """Assemble :class:`ReportEvidence` from what the pipeline knows about a site.

    Args:
        site_url: Reported URL.
        origin: ``"analyst"`` for analyst/external submissions, else ``"automated"``.
        brand_name: Impersonated brand, if known.
        multi_api_results: Multi-source detection results.
        detection_keywords: Keywords that triggered detection.
        first_seen: When the site was first detected.
        resolved_ip: Resolved IP address.
        asn: Autonomous system of the IP.
        hosting_provider: Network/hosting provider name.
        registrar: Registrar name.
        whois_text: Registration data dump (truncated for the report).
        attachments: Attachment file names.
        reproduction_note: How an abuse desk can see the content.

    Returns:
        The evidence.
    """
    results = multi_api_results or {}
    threat_level = results.get("aggregated_threat_level") or results.get("threat_level")
    if not threat_level or str(threat_level).lower() == "unknown":
        threat_level = None
    confidence = results.get("confidence_score")
    confidence_score = int(confidence) if threat_level and confidence is not None else None
    excerpt = (whois_text or "").strip()
    if excerpt in ("", "{}", "None"):
        excerpt = ""
    if len(excerpt) > WHOIS_EXCERPT_MAX_CHARS:
        excerpt = excerpt[:WHOIS_EXCERPT_MAX_CHARS] + "\n[truncated]"
    return ReportEvidence(
        site_url=site_url,
        origin=origin,
        brand_name=brand_name or None,
        first_seen_utc=utc_text(first_seen) or None,
        threat_level=str(threat_level).lower() if threat_level else None,
        confidence_score=confidence_score,
        evidence=evidence_lines(results, detection_keywords),
        resolved_ip=resolved_ip or None,
        asn=asn or None,
        hosting_provider=hosting_provider or None,
        registrar=registrar or None,
        whois_excerpt=excerpt or None,
        attachments=[os.path.basename(path) for path in attachments],
        reproduction_note=reproduction_note or None,
    )


@dataclass(frozen=True)
class RenderedMessage:
    """Subject plus both bodies of one message."""

    subject: str
    text: str
    html: str

    def to_payload(self, attachments: Sequence[str] = ()) -> Dict[str, Any]:
        """Serialise for the outbox ``payload`` column.

        Args:
            attachments: Attachment paths to add when the message is built.

        Returns:
            JSON-compatible payload.
        """
        return {
            "subject": self.subject,
            "text": self.text,
            "html": self.html,
            "attachments": list(attachments),
        }


def _subject(prefix: str, base: str, site_url: str, is_test: bool) -> str:
    """Build a subject line that carries the report id and no emoji.

    Args:
        prefix: Leading bracketed tag(s), e.g. ``[ANISAKYS-...]``.
        base: Configured subject text.
        site_url: Reported URL (only its defanged host is used).
        is_test: Add a ``[TEST]`` marker.

    Returns:
        The subject.
    """
    host = defang_host(host_of(site_url)) or "unknown host"
    clean = strip_emoji(base) or "Phishing report"
    test = "[TEST] " if is_test else ""
    return f"{test}{prefix} {clean}: {host}"


def _context(evidence: ReportEvidence, **extra: Any) -> Dict[str, Any]:
    """Template context shared by every report template.

    Args:
        evidence: Report evidence.
        **extra: Template-specific values.

    Returns:
        The context dict.
    """
    resolved_ip = evidence.resolved_ip
    defanged_ip = ""
    if resolved_ip:
        try:
            ipaddress.ip_address(resolved_ip)
            defanged_ip = defang_host(resolved_ip)
        except ValueError:
            defanged_ip = defang_host(resolved_ip)
    context = dict(evidence.to_dict())
    context.update(
        defanged_url=defang_url(evidence.site_url),
        defanged_ip=defanged_ip,
        notified_recipients=[],
        cc_disclosure=[],
        escalation_contacts=[],
        is_test=False,
        site_status=None,
    )
    context.update(extra)
    return context


def render_initial_report(
    evidence: ReportEvidence,
    *,
    report_id: str,
    report_time: datetime,
    subject_base: str,
    organization: str,
    followup_hours: int,
    cc_disclosure: Sequence[str] = (),
    notified_recipients: Sequence[str] = (),
    is_test: bool = False,
) -> RenderedMessage:
    """Render the first report for a site.

    Args:
        evidence: What the report says.
        report_id: Tracked report id (also used in the subject).
        report_time: When the report is generated.
        subject_base: Configured subject text (``ABUSE_EMAIL_SUBJECT``).
        organization: Reporting organisation for the signature.
        followup_hours: Delay before a follow-up, stated in the report.
        cc_disclosure: Addresses that receive a copy, disclosed to the reader.
        notified_recipients: Set on the CC copy: who received the report.
        is_test: Mark the message as a test.

    Returns:
        Subject, text and HTML bodies.
    """
    context = _context(
        evidence,
        report_id=report_id,
        report_time_utc=utc_text(report_time),
        organization=organization,
        followup_hours=followup_hours,
        cc_disclosure=list(cc_disclosure),
        notified_recipients=list(notified_recipients),
        is_test=is_test,
    )
    env = _templates()
    return RenderedMessage(
        subject=_subject(f"[{report_id}]", subject_base, evidence.site_url, is_test),
        text=env.get_template("abuse_report.txt").render(**context),
        html=env.get_template("abuse_report.html").render(**context),
    )


def render_followup(
    evidence: ReportEvidence,
    *,
    report_id: str,
    followup_seq: int,
    original_report_time: Optional[datetime],
    check_time: datetime,
    subject_base: str,
    organization: str,
    site_status: Optional[str] = None,
    escalation_contacts: Sequence[str] = (),
    notified_recipients: Sequence[str] = (),
) -> RenderedMessage:
    """Render a follow-up that repeats the original evidence and report id.

    Args:
        evidence: Evidence stored with the original report.
        report_id: Tracked report id.
        followup_seq: 1 for the first follow-up, 2 for the second...
        original_report_time: When the original report was sent.
        check_time: When the site was found still online.
        subject_base: Configured subject text.
        organization: Reporting organisation for the signature.
        site_status: Current site status, if known.
        escalation_contacts: Escalation addresses disclosed to the reader.
        notified_recipients: Set on the CC copy: who received the follow-up.

    Returns:
        Subject, text and HTML bodies.
    """
    context = _context(
        evidence,
        report_id=report_id,
        followup_seq=followup_seq,
        original_report_time_utc=utc_text(original_report_time) or "an earlier date",
        report_time_utc=utc_text(check_time),
        organization=organization,
        site_status=site_status,
        escalation_contacts=list(escalation_contacts),
        notified_recipients=list(notified_recipients),
    )
    env = _templates()
    return RenderedMessage(
        subject=_subject(
            f"[{report_id}] Follow-up {followup_seq}:", subject_base, evidence.site_url, False
        ),
        text=env.get_template("abuse_followup.txt").render(**context),
        html=env.get_template("abuse_followup.html").render(**context),
    )


def build_email(
    payload: Dict[str, Any],
    *,
    sender: str,
    to_addrs: Sequence[str],
    message_id: Optional[str] = None,
    max_attachment_bytes: int = 25 * 1024 * 1024,
    max_total_bytes: int = 50 * 1024 * 1024,
) -> Tuple[EmailMessage, List[str]]:
    """Build the MIME message for an outbox payload.

    The result is ``multipart/alternative`` (text first, then HTML), wrapped
    in ``multipart/mixed`` when attachments fit the size limits. No ``Cc``
    header is set: every outbox row is one message to its own recipients.

    Args:
        payload: ``{"subject", "text", "html", "attachments"}``.
        sender: ``From`` address.
        to_addrs: ``To`` addresses (also the envelope recipients).
        message_id: Stable ``Message-ID`` so a retried send is recognisable.
        max_attachment_bytes: Larger files are skipped.
        max_total_bytes: Attachments that would exceed this are skipped.

    Returns:
        The message and the names of the files actually attached.
    """
    message = EmailMessage()
    message["Subject"] = payload.get("subject") or "Phishing report"
    message["From"] = sender
    message["To"] = ", ".join(to_addrs)
    message["Date"] = formatdate(usegmt=True)
    if message_id:
        message["Message-ID"] = message_id
    message.set_content(payload.get("text") or "", subtype="plain", charset="utf-8")
    message.add_alternative(payload.get("html") or "", subtype="html", charset="utf-8")

    attached: List[str] = []
    budget = max_total_bytes - len(message.as_bytes())
    for path in payload.get("attachments") or []:
        name = os.path.basename(path)
        if not os.path.isfile(path):
            logger.warning(f"Attachment not found, skipped: {name}")
            continue
        size = os.path.getsize(path)
        encoded_size = (size * 4) // 3 + 1024
        if size > max_attachment_bytes or encoded_size > budget:
            logger.warning(f"Attachment {name} ({size} bytes) exceeds the size limit, skipped")
            continue
        with open(path, "rb") as handle:
            data = handle.read()
        mime_type, _ = mimetypes.guess_type(name)
        maintype, _, subtype = (mime_type or "application/octet-stream").partition("/")
        message.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
        attached.append(name)
        budget -= encoded_size
    return message, attached


def message_id_for(report_id: str, followup_seq: int, row_id: int, sender: str) -> str:
    """Deterministic ``Message-ID`` for an outbox row.

    Re-sending the same row (a retried attempt) reuses the id, so receiving
    systems can recognise the duplicate.

    Args:
        report_id: Tracked report id.
        followup_seq: 0 for the initial report, n for the n-th follow-up.
        row_id: Outbox row id.
        sender: ``From`` address; its domain is the id's right-hand side.

    Returns:
        The ``<...>`` message id.
    """
    domain = (sender or "").rpartition("@")[2] or "anisakys.invalid"
    return f"<{report_id}.{followup_seq}.{row_id}@{domain}>"


def unique_preserving(values: Iterable[str]) -> List[str]:
    """Drop empty and duplicate values while keeping order.

    Args:
        values: Values.

    Returns:
        The unique values.
    """
    seen = set()
    result: List[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result
