"""Route abuse reports to the channel each provider actually reads.

Some registrars and hosting providers ignore abuse e-mail and only act on
their web form (``method == "form_only"`` in ``src.data.registrar_form_db``).
E-mailing them is not a report, it is a dropped report. :func:`plan_delivery`
turns such recipients into analyst web-form tasks, applies the recipient
policy to everything else and caps the number of primary recipients.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Tuple

from src.data.registrar_form_db import lookup_form_by_email, lookup_registrar_form
from src.reporting.recipient_policy import normalize_email, recipient_rejection_reason

# How Cloudflare's own name appears in the form database.
_CLOUDFLARE_PROVIDER_NAME = "Cloudflare, Inc."


@dataclass(frozen=True)
class FormTask:
    """A report that an analyst has to file through a provider's web form."""

    provider: str
    form_url: str
    reason: str


@dataclass
class DeliveryPlan:
    """Where a report goes: e-mail recipients and analyst web-form tasks."""

    emails: List[str] = field(default_factory=list)
    form_tasks: List[FormTask] = field(default_factory=list)
    rejected: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """Whether the plan has neither e-mail recipients nor form tasks.

        Returns:
            ``True`` when nothing can be delivered.
        """
        return not self.emails and not self.form_tasks


def plan_delivery(
    candidates: Iterable[str],
    site_url: str,
    *,
    registrar: Optional[str] = None,
    hosting_provider: Optional[str] = None,
    is_cloudflare: bool = False,
    site_content: Optional[str] = None,
    max_recipients: int = 5,
    validate_email: Optional[Callable[[str], bool]] = None,
) -> DeliveryPlan:
    """Split trust-ordered candidates into e-mail recipients and form tasks.

    Args:
        candidates: Candidate addresses, most trusted first.
        site_url: Reported URL (used for the same-domain check).
        registrar: Registrar name from WHOIS/RDAP, when known.
        hosting_provider: Network/hosting provider name, when known.
        is_cloudflare: Whether the site resolves to Cloudflare's proxy.
        site_content: Content served by the site, when available.
        max_recipients: Maximum number of primary e-mail recipients.
        validate_email: Optional deliverability check (format, MX).

    Returns:
        The delivery plan; rejected candidates carry the reason.
    """
    plan = DeliveryPlan()
    seen_providers = set()

    def add_task(form: dict, reason: str) -> None:
        if form["name"] in seen_providers:
            return
        seen_providers.add(form["name"])
        plan.form_tasks.append(
            FormTask(provider=form["name"], form_url=form["form_url"], reason=reason)
        )

    for raw in candidates:
        email = normalize_email(raw)
        if not email or email in plan.emails:
            continue
        reason = recipient_rejection_reason(email, site_url, site_content)
        if reason:
            plan.rejected.append((email, reason))
            continue
        form = lookup_form_by_email(email)
        if form and form["method"] == "form_only":
            add_task(form, f"{email} is not monitored; the provider only accepts its web form")
            continue
        if validate_email is not None and not validate_email(email):
            plan.rejected.append((email, "address failed deliverability validation"))
            continue
        if len(plan.emails) >= max_recipients:
            plan.rejected.append((email, f"over the {max_recipients}-recipient cap"))
            continue
        plan.emails.append(email)

    providers = (
        (registrar, "registrar"),
        (hosting_provider, "hosting provider"),
        (_CLOUDFLARE_PROVIDER_NAME if is_cloudflare else None, "reverse proxy"),
    )
    for name, role in providers:
        form = lookup_registrar_form(name)
        if form and form["method"] == "form_only":
            add_task(form, f"{role} {name} only accepts abuse reports through its web form")

    return plan
