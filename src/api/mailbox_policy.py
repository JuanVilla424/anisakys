"""Which mailboxes the e-mail threat monitor may be pointed at through the API.

E-mail monitor threads are read with a Google Workspace service account that
has domain-wide delegation, i.e. it can open *any* mailbox of the tenant. The
API therefore only accepts mailboxes an operator explicitly allowed:

* ``EMAIL_MONITOR_ALLOWED_MAILBOXES`` — comma-separated addresses; an entry
  ``@example.com`` (or ``*@example.com``) allows every mailbox of that domain
  and domain-wide monitoring of it;
* ``EMAIL_MONITORED_MAILBOXES`` and ``EMAIL_ABUSE_MAILBOX`` — mailboxes the
  deployment already monitors, implicitly allowed.

Nothing is allowed when none of these settings is set.
"""

from typing import FrozenSet, Optional, Tuple

from src.config import settings


def _entries(*raw_values: Optional[str]) -> FrozenSet[str]:
    """Split comma-separated settings into normalised (lower-case) entries.

    Args:
        *raw_values: Raw setting values; None is ignored.

    Returns:
        The non-empty entries.
    """
    entries = set()
    for raw in raw_values:
        for item in (raw or "").split(","):
            item = item.strip().lower()
            if item:
                entries.add(item)
    return frozenset(entries)


def allowlist() -> Tuple[FrozenSet[str], FrozenSet[str]]:
    """Return the allowed mailboxes and the domains allowed as a whole.

    Returns:
        ``(mailboxes, domains)``, both lower-cased.
    """
    entries = _entries(
        settings.EMAIL_MONITOR_ALLOWED_MAILBOXES,
        settings.EMAIL_MONITORED_MAILBOXES,
        settings.EMAIL_ABUSE_MAILBOX,
    )
    domains = frozenset(
        entry.split("@", 1)[1] for entry in entries if entry.startswith(("@", "*@"))
    )
    mailboxes = frozenset(entry for entry in entries if not entry.startswith(("@", "*@")))
    return mailboxes, domains


def is_mailbox_allowed(mailbox: str) -> bool:
    """Tell whether a single mailbox may be monitored.

    Args:
        mailbox: E-mail address of the mailbox.

    Returns:
        True when the address, or its whole domain, is on the allowlist.
    """
    mailbox = mailbox.strip().lower()
    mailboxes, domains = allowlist()
    if mailbox in mailboxes:
        return True
    _, _, domain = mailbox.rpartition("@")
    return bool(domain) and domain in domains


def is_domain_allowed(domain: str) -> bool:
    """Tell whether every mailbox of a domain may be monitored.

    Args:
        domain: Workspace domain to monitor domain-wide.

    Returns:
        True only when the allowlist contains ``@domain`` (or ``*@domain``).
    """
    _, domains = allowlist()
    return domain.strip().lower() in domains
