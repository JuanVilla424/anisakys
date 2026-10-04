"""
Google Workspace Blocked Senders — Cloud Identity Policy API v1beta1.

Manages the "Anisakys" entry inside the existing gmail.blocked_sender_lists policy
of the customer configured in ``GOOGLE_WORKSPACE_CUSTOMER_ID`` (default
``my_customer``, the documented alias for the caller's own organization).
"""

import re
import threading
from typing import Optional

from src.config import settings
from src.logger import logger

POLICY_SCOPE = "https://www.googleapis.com/auth/cloud-identity.policies"
SETTING_TYPE = "settings/gmail.blocked_sender_lists"
DEFAULT_CUSTOMER_ID = "my_customer"
LIST_NAME = "Anisakys"

_CUSTOMER_ID_RE = re.compile(r"^[A-Za-z0-9_]+$")


def customer_resource(customer_id: Optional[str]) -> str:
    """Build the ``customers/{id}`` resource name used in policy filters.

    Args:
        customer_id: Workspace customer ID (``C0...``), ``my_customer``, or an
            already-prefixed ``customers/{id}``. Empty means ``my_customer``.

    Returns:
        The resource name, e.g. ``customers/my_customer``.

    Raises:
        ValueError: If the ID contains characters a customer ID cannot have
            (it is interpolated into a CEL filter).
    """
    value = (customer_id or "").strip() or DEFAULT_CUSTOMER_ID
    if value.startswith("customers/"):
        value = value[len("customers/") :]
    if not _CUSTOMER_ID_RE.match(value):
        raise ValueError(f"Invalid Google Workspace customer ID: {value!r}")
    return f"customers/{value}"


class BlockedSendersClient:
    """Read/modify the Anisakys entry of the Gmail blocked-senders policy."""

    def __init__(
        self, service_account_file: str, admin_email: str, customer_id: Optional[str] = None
    ):
        """Create a client authorised as ``admin_email`` via domain-wide delegation.

        Args:
            service_account_file: Path to the service-account JSON key.
            admin_email: Workspace admin to impersonate.
            customer_id: Workspace customer; defaults to
                ``GOOGLE_WORKSPACE_CUSTOMER_ID`` (``my_customer``).

        Raises:
            ValueError: If the customer ID is malformed.
        """
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        self.customer = customer_resource(
            customer_id or getattr(settings, "GOOGLE_WORKSPACE_CUSTOMER_ID", None)
        )

        creds = service_account.Credentials.from_service_account_file(
            service_account_file,
            scopes=[POLICY_SCOPE],
        ).with_subject(admin_email)

        self._svc = build("cloudidentity", "v1beta1", credentials=creds, cache_discovery=False)
        self._lock = threading.Lock()

    def _get_policy(self) -> tuple[str, list]:
        """Return (policy_name, blockedSenders list) from the existing policy.

        Returns:
            The policy resource name and its ``blockedSenders`` list.

        Raises:
            Exception: If the customer has no gmail.blocked_sender_lists policy.
        """
        resp = (
            self._svc.policies()
            .list(
                filter=f'customer=="{self.customer}" && setting.type=="{SETTING_TYPE}"',
                pageSize=50,
            )
            .execute()
        )
        policies = resp.get("policies", [])
        if not policies:
            raise Exception("blocked_senders: no gmail.blocked_sender_lists policy found")
        p = policies[0]
        blocked = p.get("setting", {}).get("value", {}).get("blockedSenders", [])
        return p["name"], blocked

    def _find_or_create_anisakys(self, policy_name: str, blocked: list) -> tuple[int, list]:
        """
        Return (index, senderBlocklist) for the Anisakys entry.
        Creates the entry in the policy if it doesn't exist.
        """
        for i, entry in enumerate(blocked):
            if entry.get("description", "").lower() == LIST_NAME.lower():
                return i, entry.get("senderBlocklist", [])

        # Not found — add empty Anisakys entry
        logger.info("blocked_senders: creating Anisakys entry in policy")
        new_entry = {"description": LIST_NAME, "bypassApprovedSender": True, "senderBlocklist": []}
        blocked.append(new_entry)
        self._svc.policies().patch(
            name=policy_name,
            body={"setting": {"type": SETTING_TYPE, "value": {"blockedSenders": blocked}}},
        ).execute()
        logger.info("blocked_senders: Anisakys entry created")
        return len(blocked) - 1, []

    # ── Public API ────────────────────────────────────────────────────────────

    def add_entry(self, entry: str, entry_type: str) -> bool:
        """Add an email address or domain to the Anisakys blocked senders entry."""
        entry = entry.lower().strip()
        with self._lock:
            try:
                policy_name, blocked = self._get_policy()
                idx, sender_list = self._find_or_create_anisakys(policy_name, blocked)

                if entry in [s.lower() for s in sender_list]:
                    logger.info(f"blocked_senders: {entry} already in Anisakys")
                    return True

                blocked[idx]["senderBlocklist"] = sender_list + [entry]

                self._svc.policies().patch(
                    name=policy_name,
                    body={"setting": {"type": SETTING_TYPE, "value": {"blockedSenders": blocked}}},
                    updateMask="setting.value",
                ).execute()

                logger.info(f"blocked_senders: added {entry} ({entry_type}) to Anisakys")
                return True

            except Exception as exc:
                logger.error(f"blocked_senders add_entry({entry}): {exc}")
                return False

    def list_entries(self) -> list[dict]:
        """Return addresses in the Anisakys entry."""
        try:
            _, blocked = self._get_policy()
            for entry in blocked:
                if entry.get("description", "").lower() == LIST_NAME.lower():
                    return [{"address": s} for s in entry.get("senderBlocklist", [])]
            return []
        except Exception as exc:
            logger.error(f"blocked_senders list_entries: {exc}")
            return []


# ── Singleton ─────────────────────────────────────────────────────────────────

_client: Optional[BlockedSendersClient] = None


def get_blocked_senders_client(
    service_account_file: str,
    admin_email: str,
) -> BlockedSendersClient:
    """Return the process-wide client, creating it on first use.

    Args:
        service_account_file: Path to the service-account JSON key.
        admin_email: Workspace admin to impersonate.

    Returns:
        The shared :class:`BlockedSendersClient` (customer from settings).
    """
    global _client
    if _client is None:
        _client = BlockedSendersClient(service_account_file, admin_email)
    return _client
