"""Gmail API client using service account with domain-wide delegation."""

import base64
import email as email_lib
import re
import threading
import time
from typing import Optional

from src.logger import logger

GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
ADMIN_DIRECTORY_SCOPE = "https://www.googleapis.com/auth/admin.directory.user.readonly"

# Module-level user list cache: thread-safe, 1-hour TTL
_user_list_cache: dict = {}  # domain -> {"users": [...], "fetched_at": float}
_user_list_lock = threading.Lock()
_USER_CACHE_TTL = 3600  # seconds


class GmailClient:
    def __init__(self, service_account_file: str, domain: str):
        """
        Initialize Gmail client with a service account file.
        The service account must have domain-wide delegation enabled in Google Workspace.

        Args:
            service_account_file: Path to the service account JSON key file.
            domain: Google Workspace domain (e.g. 'company.com').
        """
        from google.oauth2 import service_account

        self.domain = domain
        self._service_account_file = service_account_file
        self._credentials = service_account.Credentials.from_service_account_file(
            service_account_file,
            scopes=[GMAIL_READONLY_SCOPE],
        )

    def _get_service(self, user_email: str):
        """Return a Gmail API service client impersonating the given user."""
        from googleapiclient.discovery import build

        delegated = self._credentials.with_subject(user_email)
        return build("gmail", "v1", credentials=delegated, cache_discovery=False)

    def _get_admin_service(self, admin_email: str):
        """Return an Admin Directory API service impersonating the given super admin."""
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        admin_creds = service_account.Credentials.from_service_account_file(
            self._service_account_file,
            scopes=[ADMIN_DIRECTORY_SCOPE],
        ).with_subject(admin_email)
        return build("admin", "directory_v1", credentials=admin_creds, cache_discovery=False)

    def list_domain_users(self, domain: str, admin_email: str) -> list:
        """
        Return a list of active (non-suspended) user email addresses in the domain.

        Results are cached for 1 hour (thread-safe). On Directory API error, falls back
        to the stale cache if available so a transient failure doesn't stop all scans.

        Requires the service account to have admin.directory.user.readonly scope
        authorized in Google Admin Console domain-wide delegation.

        Args:
            domain: Google Workspace domain to enumerate.
            admin_email: Email of a super admin to impersonate for the Directory API call.

        Returns:
            List of lowercase primary email addresses of active users.
        """
        now = time.time()
        with _user_list_lock:
            cached = _user_list_cache.get(domain)
            if cached and (now - cached["fetched_at"]) < _USER_CACHE_TTL:
                logger.debug(
                    f"gmail_client: returning cached user list for {domain} "
                    f"({len(cached['users'])} users)"
                )
                return cached["users"]

        # Cache miss or stale — fetch from Directory API
        try:
            service = self._get_admin_service(admin_email)
            users = []
            page_token = None

            while True:
                response = (
                    service.users()
                    .list(
                        domain=domain,
                        maxResults=500,
                        orderBy="email",
                        pageToken=page_token,
                        query="isSuspended=false",
                    )
                    .execute()
                )
                for user in response.get("users", []):
                    email = user.get("primaryEmail", "")
                    if email:
                        users.append(email.lower())
                page_token = response.get("nextPageToken")
                if not page_token:
                    break

            with _user_list_lock:
                _user_list_cache[domain] = {"users": users, "fetched_at": time.time()}

            logger.info(f"gmail_client: enumerated {len(users)} active users in {domain}")
            return users

        except Exception as exc:
            logger.error(f"gmail_client list_domain_users({domain}): {exc}")
            # Return stale cache if available rather than leaving all scans empty
            with _user_list_lock:
                cached = _user_list_cache.get(domain)
                if cached:
                    logger.warning(
                        f"gmail_client: returning stale user cache for {domain} after API error"
                    )
                    return cached["users"]
            return []

    def list_new_messages(
        self,
        user_email: str,
        history_id: Optional[str] = None,
        after_timestamp: Optional[str] = None,
    ) -> tuple:
        """
        Return (message_ids, new_history_id) for messages new since last check.

        Uses history.list for incremental polling when history_id is available
        (efficient — only returns changes). Falls back to messages.list with a
        date filter on the first poll.

        Args:
            user_email: Mailbox to query.
            history_id: Last known history ID from previous poll.
            after_timestamp: Unix timestamp string for initial messages.list query.

        Returns:
            Tuple of (list of message IDs, updated history_id).
        """
        service = self._get_service(user_email)
        message_ids = []
        new_history_id = history_id

        try:
            if history_id:
                # Incremental: only new messages since last historyId
                response = (
                    service.users()
                    .history()
                    .list(
                        userId=user_email,
                        startHistoryId=history_id,
                        historyTypes=["messageAdded"],
                    )
                    .execute()
                )
                new_history_id = response.get("historyId", history_id)
                for record in response.get("history", []):
                    for added in record.get("messagesAdded", []):
                        msg_id = added["message"]["id"]
                        if msg_id not in message_ids:
                            message_ids.append(msg_id)
            else:
                # Initial poll: list messages with optional date filter
                query = "in:inbox"
                if after_timestamp:
                    query += f" after:{after_timestamp}"
                response = (
                    service.users()
                    .messages()
                    .list(userId=user_email, q=query, maxResults=500)
                    .execute()
                )
                for msg in response.get("messages", []):
                    message_ids.append(msg["id"])
                # Capture historyId from the profile for future incremental polls
                profile = service.users().getProfile(userId=user_email).execute()
                new_history_id = profile.get("historyId")

            logger.debug(f"gmail_client: {len(message_ids)} new messages for {user_email}")
        except Exception as exc:
            logger.error(f"gmail_client list_new_messages({user_email}): {exc}")

        return message_ids, new_history_id

    def get_message(self, user_email: str, message_id: str) -> Optional[dict]:
        """
        Fetch a full message and return a parsed dict:
        {
          "id": str,
          "from": str,
          "from_name": str,
          "from_email": str,
          "to": str,
          "subject": str,
          "date": str,
          "reply_to": str | None,
          "authentication_results": str | None,
          "body_text": str,
          "attachments": [{"filename": str, "mime_type": str, "size": int, "attachment_id": str}]
        }
        """
        try:
            service = self._get_service(user_email)
            msg = (
                service.users()
                .messages()
                .get(userId=user_email, id=message_id, format="full")
                .execute()
            )
            return self._parse_message(msg)
        except Exception as exc:
            logger.error(f"gmail_client get_message({user_email}, {message_id}): {exc}")
            return None

    def _parse_message(self, msg: dict) -> dict:
        """Parse Gmail API message object into a clean dict."""
        headers = {h["name"].lower(): h["value"] for h in msg.get("payload", {}).get("headers", [])}
        from_raw = headers.get("from", "")
        from_name, from_email = self._parse_address(from_raw)

        body_text = self._extract_body(msg.get("payload", {}))
        attachments = self._extract_attachments(msg.get("payload", {}))

        return {
            "id": msg["id"],
            "thread_id": msg.get("threadId"),
            "from": from_raw,
            "from_name": from_name,
            "from_email": from_email,
            "to": headers.get("to", ""),
            "subject": headers.get("subject", ""),
            "date": headers.get("date", ""),
            "reply_to": headers.get("reply-to"),
            "authentication_results": headers.get("authentication-results"),
            "received_spf": headers.get("received-spf"),
            "body_text": body_text,
            "attachments": attachments,
        }

    def get_attachment_data(
        self, user_email: str, message_id: str, attachment_id: str
    ) -> Optional[bytes]:
        """Download raw bytes of an attachment (for hash calculation)."""
        try:
            service = self._get_service(user_email)
            resp = (
                service.users()
                .messages()
                .attachments()
                .get(userId=user_email, messageId=message_id, id=attachment_id)
                .execute()
            )
            data = resp.get("data", "")
            return base64.urlsafe_b64decode(data + "==")
        except Exception as exc:
            logger.error(f"gmail_client get_attachment_data({user_email}, {message_id}): {exc}")
            return None

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_address(raw: str) -> tuple:
        """Extract (display_name, email) from a raw From/Reply-To header value."""
        match = re.match(r'^"?([^"<]*?)"?\s*<([^>]+)>', raw.strip())
        if match:
            return match.group(1).strip(), match.group(2).strip().lower()
        raw = raw.strip()
        if "@" in raw:
            return "", raw.lower()
        return raw, ""

    def _extract_body(self, payload: dict) -> str:
        """Recursively extract text/plain body from a MIME payload."""
        mime_type = payload.get("mimeType", "")
        if mime_type == "text/plain":
            data = payload.get("body", {}).get("data", "")
            if data:
                return base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
        if mime_type.startswith("multipart/"):
            for part in payload.get("parts", []):
                text = self._extract_body(part)
                if text:
                    return text
        return ""

    def _extract_attachments(self, payload: dict) -> list:
        """Recursively collect attachment metadata from MIME parts."""
        attachments = []
        mime_type = payload.get("mimeType", "")
        filename = payload.get("filename", "")
        body = payload.get("body", {})

        if filename and body.get("attachmentId"):
            attachments.append(
                {
                    "filename": filename,
                    "mime_type": mime_type,
                    "size": body.get("size", 0),
                    "attachment_id": body["attachmentId"],
                }
            )

        for part in payload.get("parts", []):
            attachments.extend(self._extract_attachments(part))

        return attachments
