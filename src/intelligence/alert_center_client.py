"""
Google Workspace Alert Center client.

Uses the existing service account with domain-wide delegation.

Prerequisite: the scope https://www.googleapis.com/auth/apps.alerts must be
granted to the service account Client ID in:
  Google Workspace Admin > Security > API Controls > Domain-wide delegation
"""

from typing import Optional

ALERT_CENTER_SCOPE = "https://www.googleapis.com/auth/apps.alerts"


class AlertCenterClient:
    def __init__(self, service_account_file: str, admin_email: str):
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        creds = service_account.Credentials.from_service_account_file(
            service_account_file,
            scopes=[ALERT_CENTER_SCOPE],
        ).with_subject(admin_email)

        self._service = build("alertcenter", "v1beta1", credentials=creds, cache_discovery=False)

    def list_alerts(self, filter_str: Optional[str] = None, page_size: int = 100) -> list[dict]:
        """Fetch all alerts, handling pagination."""
        alerts = []
        page_token = None

        while True:
            kwargs: dict = {"pageSize": page_size}
            if filter_str:
                kwargs["filter"] = filter_str
            if page_token:
                kwargs["pageToken"] = page_token

            resp = self._service.alerts().list(**kwargs).execute()
            alerts.extend(resp.get("alerts", []))
            page_token = resp.get("nextPageToken")
            if not page_token:
                break

        return alerts

    def get_alert(self, alert_id: str) -> dict:
        """Fetch a single alert by ID."""
        return self._service.alerts().get(alertId=alert_id).execute()

    def list_feedback(self, alert_id: str) -> list[dict]:
        """List feedback entries for an alert."""
        resp = self._service.alerts().feedback().list(alertId=alert_id).execute()
        return resp.get("feedback", [])


# ── Singleton ─────────────────────────────────────────────────────────────────

_client: Optional[AlertCenterClient] = None


def get_alert_center_client(
    service_account_file: str,
    admin_email: str,
) -> AlertCenterClient:
    global _client
    if _client is None:
        _client = AlertCenterClient(service_account_file, admin_email)
    return _client
