"""
Google Safe Browsing URL Reporter

Submits detected phishing URLs to Google for inclusion in Safe Browsing.

Two channels, tried in this order:

1. **Web Risk Submission API** (documented): ``POST
   https://webrisk.googleapis.com/v1/projects/{project}/uris:submit`` with an
   OAuth access token (scope ``cloud-platform``) for a project that Google has
   allowlisted for submissions. It returns a long-running ``Operation``; a
   submission counts as accepted only when that operation is parsed. Enabled
   only when ``GOOGLE_CLOUD_PROJECT`` is configured; credentials come from
   ``GOOGLE_APPLICATION_CREDENTIALS`` (service-account JSON) or Application
   Default Credentials. An API key (``GOOGLE_WEB_RISK_API_KEY``) cannot be
   used for submissions.
2. **crx-report** (undocumented, best effort): the endpoint used by Google's
   own browser extension. Its responses carry no submission identifier, so a
   2xx only means the request was accepted for transport; results are marked
   ``method="crx_report_unverified"`` and ``verified=False``. Can be disabled
   with ``GSB_CRX_REPORT_ENABLED=false``.
"""

import json
import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import requests

from src.config import settings
from src.observability.structured_logger import log_with_context
from src.utils.redaction import redact_secrets

logger = logging.getLogger(__name__)

# Configuration
GSB_CRX_REPORT_URL = "https://safebrowsing.google.com/safebrowsing/clientreport/crx-report"
WEB_RISK_SUBMIT_URL_TEMPLATE = "https://webrisk.googleapis.com/v1/projects/{project}/uris:submit"
WEB_RISK_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
REQUEST_TIMEOUT_SECONDS = 30

# Kept for backward compatibility with importers of the old module constant.
WEB_RISK_API_KEY = getattr(settings, "GOOGLE_WEB_RISK_API_KEY", None)

METHOD_WEB_RISK = "web_risk_api"
METHOD_CRX_UNVERIFIED = "crx_report_unverified"

# Threat type flags for crx-report
CRX_THREAT_FLAGS = {
    "phishing": "SOCIAL_ENGINEERING",
    "malware": "MALWARE",
    "unwanted_software": "UNWANTED_SOFTWARE",
}

# Web Risk ThreatInfo.abuseType values
WEB_RISK_ABUSE_TYPES = {
    "phishing": "SOCIAL_ENGINEERING",
    "malware": "MALWARE",
    "unwanted_software": "UNWANTED_SOFTWARE",
}

_api_key_warning_logged = False


def _warn_api_key_unusable_once() -> None:
    """Log once that a Web Risk API key alone cannot submit URLs."""
    global _api_key_warning_logged
    if _api_key_warning_logged:
        return
    _api_key_warning_logged = True
    logger.warning(
        "GOOGLE_WEB_RISK_API_KEY is set but the Web Risk Submission API requires OAuth "
        "credentials for an allowlisted project; set GOOGLE_CLOUD_PROJECT (and "
        "GOOGLE_APPLICATION_CREDENTIALS) to enable it. The key is not used for submissions."
    )


class GSBReporter:
    """
    Reports phishing URLs to Google Safe Browsing.

    Features:
    - Documented Web Risk Submission API when configured, with operation parsing
    - Best-effort crx-report channel, explicitly marked as unverified
    - Optional screenshot attachment (crx-report only)
    - Submission statistics
    """

    def __init__(
        self,
        web_risk_api_key: Optional[str] = None,
        project: Optional[str] = None,
        credentials: Optional[Any] = None,
        credentials_file: Optional[str] = None,
        crx_enabled: Optional[bool] = None,
        session_factory: Optional[Callable[[Any], requests.Session]] = None,
    ):
        """
        Initialize GSB Reporter.

        Args:
            web_risk_api_key: Legacy Web Risk API key. Not usable for submissions;
                only triggers a configuration warning when OAuth is missing.
            project: Google Cloud project ID/number allowlisted for the
                Submission API. Defaults to ``GOOGLE_CLOUD_PROJECT``.
            credentials: Ready ``google.auth`` credentials (mainly for tests).
            credentials_file: Service-account JSON path. Defaults to
                ``GOOGLE_APPLICATION_CREDENTIALS``; ADC is used when unset.
            crx_enabled: Enable the crx-report channel. Defaults to
                ``GSB_CRX_REPORT_ENABLED``.
            session_factory: Builds an authorized HTTP session from credentials.
                Defaults to ``google.auth.transport.requests.AuthorizedSession``.
        """
        self.web_risk_api_key = web_risk_api_key or getattr(
            settings, "GOOGLE_WEB_RISK_API_KEY", None
        )
        self.project = project or getattr(settings, "GOOGLE_CLOUD_PROJECT", None)
        self.credentials_file = credentials_file or getattr(
            settings, "GOOGLE_APPLICATION_CREDENTIALS", None
        )
        self.crx_enabled = (
            crx_enabled
            if crx_enabled is not None
            else bool(getattr(settings, "GSB_CRX_REPORT_ENABLED", True))
        )
        self._credentials = credentials
        self._session_factory = session_factory
        self._web_risk_session: Optional[requests.Session] = None
        self.web_risk_enabled = bool(self.project)

        if self.web_risk_api_key and not self.web_risk_enabled:
            _warn_api_key_unusable_once()

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
                "Content-Type": "application/json",
            }
        )

        # Statistics
        self.stats = {
            "total_submissions": 0,
            "crx_successes": 0,
            "web_risk_successes": 0,
            "failures": 0,
            "last_submission": None,
        }

    def report_url(
        self,
        url: str,
        threat_type: str = "phishing",
        screenshot_base64: Optional[str] = None,
        dom_content: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Report a URL to Google Safe Browsing.

        Tries the Web Risk Submission API first when configured (its answer is
        verifiable), then the best-effort crx-report channel.

        Args:
            url: The phishing URL to report.
            threat_type: Type of threat (phishing, malware, unwanted_software).
            screenshot_base64: Optional base64-encoded screenshot (crx-report).
            dom_content: Optional HTML DOM content (crx-report).
            correlation_id: Optional correlation ID for logging.

        Returns:
            Dict with ``success``, ``method`` (``"web_risk_api"``,
            ``"crx_report_unverified"`` or ``None``), ``verified`` (``True``
            only for a parsed Web Risk operation), ``operation`` (Web Risk
            operation name), ``message``, ``timestamp`` and ``url``.
        """
        result: Dict[str, Any] = {
            "success": False,
            "method": None,
            "verified": False,
            "operation": None,
            "message": "",
            "timestamp": datetime.now().isoformat(),
            "url": url,
        }

        self.stats["total_submissions"] += 1
        failures: List[str] = []

        if self.web_risk_enabled:
            web_risk_result = self._submit_web_risk(url, threat_type)
            if web_risk_result["success"]:
                result.update(
                    {
                        "success": True,
                        "method": METHOD_WEB_RISK,
                        "verified": True,
                        "operation": web_risk_result.get("operation"),
                        "message": "URL submitted via Web Risk Submission API "
                        f"(operation {web_risk_result.get('operation')})",
                    }
                )
                self.stats["web_risk_successes"] += 1
                self.stats["last_submission"] = datetime.now().isoformat()
                log_with_context(
                    logger,
                    logging.INFO,
                    f"GSB submission accepted by Web Risk: {url}",
                    url=url,
                    method=METHOD_WEB_RISK,
                    operation=web_risk_result.get("operation"),
                    threat_type=threat_type,
                    correlation_id=correlation_id,
                    event_type="gsb_submission_success",
                )
                return result
            failures.append(f"web_risk: {web_risk_result['error']}")
        else:
            failures.append("web_risk: not configured (GOOGLE_CLOUD_PROJECT unset)")

        if self.crx_enabled:
            crx_result = self._submit_crx_report(url, threat_type, screenshot_base64, dom_content)
            if crx_result["success"]:
                result.update(
                    {
                        "success": True,
                        "method": METHOD_CRX_UNVERIFIED,
                        "verified": False,
                        "message": "URL sent to the undocumented crx-report endpoint; "
                        "best effort, delivery not verifiable",
                    }
                )
                self.stats["crx_successes"] += 1
                self.stats["last_submission"] = datetime.now().isoformat()
                log_with_context(
                    logger,
                    logging.INFO,
                    f"GSB best-effort submission sent (unverified): {url}",
                    url=url,
                    method=METHOD_CRX_UNVERIFIED,
                    threat_type=threat_type,
                    correlation_id=correlation_id,
                    event_type="gsb_submission_unverified",
                )
                return result
            failures.append(f"crx: {crx_result['error']}")
        else:
            failures.append("crx: disabled (GSB_CRX_REPORT_ENABLED=false)")

        result["message"] = "All submission channels failed. " + "; ".join(failures)
        self.stats["failures"] += 1

        log_with_context(
            logger,
            logging.WARNING,
            f"GSB submission failed: {url}",
            url=url,
            error=result["message"],
            correlation_id=correlation_id,
            event_type="gsb_submission_failed",
        )

        return result

    def _submit_crx_report(
        self,
        url: str,
        threat_type: str,
        screenshot_base64: Optional[str] = None,
        dom_content: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send a URL to the undocumented crx-report endpoint (best effort).

        Request format: JSON array
        ``[url, null, screenshot_base64, dom_content, null, [flags]]``.

        Args:
            url: URL to report.
            threat_type: Internal threat type key (see ``CRX_THREAT_FLAGS``).
            screenshot_base64: Optional screenshot.
            dom_content: Optional DOM snapshot.

        Returns:
            ``{"success": True}`` on any 2xx (transport-level acceptance only),
            otherwise ``{"success": False, "error": str}``.
        """
        flags = [CRX_THREAT_FLAGS.get(threat_type, "SOCIAL_ENGINEERING")]
        payload = [
            url,  # URL to report
            None,  # Unused field
            screenshot_base64 or "",  # Screenshot (base64)
            dom_content or "",  # DOM content
            None,  # Referrer chain
            flags,  # Threat flags
        ]

        try:
            response = self.session.post(
                GSB_CRX_REPORT_URL,
                data=json.dumps(payload),
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except requests.RequestException as e:
            return {"success": False, "error": redact_secrets(e)}

        if 200 <= response.status_code < 300:
            return {"success": True}
        return {
            "success": False,
            "error": f"HTTP {response.status_code}: {redact_secrets(response.text[:200])}",
        }

    def _get_web_risk_session(self) -> requests.Session:
        """Build (once) an OAuth-authorized session for the Web Risk API.

        Returns:
            A session that attaches and refreshes the access token.

        Raises:
            google.auth.exceptions.GoogleAuthError: If no credentials are found.
            OSError: If the service-account file cannot be read.
            ValueError: If the service-account file is malformed.
        """
        if self._web_risk_session is not None:
            return self._web_risk_session

        credentials = self._credentials
        if credentials is None:
            if self.credentials_file:
                from google.oauth2 import service_account

                credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_file, scopes=WEB_RISK_SCOPES
                )
            else:
                import google.auth

                credentials, _ = google.auth.default(scopes=WEB_RISK_SCOPES)

        factory = self._session_factory
        if factory is None:
            from google.auth.transport.requests import AuthorizedSession

            factory = AuthorizedSession
        self._web_risk_session = factory(credentials)
        return self._web_risk_session

    def _submit_web_risk(self, url: str, threat_type: str) -> Dict[str, Any]:
        """
        Submit a URL via the Web Risk Submission API (``projects.uris.submit``).

        Args:
            url: URL to submit.
            threat_type: Internal threat type key (see ``WEB_RISK_ABUSE_TYPES``).

        Returns:
            ``{"success": True, "operation": name, "done": bool, "state": str}``
            when the response is a parseable ``Operation`` for this project,
            otherwise ``{"success": False, "error": str}``.
        """
        if not self.web_risk_enabled:
            return {"success": False, "error": "Web Risk submission not configured"}

        from google.auth import exceptions as google_auth_exceptions

        try:
            session = self._get_web_risk_session()
        except (google_auth_exceptions.GoogleAuthError, OSError, ValueError) as e:
            logger.error(f"Web Risk credentials unavailable: {redact_secrets(e)}")
            return {"success": False, "error": f"Credentials unavailable: {redact_secrets(e)}"}

        payload = {
            "submission": {"uri": url},
            "threatInfo": {
                "abuseType": WEB_RISK_ABUSE_TYPES.get(threat_type, "SOCIAL_ENGINEERING"),
                "threatJustification": {"labels": ["AUTOMATED_REPORT"]},
            },
        }
        endpoint = WEB_RISK_SUBMIT_URL_TEMPLATE.format(project=self.project)

        try:
            response = session.post(endpoint, json=payload, timeout=REQUEST_TIMEOUT_SECONDS)
        except (requests.RequestException, google_auth_exceptions.GoogleAuthError) as e:
            return {"success": False, "error": redact_secrets(e)}

        if response.status_code != 200:
            hint = ""
            if response.status_code == 403:
                hint = " (project not allowlisted for submissions or missing permission)"
            return {
                "success": False,
                "error": f"HTTP {response.status_code}{hint}: "
                f"{redact_secrets(response.text[:200])}",
            }

        try:
            operation = response.json()
        except ValueError:
            return {"success": False, "error": "Unparseable Web Risk response"}

        name = operation.get("name") if isinstance(operation, dict) else None
        if not (
            isinstance(name, str)
            and name.startswith("projects/")
            and "/operations/" in name
            and not operation.get("error")
        ):
            return {"success": False, "error": "Response is not a valid submit operation"}

        metadata = operation.get("metadata") or {}
        return {
            "success": True,
            "operation": name,
            "done": bool(operation.get("done", False)),
            "state": metadata.get("state") if isinstance(metadata, dict) else None,
        }

    def report_batch(
        self,
        urls: List[str],
        threat_type: str = "phishing",
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Report multiple URLs to Google Safe Browsing.

        Args:
            urls: List of URLs to report.
            threat_type: Type of threat.
            correlation_id: Optional correlation ID for logging.

        Returns:
            Dict with batch results.
        """
        results: Dict[str, Any] = {
            "total": len(urls),
            "successful": 0,
            "failed": 0,
            "details": [],
        }

        for url in urls:
            result = self.report_url(
                url=url,
                threat_type=threat_type,
                correlation_id=correlation_id,
            )
            results["details"].append(result)

            if result["success"]:
                results["successful"] += 1
            else:
                results["failed"] += 1

        log_with_context(
            logger,
            logging.INFO,
            f"GSB batch submission completed: {results['successful']}/{results['total']} successful",
            total=results["total"],
            successful=results["successful"],
            failed=results["failed"],
            correlation_id=correlation_id,
            event_type="gsb_batch_submission",
        )

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get submission statistics.

        Returns:
            Counters plus whether each channel is configured.
        """
        return {
            **self.stats,
            "web_risk_configured": self.web_risk_enabled,
            "crx_enabled": self.crx_enabled,
        }


# Singleton instance
_gsb_reporter: Optional[GSBReporter] = None


def get_gsb_reporter() -> GSBReporter:
    """Get or create the GSB reporter instance."""
    global _gsb_reporter
    if _gsb_reporter is None:
        _gsb_reporter = GSBReporter()
    return _gsb_reporter


def report_phishing_url(
    url: str,
    screenshot_base64: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convenience function to report a phishing URL to GSB.

    Args:
        url: The phishing URL to report.
        screenshot_base64: Optional screenshot.
        correlation_id: Optional correlation ID.

    Returns:
        Submission result dict (see :meth:`GSBReporter.report_url`).
    """
    reporter = get_gsb_reporter()
    return reporter.report_url(
        url=url,
        threat_type="phishing",
        screenshot_base64=screenshot_base64,
        correlation_id=correlation_id,
    )
