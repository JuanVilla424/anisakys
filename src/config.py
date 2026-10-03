import sys
import tempfile
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr
from typing import Literal, Optional

from src.dns import cloudflare_ranges


def _default_screenshots_dir() -> str:
    """Portable fallback storage location, used only when SCREENSHOTS_DIR is
    not set via env/.env -- matches the one already used by ScreenshotService
    itself, so every call site agrees on where screenshots live instead of
    each guessing its own (previously divergent) hardcoded default."""
    return str(Path(tempfile.gettempdir()) / "anisakys_screenshots")


if "pytest" in sys.modules:
    test_env = Path(".env.test")
    if not test_env.exists():
        raise Exception("When running tests, the .env.test file must exist.")
    env_file = ".env.test"
else:
    env_file = ".env"


class Settings(BaseSettings):
    TIMEOUT: int = 50
    SCAN_INTERVAL: int = 40200
    KEYWORDS: str = Field(..., description="Comma-separated list of keywords")
    DOMAINS: str = Field(..., description="Comma-separated list of domains")
    ALLOWED_SITES: Optional[str] = None
    REPORT_INTERVAL: int = 14400
    SMTP_HOST: str = Field(..., description="SMTP host address")
    SMTP_PORT: int = Field(..., description="SMTP port")
    ABUSE_EMAIL_SENDER: str = Field(..., description="Sender email for abuse reports")
    ABUSE_EMAIL_SUBJECT: str = Field(..., description="Subject line for abuse reports")
    DEFAULT_CC_EMAILS: Optional[str] = None
    DEFAULT_CC_EMAILS_ESCALATION_LEVEL2: Optional[str] = None
    DEFAULT_CC_EMAILS_ESCALATION_LEVEL3: Optional[str] = None
    ATTACHMENTS_FOLDER: Optional[str] = None
    DATABASE_URL: Optional[str] = None
    QUERIES_FILE: Optional[str] = None
    OFFSET_FILE: Optional[str] = None
    AUTO_MULTI_API_SCAN: Optional[bool] = False
    AUTO_REPORT_THRESHOLD_CONFIDENCE: int = Field(default=85, ge=0, le=100)
    AUTO_REPORT_THREAT_LEVELS: Optional[str] = None
    MANUAL_REVIEW_THRESHOLD_CONFIDENCE: int = Field(default=70, ge=0, le=100)
    AUTO_ANALYSIS_DELAY_SECONDS: int = Field(default=30, ge=0)
    VIRUSTOTAL_API_KEY: Optional[str] = None
    URLVOID_API_KEY: Optional[str] = None
    PHISHTANK_API_KEY: Optional[str] = None
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    GRINDER0X_API_URL: Optional[str] = None
    GRINDER0X_API_KEY: Optional[str] = None
    MAX_ATTACHMENT_SIZE_MB: Optional[int] = None
    MAX_EMAIL_SIZE_MB: Optional[int] = None
    SCREENSHOTS_DIR: str = Field(default_factory=_default_screenshots_dir)
    SMTP_USER: Optional[str] = None
    SMTP_PASS: Optional[str] = None
    SMTP_RATE_LIMIT_PER_HOUR: int = 100
    DEFAULT_ATTACHMENT: Optional[str] = None
    LOG_LEVEL: Optional[str] = None
    ANISAKYS_API_KEY: Optional[str] = None
    ANISAKYS_API_PORT: Optional[int] = 8091
    RATELIMIT_STORAGE_URL: Optional[str] = None
    CT_MONITOR_ENABLED: Optional[bool] = False
    CT_MONITOR_MIN_SCORE: Optional[int] = None
    CT_STREAM_URL: Optional[str] = None
    FEED_INTEL_ENABLED: Optional[bool] = False
    URLHAUS_API_KEY: Optional[str] = None
    URLSCAN_API_KEY: Optional[str] = None
    TAXII_BASE_URL: Optional[str] = None
    TAXII_USERNAME: Optional[str] = None
    TAXII_PASSWORD: Optional[str] = None
    TAXII_DEFAULT_API_ROOT: Optional[str] = None
    TAXII_DEFAULT_COLLECTION_ID: Optional[str] = None
    MISP_URL: Optional[str] = None
    MISP_API_KEY: Optional[str] = None
    SCREENSHOT_WORKER_SOCKET: Optional[str] = None
    TEST_EMAIL: Optional[str] = None
    SERPAPI_KEY: Optional[str] = None
    S3_DATA_BUCKET: Optional[str] = None
    AWS_REGION: Optional[str] = None
    GOOGLE_SERVICE_ACCOUNT_FILE: Optional[str] = None
    GOOGLE_WORKSPACE_DOMAIN: Optional[str] = None
    GOOGLE_ADMIN_EMAIL: Optional[str] = None
    EMAIL_ABUSE_MAILBOX: Optional[str] = None
    EMAIL_MONITORED_MAILBOXES: Optional[str] = None
    EMAIL_BLOCK_THRESHOLD: Optional[int] = 5
    EMAIL_POLL_INTERVAL_MINUTES: Optional[int] = 15

    # --- v2 phase 0: API, auth & HTTP serving ---------------------------------
    # Interface the Flask development server (--start-api) binds to. Loopback by
    # default; containers serving through gunicorn bind explicitly instead.
    API_BIND_HOST: str = "127.0.0.1"
    # Number of reverse proxies (nginx, load balancer) in front of the API whose
    # X-Forwarded-For/-Proto headers are trusted. 0 disables ProxyFix.
    TRUSTED_PROXY_HOPS: int = Field(default=0, ge=0, le=10)
    # Static bearer token for Prometheus scrapers on /metrics (an API key with the
    # "metrics" or "read" scope also works). Unset = API keys only.
    METRICS_TOKEN: Optional[SecretStr] = None
    # Mailboxes the API may create e-mail monitor threads for (comma-separated;
    # "@domain" allows a whole domain, incl. domain-wide monitoring).
    # EMAIL_MONITORED_MAILBOXES and EMAIL_ABUSE_MAILBOX are allowed implicitly.
    EMAIL_MONITOR_ALLOWED_MAILBOXES: Optional[str] = None

    # --- v2 phase 0: reporting pipeline & process roles ------------------------
    # Which long-running jobs this process owns. Exactly one process per
    # deployment should run "scheduler" (or "all" for single-process dev).
    PROCESS_ROLE: Literal["all", "api", "scanner", "scheduler"] = "all"
    # Guard the scheduler jobs with a PostgreSQL advisory lock so a second
    # misconfigured scheduler waits as a hot standby instead of running jobs.
    SCHEDULER_LEADER_LOCK: bool = True
    REPORT_CLAIM_BATCH_SIZE: int = Field(default=5, ge=1, le=100)
    REPORT_CLAIM_LEASE_SECONDS: int = Field(default=1800, ge=60)
    REPORT_SITE_MAX_ATTEMPTS: int = Field(default=3, ge=1, le=20)
    REPORT_RESEND_COOLDOWN_HOURS: int = Field(default=48, ge=0)
    REPORT_MAX_PRIMARY_RECIPIENTS: int = Field(default=5, ge=1, le=20)
    REPORT_DB_STATEMENT_TIMEOUT_MS: int = Field(default=5000, ge=100)
    REPORT_DB_LOCK_TIMEOUT_MS: int = Field(default=2000, ge=100)
    # Brand impersonated by the reported sites, rendered in the report when set.
    REPORT_BRAND_NAME: Optional[str] = None
    # Reporting organisation shown in the signature of every report.
    REPORT_ORGANIZATION: str = "Anisakys phishing takedown"
    # Default "how to reproduce" guidance (e.g. geo-fencing or mobile-only kits).
    REPORT_REPRODUCTION_NOTE: Optional[str] = None
    OUTBOX_MAX_ATTEMPTS: int = Field(default=3, ge=1, le=10)
    OUTBOX_RETRY_BACKOFF_SECONDS: int = Field(default=900, ge=1)
    OUTBOX_RATE_LIMIT_DEFER_SECONDS: int = Field(default=300, ge=1)
    OUTBOX_DISPATCH_INTERVAL_SECONDS: int = Field(default=60, ge=5)
    OUTBOX_DISPATCH_BATCH_SIZE: int = Field(default=20, ge=1, le=500)
    # Transport security for SMTP: "auto" = implicit TLS on 465, otherwise
    # STARTTLS when offered; credentials are never sent without TLS unless
    # "none" is set explicitly (loopback relays only).
    SMTP_SECURITY: Literal["auto", "starttls", "ssl", "none"] = "auto"
    SMTP_TIMEOUT_SECONDS: int = Field(default=30, ge=1, le=600)
    GSB_SCREENSHOT_MAX_BYTES: int = Field(default=4_000_000, ge=0)
    FOLLOWUP_INTERVAL_HOURS: int = Field(default=48, ge=1)
    FOLLOWUP_MAX_COUNT: int = Field(default=3, ge=0, le=10)
    FOLLOWUP_CHECK_INTERVAL_SECONDS: int = Field(default=3600, ge=60)

    # --- v2 phase 0: detection & threat-intel providers ------------------------
    GOOGLE_WEB_RISK_API_KEY: Optional[str] = None
    # Web Risk Submission API (projects/{project}/uris:submit). It needs OAuth
    # credentials for an allowlisted project; an API key alone cannot submit.
    # Disabled unless GOOGLE_CLOUD_PROJECT is set. Credentials come from the
    # service-account JSON at GOOGLE_APPLICATION_CREDENTIALS, or from
    # Application Default Credentials when that is unset.
    GOOGLE_CLOUD_PROJECT: Optional[str] = None
    GOOGLE_APPLICATION_CREDENTIALS: Optional[str] = None
    # Best-effort submission through the undocumented Safe Browsing crx-report
    # endpoint; delivery cannot be verified (reported as crx_report_unverified).
    GSB_CRX_REPORT_ENABLED: bool = True

    # --- v2 phase 0: platform, logging & operations ----------------------------
    # Logging (src/observability/structured_logger.py); LOG_LEVEL above sets the
    # level. Each process writes its own <LOG_DIR>/anisakys-<role>-<pid>.log; an
    # empty LOG_DIR disables the file (console only, e.g. in containers).
    LOG_DIR: Optional[str] = None
    LOG_PROCESS_NAME: Optional[str] = None
    LOG_MAX_BYTES: int = Field(default=20 * 1024 * 1024, gt=0)
    LOG_BACKUP_COUNT: int = Field(default=5, ge=0)
    LOG_CONSOLE_FORMAT: str = Field(default="text", pattern="^(text|json)$")
    # Database connection pooling (src/database/manager.py: create_db_engine).
    # 0 = no pooling (default). >0 = bounded QueuePool with pre-ping, intended
    # for the API under gunicorn; keep 0 for the threads/scanner roles.
    DB_POOL_SIZE: int = Field(default=0, ge=0)
    DB_MAX_OVERFLOW: int = Field(default=5, ge=0)
    DB_POOL_TIMEOUT_SECONDS: int = Field(default=30, gt=0)
    DB_POOL_RECYCLE_SECONDS: int = Field(default=1800, ge=-1)

    model_config = {
        "env_file": env_file,
        "extra": "ignore",
        "case_sensitive": False,
    }


settings = Settings()

# Fallback bind path for the sandboxed screenshot worker's own unix socket,
# used only when starting it without an explicit SCREENSHOT_WORKER_SOCKET
# override -- portable (tempdir-based) rather than assuming a specific
# deployment layout like /run/anisakys exists and is writable.
DEFAULT_SCREENSHOT_WORKER_SOCKET = str(
    Path(tempfile.gettempdir()) / "anisakys" / "screenshot-worker.sock"
)

# Re-exported for existing importers (src.main, src.detection.scanner)
CLOUDFLARE_IP_RANGES = cloudflare_ranges.CLOUDFLARE_IP_RANGES

# Shared HTTP scanning constants (used by src.main and src.detection.scanner)
ALLOWED_HEAD_STATUS = {200, 201, 202, 203, 204, 205, 206, 301, 302, 403, 405, 503, 504}

# Realistic browser user agents - Chrome is primary, Firefox as fallback
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

FIREFOX_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) " "Gecko/20100101 Firefox/122.0"
)

# Standard browser headers to appear as legitimate traffic
BROWSER_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}
DNS_ERROR_KEY_PHRASES = {
    "Name or service not known",
    "getaddrinfo failed",
    "Failed to resolve",
    "Max retries exceeded",
}
