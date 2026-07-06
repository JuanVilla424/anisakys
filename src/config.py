import sys
import ipaddress
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional

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
    AUTO_REPORT_THRESHOLD_CONFIDENCE: Optional[int] = None
    AUTO_REPORT_THREAT_LEVELS: Optional[str] = None
    MANUAL_REVIEW_THRESHOLD_CONFIDENCE: Optional[int] = None
    AUTO_ANALYSIS_DELAY_SECONDS: Optional[int] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    URLVOID_API_KEY: Optional[str] = None
    PHISHTANK_API_KEY: Optional[str] = None
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    GRINDER0X_API_URL: Optional[str] = None
    GRINDER0X_API_KEY: Optional[str] = None
    MAX_ATTACHMENT_SIZE_MB: Optional[int] = None
    MAX_EMAIL_SIZE_MB: Optional[int] = None
    SCREENSHOTS_DIR: Optional[str] = None
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

    model_config = {
        "env_file": env_file,
        "extra": "ignore",
        "case_sensitive": False,
    }


settings = Settings()

CLOUDFLARE_IP_RANGES = [
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("104.16.0.0/12"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("131.0.72.0/22"),
]

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
