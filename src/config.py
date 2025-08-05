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
    GRINDER0X_API_URL: Optional[str] = None
    GRINDER0X_API_KEY: Optional[str] = None

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
