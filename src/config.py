from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


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

    model_config = {
        "env_file": ".env",
        "extra": "ignore",
        "case_sensitive": False,
    }


settings = Settings()
