from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    TIMEOUT: int = 50
    SCAN_INTERVAL: int = 40200
    KEYWORDS: str = Field()
    DOMAINS: str = Field()
    ALLOWED_SITES: str = Field()
    REPORT_INTERVAL: int = 14400
    SMTP_HOST: str = Field()
    SMTP_PORT: int = Field()
    ABUSE_EMAIL_SENDER: str = Field()
    ABUSE_EMAIL_SUBJECT: str = Field()

    model_config = {"env_file": ".env"}


settings = Settings()
