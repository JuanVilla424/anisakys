from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    TIMEOUT: int = 50
    SCAN_INTERVAL: int = 300
    KEYWORDS: str = Field()
    DOMAINS: str = Field()

    model_config = {"env_file": ".env"}


settings = Settings()
