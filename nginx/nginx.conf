"""app/core/config.py — typed settings loaded from environment / .env"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # API
    debug: bool = False
    log_level: str = "info"
    secret_key: str = "dev-secret-key"
    web_concurrency: int = 2

    # Database
    database_url: str = "postgresql+asyncpg://piisafe:piisafe@localhost:5432/piisafe_audit"

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    redis_token_ttl: int = 3600

    # PII
    pii_entity_types: str = "NAME,EMAIL,PHONE,SSN,CREDIT_CARD,IP_ADDR"
    pii_default_strategy: str = "pseudonymise"
    enable_output_guardrails: bool = True
    enable_honey_tokens: bool = True

    @property
    def entity_types(self) -> list[str]:
        return [e.strip() for e in self.pii_entity_types.split(",")]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
