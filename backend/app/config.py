from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    abuseipdb_api_key: str | None = Field(default=None, validation_alias="ABUSEIPDB_API_KEY")
    virustotal_api_key: str | None = Field(default=None, validation_alias="VIRUSTOTAL_API_KEY")
    ip_geolocation_api_key: str | None = Field(
        default=None, validation_alias="IP_GEOLOCATION_API_KEY"
    )
    threat_intelligence_dns_enabled: bool = Field(
        default=True, validation_alias="THREAT_INTELLIGENCE_DNS_ENABLED"
    )
    threat_intelligence_rdap_enabled: bool = Field(
        default=True, validation_alias="THREAT_INTELLIGENCE_RDAP_ENABLED"
    )
    threat_intelligence_timeout_seconds: float = Field(
        default=2.0, validation_alias="THREAT_INTELLIGENCE_TIMEOUT_SECONDS", gt=0, le=30
    )
    max_email_size_mb: float = Field(
        default=10.0, validation_alias="MAX_EMAIL_SIZE_MB", gt=0, le=1024
    )
    # Step 7 is deliberately disabled unless an operator opts in.  The
    # provider key is never included in structured investigation context.
    ai_agent_enabled: bool = Field(default=False, validation_alias="AI_AGENT_ENABLED")
    ai_provider: str = Field(default="openai", validation_alias="AI_PROVIDER")
    ai_model: str = Field(default="gpt-4o-mini", validation_alias="AI_MODEL")
    ai_api_key: str | None = Field(default=None, validation_alias="AI_API_KEY")
    ai_agent_max_iterations: int = Field(
        default=5, validation_alias="AI_AGENT_MAX_ITERATIONS", ge=1, le=20
    )
    ai_agent_timeout_seconds: float = Field(
        default=30.0, validation_alias="AI_AGENT_TIMEOUT_SECONDS", gt=0, le=300
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
