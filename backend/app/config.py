from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_DIR = Path(__file__).resolve().parent.parent
_ENV_FILE = _BACKEND_DIR / ".env"


class Settings(BaseSettings):
    database_url: str | None = Field(default=None, validation_alias="DATABASE_URL")
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
    # Step 7 is deliberately disabled unless an operator opts in. The
    # provider key is never included in structured investigation context.
    ai_agent_enabled: bool = Field(default=False, validation_alias="AI_AGENT_ENABLED")
    ai_provider: str = Field(default="groq", validation_alias="AI_PROVIDER")
    ai_model: str = Field(default="llama-3.3-70b-versatile", validation_alias="AI_MODEL")
    groq_api_key: str | None = Field(default=None, validation_alias="GROQ_API_KEY")
    ai_api_key: str | None = Field(default=None, validation_alias="AI_API_KEY")
    ai_agent_max_iterations: int = Field(
        default=4,
        validation_alias=AliasChoices("MAX_AGENT_ITERATIONS", "AI_AGENT_MAX_ITERATIONS"),
        ge=1,
        le=20,
    )
    ai_agent_timeout_seconds: float = Field(
        default=60.0, validation_alias="AI_AGENT_TIMEOUT_SECONDS", gt=0, le=300
    )

    @property
    def effective_ai_api_key(self) -> str | None:
        return self.groq_api_key or self.ai_api_key

    model_config = SettingsConfigDict(
        env_file=(_ENV_FILE, ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


def validate_ai_configuration(settings: Settings | None = None) -> tuple[bool, str]:
    """Safe validation of AI configuration without exposing secrets."""
    settings = settings or get_settings()
    if not settings.ai_agent_enabled:
        return False, "AI Analyst is disabled (AI_AGENT_ENABLED=false)."
    key = settings.effective_ai_api_key
    if not key or not key.strip():
        return False, f"AI configuration error: Missing required API key for provider '{settings.ai_provider}' (GROQ_API_KEY / AI_API_KEY is unset)."
    return True, "AI configuration valid."

