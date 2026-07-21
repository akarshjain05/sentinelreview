"""
Central configuration for SentinelReview.

All external integrations (GitHub App creds, LLM provider keys, DB URLs) are
read from environment variables so nothing secret ever lives in source.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # App
    app_name: str = "SentinelReview"
    environment: str = "development"
    log_level: str = "INFO"

    # Database
    database_url: str = "postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinelreview"

    # Redis / job queue
    redis_url: str = "redis://localhost:6379/0"

    # GitHub App
    github_app_id: str | None = None
    github_private_key: str | None = None
    github_webhook_secret: str | None = None
    
    # GitHub OAuth
    github_client_id: str | None = None
    github_client_secret: str | None = None
    session_secret_key: str = "change-me-in-production"

    # LLM providers
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None

    # Vulnerability data sources
    nvd_api_key: str | None = None

    # Sandbox limits
    sandbox_cpu_limit: str = "1"
    sandbox_mem_limit: str = "512m"
    sandbox_timeout_seconds: int = 30
    sandbox_network_disabled: bool = True

    # Agent limits (guardrails against runaway loops / cost)
    max_agent_retries: int = 2
    max_context_tokens: int = 8000
    max_files_per_review: int = 40


@lru_cache
def get_settings() -> Settings:
    return Settings()
