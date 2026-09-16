from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Zero Trust LLM SecOps"
    app_version: str = "0.9.0"
    app_environment: Literal["local", "test", "production"] = "local"
    analyzer_mode: Literal["rule", "openai", "hybrid"] = "rule"
    openai_api_key: SecretStr | None = None
    openai_api_key_secret_arn: str | None = None
    openai_model: str = "gpt-5.4-mini"
    openai_few_shot_count: int = Field(default=1, ge=0, le=10)
    openai_reasoning_effort: Literal["none", "low", "medium", "high"] = "none"
    openai_max_output_tokens: int = Field(default=800, ge=300, le=4000)
    hybrid_confidence_threshold: float = Field(default=0.85, ge=0.5, le=1)
    hybrid_llm_timeout_seconds: float = Field(default=2.5, ge=0.5, le=30)
    audit_log_path: Path = Path("runtime/audit.jsonl")
    audit_backend: Literal["jsonl", "dynamodb"] = "jsonl"
    dynamodb_table_name: str = "zero-trust-llm-secops-audit"
    aws_region: str = "ap-northeast-2"
    auth_mode: Literal["disabled", "api_key", "oidc"] = "disabled"
    api_key_sha256: SecretStr | None = None
    api_key_subject: str = Field(default="service-client", min_length=1, max_length=128)
    api_key_tenant_id: str = Field(default="local", pattern=r"^[a-zA-Z0-9._-]{1,64}$")
    api_key_roles: str = "analyst,responder,viewer"
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_roles_claim: str = Field(default="roles", min_length=1, max_length=64)
    oidc_tenant_claim: str = Field(default="tenant_id", min_length=1, max_length=64)
    allowed_hosts: str = "127.0.0.1,localhost,testserver"
    api_max_body_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)
    analysis_max_concurrency: int = Field(default=8, ge=1, le=100)
    analysis_queue_timeout_seconds: float = Field(default=0.25, ge=0.01, le=10)

    model_config = SettingsConfigDict(
        env_file=".env.local",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    @property
    def allowed_host_list(self) -> list[str]:
        return [host.strip() for host in self.allowed_hosts.split(",") if host.strip()]

    @property
    def api_key_role_list(self) -> list[str]:
        return [role.strip() for role in self.api_key_roles.split(",") if role.strip()]

    @model_validator(mode="after")
    def validate_enterprise_security(self) -> "Settings":
        if self.app_environment == "production" and self.auth_mode == "disabled":
            raise ValueError("production requires api_key or oidc authentication")

        if self.auth_mode == "api_key":
            digest = self.api_key_sha256.get_secret_value() if self.api_key_sha256 else ""
            if len(digest) != 64 or any(character not in "0123456789abcdefABCDEF" for character in digest):
                raise ValueError("api_key mode requires API_KEY_SHA256 as a 64-character hex digest")

        if self.auth_mode == "oidc":
            if not all((self.oidc_issuer, self.oidc_audience, self.oidc_jwks_url)):
                raise ValueError("oidc mode requires issuer, audience, and JWKS URL")
            if self.app_environment == "production" and not all(
                value and value.startswith("https://")
                for value in (self.oidc_issuer, self.oidc_jwks_url)
            ):
                raise ValueError("production OIDC endpoints must use HTTPS")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
