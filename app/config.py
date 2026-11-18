from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Zero Trust LLM SecOps"
    app_version: str = "0.17.0"
    app_environment: Literal["local", "test", "production"] = "local"
    analyzer_mode: Literal["rule", "openai", "hybrid"] = "rule"
    openai_api_key: SecretStr | None = None
    openai_api_key_secret_arn: str | None = None
    openai_model: str = "gpt-5.4-mini"
    openai_prompt_mode: Literal["legacy", "grounded"] = "legacy"
    openai_few_shot_count: int = Field(default=1, ge=0, le=10)
    openai_reasoning_effort: Literal["none", "low", "medium", "high"] = "none"
    openai_max_output_tokens: int = Field(default=800, ge=300, le=4000)
    openai_incomplete_retries: int = Field(default=0, ge=0, le=1)
    openai_retry_max_output_tokens: int = Field(default=4000, ge=300, le=4000)
    openai_evidence_agent_enabled: bool = False
    openai_evidence_execution_delivery: Literal["inline", "on_request"] = "inline"
    openai_evidence_review_timeout_seconds: float = Field(default=30.0, ge=1.0, le=90.0)
    hybrid_confidence_threshold: float = Field(default=0.85, ge=0.5, le=1)
    hybrid_review_all: bool = False
    hybrid_llm_timeout_seconds: float = Field(default=2.5, ge=0.5, le=30)
    audit_log_path: Path = Path("runtime/audit.jsonl")
    case_log_path: Path = Path("runtime/cases.jsonl")
    outbox_log_path: Path = Path("runtime/integration-outbox.jsonl")
    zero_trust_db_path: Path = Path("runtime/zero-trust.sqlite3")
    zero_trust_policy_path: Path | None = None
    behavior_context_db_path: Path | None = None
    native_analysis_shared_config_path: Path | None = None
    native_analysis_shared_config_sha256: str | None = Field(
        default=None, pattern=r"^[a-f0-9]{64}$"
    )
    # Compatibility for offline legacy fixtures; the application uses behavior_context_db_path.
    response_workflow_db_path: Path = Path("runtime/response-workflow.sqlite3")
    trusted_signal_sources_path: Path | None = None
    signal_inbox_max_pending: int = Field(default=1000, ge=1, le=10000)
    signal_inbox_max_records: int = Field(default=10000, ge=1, le=100000)
    signal_inbox_max_attempts: int = Field(default=3, ge=1, le=20)
    signal_inbox_lease_seconds: float = Field(default=30, gt=0, le=3600)
    signal_inbox_retry_seconds: float = Field(default=1, gt=0, le=60)
    audit_backend: Literal["jsonl", "dynamodb", "sqlite"] = "jsonl"
    audit_db_path: Path | None = None
    audit_checkpoint_path: Path | None = None
    audit_checkpoint_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    dynamodb_table_name: str = "zero-trust-llm-secops-audit"
    aws_region: str = "ap-northeast-2"
    auth_mode: Literal["disabled", "api_key", "oidc"] = "disabled"
    api_key_sha256: SecretStr | None = None
    api_key_accounts_path: Path | None = None
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
    authentication_max_concurrency: int = Field(default=4, ge=1, le=16)
    authentication_queue_timeout_seconds: float = Field(
        default=0.05, ge=0.01, le=2, allow_inf_nan=False
    )
    authentication_max_token_chars: int = Field(default=16384, ge=1024, le=131072)
    evaluation_max_concurrency: int = Field(default=2, ge=1, le=4)
    evaluation_queue_timeout_seconds: float = Field(
        default=0.05, ge=0.01, le=2, allow_inf_nan=False
    )
    analysis_max_concurrency: int = Field(default=8, ge=1, le=100)
    analysis_queue_timeout_seconds: float = Field(default=0.25, ge=0.01, le=10)
    audit_query_max_concurrency: int = Field(default=2, ge=1, le=8)
    audit_query_queue_timeout_seconds: float = Field(
        default=0.05, ge=0.01, le=2, allow_inf_nan=False
    )
    audit_review_require_if_match: bool = False
    audit_cursor_key_path: Path | None = None
    audit_cursor_key_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    # Host-only control plane. Disabled unless an operator selects a private root.
    dashboard_operations_directory: Path | None = None
    dashboard_operations_tenant: str = "local"
    dashboard_m7_paired_directory: Path | None = None
    dashboard_live_max_usd: float = Field(default=0, ge=0, le=50, allow_inf_nan=False)

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
        if self.audit_review_require_if_match and self.audit_backend != "sqlite":
            raise ValueError("required conditional audit reviews need sqlite backend")
        if (self.audit_checkpoint_path is None) != (self.audit_checkpoint_sha256 is None):
            raise ValueError("audit checkpoint requires both path and SHA-256 pin")
        if self.audit_checkpoint_path is not None and self.audit_backend != "sqlite":
            raise ValueError("runtime audit checkpoint requires sqlite backend")
        if (self.audit_cursor_key_path is None) != (self.audit_cursor_key_sha256 is None):
            raise ValueError("audit cursors require both private key path and SHA-256 pin")
        if (self.native_analysis_shared_config_path is None) != (
            self.native_analysis_shared_config_sha256 is None
        ):
            raise ValueError("shared native analysis requires both config path and SHA-256 pin")
        if (
            self.openai_incomplete_retries
            and self.openai_retry_max_output_tokens <= self.openai_max_output_tokens
        ):
            raise ValueError("incomplete retry output limit must exceed the initial limit")
        if self.app_environment == "production" and self.auth_mode == "disabled":
            raise ValueError("production requires api_key or oidc authentication")

        if self.auth_mode == "api_key":
            digest = self.api_key_sha256.get_secret_value() if self.api_key_sha256 else ""
            if len(digest) != 64 or any(
                character not in "0123456789abcdefABCDEF" for character in digest
            ):
                raise ValueError(
                    "api_key mode requires API_KEY_SHA256 as a 64-character hex digest"
                )

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
