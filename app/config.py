from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Zero Trust LLM SecOps"
    app_version: str = "0.6.0"
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

    model_config = SettingsConfigDict(
        env_file=".env.local",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
