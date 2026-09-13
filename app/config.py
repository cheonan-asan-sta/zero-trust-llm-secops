from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Zero Trust LLM SecOps"
    app_version: str = "0.2.0"
    analyzer_mode: Literal["rule", "openai"] = "rule"
    openai_api_key: SecretStr | None = None
    openai_model: str = "gpt-5.4-mini"
    audit_log_path: Path = Path("runtime/audit.jsonl")

    model_config = SettingsConfigDict(
        env_file=".env.local",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
