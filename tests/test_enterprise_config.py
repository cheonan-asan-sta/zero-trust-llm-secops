import pytest
from pydantic import ValidationError

from app.config import Settings


def test_production_rejects_disabled_authentication() -> None:
    with pytest.raises(ValidationError, match="production requires"):
        Settings(app_environment="production", auth_mode="disabled")


def test_api_key_mode_requires_sha256_digest() -> None:
    with pytest.raises(ValidationError, match="API_KEY_SHA256"):
        Settings(auth_mode="api_key", api_key_sha256="plain-text-key")


def test_production_oidc_requires_https_endpoints() -> None:
    with pytest.raises(ValidationError, match="must use HTTPS"):
        Settings(
            app_environment="production",
            auth_mode="oidc",
            oidc_issuer="http://identity.example.test",
            oidc_audience="secops-api",
            oidc_jwks_url="http://identity.example.test/keys",
        )
