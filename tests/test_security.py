import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.config import Settings
from app.security import Role, _oidc_principal


class _StaticJwksClient:
    def __init__(self, public_key) -> None:
        self.public_key = public_key

    def get_signing_key_from_jwt(self, _: str):
        return SimpleNamespace(key=self.public_key)


def _oidc_settings() -> Settings:
    return Settings(
        auth_mode="oidc",
        oidc_issuer="https://identity.example.test",
        oidc_audience="secops-api",
        oidc_jwks_url="https://identity.example.test/keys",
    )


def test_oidc_principal_validates_signature_issuer_audience_and_claims(monkeypatch) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "analyst@example.test",
            "tenant_id": "tenant-a",
            "roles": ["analyst"],
            "iss": "https://identity.example.test",
            "aud": "secops-api",
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        private_key,
        algorithm="RS256",
    )
    monkeypatch.setattr(
        "app.security._jwks_client",
        lambda _: _StaticJwksClient(private_key.public_key()),
    )

    principal = asyncio.run(
        _oidc_principal(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token), _oidc_settings())
    )

    assert principal.subject == "analyst@example.test"
    assert principal.tenant_id == "tenant-a"
    assert Role.ANALYST in principal.roles
    assert Role.VIEWER in principal.effective_roles


def test_oidc_principal_rejects_wrong_audience(monkeypatch) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "analyst@example.test",
            "tenant_id": "tenant-a",
            "roles": ["analyst"],
            "iss": "https://identity.example.test",
            "aud": "different-api",
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        private_key,
        algorithm="RS256",
    )
    monkeypatch.setattr(
        "app.security._jwks_client",
        lambda _: _StaticJwksClient(private_key.public_key()),
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            _oidc_principal(
                HTTPAuthorizationCredentials(scheme="Bearer", credentials=token),
                _oidc_settings(),
            )
        )
    assert exc_info.value.status_code == 401
