"""Offline OIDC validation with generated test keys and a local JWKS substitute."""

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


@pytest.fixture(scope="module")
def identity_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def identity(identity_key, monkeypatch):
    now = datetime.now(UTC)
    claims = {
        "sub": "test-operator", "tenant_id": "tenant-a", "roles": ["analyst"],
        "iss": "https://identity.example.test", "aud": "secops-api",
        "iat": now, "exp": now + timedelta(minutes=5),
    }
    settings = Settings(
        auth_mode="oidc", oidc_issuer="https://identity.example.test", oidc_audience="secops-api",
        oidc_jwks_url="https://identity.example.test/keys",
    )

    class LocalKeys:
        def get_signing_key_from_jwt(self, token):
            return SimpleNamespace(key=identity_key.public_key())

    monkeypatch.setattr("app.security._jwks_client", lambda _: LocalKeys())

    def authenticate(payload=None, *, signer=identity_key, algorithm="RS256"):
        token = jwt.encode(claims if payload is None else payload, signer, algorithm=algorithm)
        return asyncio.run(_oidc_principal(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=token), settings,
        ))

    return SimpleNamespace(now=now, claims=claims, authenticate=authenticate, settings=settings)


@pytest.mark.parametrize("field,value", [
    ("iss", "https://untrusted.example.test"),
    ("aud", "another-api"),
    ("tenant_id", ""),
    ("tenant_id", "tenant/other"),
    ("tenant_id", None),
    ("tenant_id", 123),
    ("tenant_id", True),
    ("roles", []),
    ("roles", ["super-admin"]),
    ("roles", {"admin": True}),
    ("sub", ""),
    ("iat", "invalid-timestamp"),
])
def test_invalid_identity_claims_cannot_produce_a_principal(identity, field, value):
    payload = {**identity.claims, field: value}
    with pytest.raises(HTTPException) as rejected:
        identity.authenticate(payload)
    assert rejected.value.status_code == 401


@pytest.mark.parametrize("field", ["sub", "exp", "iat", "tenant_id"])
def test_missing_required_identity_claim_is_rejected(identity, field):
    payload = dict(identity.claims)
    del payload[field]
    with pytest.raises(HTTPException) as rejected:
        identity.authenticate(payload)
    assert rejected.value.status_code == 401


@pytest.mark.parametrize("field,offset", [("exp", -60), ("iat", 300), ("nbf", 300)])
def test_expired_or_not_yet_valid_identity_token_is_rejected(identity, field, offset):
    payload = {**identity.claims, field: identity.now + timedelta(seconds=offset)}
    with pytest.raises(HTTPException) as rejected:
        identity.authenticate(payload)
    assert rejected.value.status_code == 401


def test_an_untrusted_signing_key_is_rejected(identity):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(HTTPException) as rejected:
        identity.authenticate(signer=other)
    assert rejected.value.status_code == 401


def test_symmetric_algorithm_cannot_replace_the_allowed_asymmetric_algorithm(identity):
    with pytest.raises(HTTPException) as rejected:
        identity.authenticate(signer=b"offline-test-key-never-used-by-the-app", algorithm="HS256")
    assert rejected.value.status_code == 401


@pytest.mark.parametrize("roles", [["analyst"], "analyst", ["analyst", "unknown-role"]])
def test_valid_analyst_identity_preserves_exact_subject_tenant_and_least_privilege(identity, roles):
    principal = identity.authenticate({**identity.claims, "roles": roles})
    assert principal.subject == "test-operator"
    assert principal.tenant_id == "tenant-a"
    assert principal.effective_roles == frozenset({Role.ANALYST, Role.VIEWER})


def test_missing_bearer_credentials_are_rejected(identity):
    with pytest.raises(HTTPException) as rejected:
        asyncio.run(_oidc_principal(None, identity.settings))
    assert rejected.value.status_code == 401
