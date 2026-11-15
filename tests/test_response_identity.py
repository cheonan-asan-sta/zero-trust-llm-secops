"""Exercise real signed OIDC identities through the approval HTTP dependency."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.response_api import response_router
from tests import test_response_actions as response_cases
from tests.test_response_actions import command, create, review


@pytest.fixture
def response_lab(tmp_path, monkeypatch):
    return response_cases.response_lab.__wrapped__(tmp_path, monkeypatch)


def test_signed_distinct_identities_are_required_without_principal_override(
    response_lab, monkeypatch
):
    e = response_lab
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    settings = Settings(
        auth_mode="oidc",
        oidc_issuer="https://identity.example.test",
        oidc_audience="secops-api",
        oidc_jwks_url="https://identity.example.test/keys",
    )
    monkeypatch.setattr("app.security.get_settings", lambda: settings)
    monkeypatch.setattr(
        "app.security._jwks_client",
        lambda _: SimpleNamespace(
            get_signing_key_from_jwt=lambda _: SimpleNamespace(key=key.public_key())
        ),
    )
    app = FastAPI()
    app.include_router(response_router(e.service))
    client = TestClient(app)

    def headers(subject, *, role="responder", tenant="tenant-a", signing_key=key):
        now = datetime.now(UTC)
        token = jwt.encode(
            {
                "sub": subject,
                "tenant_id": tenant,
                "roles": [role],
                "iss": settings.oidc_issuer,
                "aud": settings.oidc_audience,
                "iat": now,
                "exp": now + timedelta(minutes=2),
            },
            signing_key,
            algorithm="RS256",
        )
        return {"Authorization": "Bearer " + token}

    request, _ = create(e)
    path = "/response/requests/" + request.request_id
    view = client.get(path, headers=headers(e.requester.subject)).json()
    assert (
        client.post(
            path + "/approvals",
            headers=headers(e.requester.subject),
            json=review(view).model_dump(),
        ).status_code
        == 403
    )
    assert (
        client.post(
            path + "/approvals",
            headers=headers("reader", role="viewer"),
            json=review(view).model_dump(),
        ).status_code
        == 403
    )
    assert (
        client.post(
            path + "/approvals",
            headers=headers("outsider", tenant="tenant-b"),
            json=review(view).model_dump(),
        ).status_code
        == 404
    )
    fake = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert (
        client.post(
            path + "/approvals",
            headers=headers("forged", signing_key=fake),
            json=review(view).model_dump(),
        ).status_code
        == 401
    )
    for name in ["reviewer-a", "reviewer-b"]:
        response = client.post(
            path + "/approvals", headers=headers(name), json=review(view).model_dump()
        )
        assert response.status_code == 200
        view = response.json()
    response = client.post(
        path + "/execute", headers=headers(e.requester.subject), json=command(view).model_dump()
    )
    assert response.status_code == 200
    assert response.json()["approved_by"] == ["reviewer-a", "reviewer-b"]
    assert response.json()["result"]["effect_applied"] is False


def test_unavailable_simulator_fails_closed(response_lab):
    app = FastAPI()
    app.include_router(response_router(None))
    from app.security import get_principal

    app.dependency_overrides[get_principal] = lambda: response_lab.requester
    client = TestClient(app)
    assert client.get("/response/requests").status_code == 503
