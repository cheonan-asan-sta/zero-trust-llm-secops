from dataclasses import replace
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from app import security
from app.config import Settings
from scripts.keycloak_live_authority import KeycloakLiveAuthority
from scripts.local_oidc_authority import LocalOIDCAuthority


def test_live_authority_rejects_removed_role_and_ended_session_without_client_writes():
    issuer = "http://127.0.0.1:18080/realms/local"
    requests = []
    state = {"roles": [{"name": "analyst"}], "sessions": [{"id": "signed-session"}]}

    def provider(request):
        requests.append((request.method, request.url.path))
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "reader-only-token"})
        if request.url.path.endswith("/composite"):
            return httpx.Response(200, json=state["roles"])
        if request.url.path.endswith("/sessions"):
            return httpx.Response(200, json=state["sessions"])
        return httpx.Response(200, json={"id": "subject", "enabled": True})

    verifier = KeycloakLiveAuthority(
        issuer, "reader", "credential", transport=httpx.MockTransport(provider)
    )
    caller = security.Principal(
        "subject",
        "local",
        frozenset({security.Role.ANALYST}),
        "oidc",
        oidc_session_id="signed-session",
    )
    verifier(issuer, caller)
    state["roles"] = [{"name": "viewer"}]
    with pytest.raises(HTTPException, match="roles changed") as role_error:
        verifier(issuer, caller)
    assert role_error.value.status_code == 401
    state["sessions"] = [{"id": "different-session"}]
    updated = replace(caller, roles=frozenset({security.Role.VIEWER}))
    with pytest.raises(HTTPException, match="session is no longer active") as ended:
        verifier(issuer, updated)
    assert ended.value.status_code == 401
    assert all(method == "GET" or path.endswith("/token") for method, path in requests)


def test_live_authority_fails_closed_if_current_provider_cannot_be_read():
    issuer = "http://127.0.0.1:18080/realms/local"
    verifier = KeycloakLiveAuthority(
        issuer,
        "reader",
        "credential",
        transport=httpx.MockTransport(lambda _: httpx.Response(503)),
    )
    caller = security.Principal(
        "subject",
        "local",
        frozenset({security.Role.ANALYST}),
        "oidc",
        oidc_session_id="signed-session",
    )
    with pytest.raises(HTTPException) as error:
        verifier(issuer, caller)
    assert error.value.status_code == 503
    with pytest.raises(HTTPException) as missing:
        verifier(issuer, replace(caller, oidc_session_id=None))
    assert missing.value.status_code == 401


def test_gateway_live_hook_receives_session_id_from_verified_oidc_claim(monkeypatch):
    with LocalOIDCAuthority() as authority:
        settings = Settings(
            _env_file=None,
            app_environment="test",
            auth_mode="oidc",
            oidc_issuer=authority.issuer,
            oidc_audience=authority.audience,
            oidc_jwks_url=authority.jwks_url,
        )
        monkeypatch.setattr(security, "get_settings", lambda: settings)
        app = FastAPI()
        active = {"sid": "session-for-old-token"}
        recorded = []

        def live_check(issuer, principal):
            recorded.append((issuer, principal.oidc_session_id))
            if principal.oidc_session_id != active["sid"]:
                raise HTTPException(401, "Caller session is no longer active")

        app.state.oidc_live_authority = live_check

        @app.get("/protected")
        def protected(principal: Annotated[security.Principal, Depends(security.get_principal)]):
            return {"allowed": bool(principal.subject)}

        token = authority.issue(sid=active["sid"])
        headers = {"Authorization": f"Bearer {token}"}
        with TestClient(app) as client:
            assert client.get("/protected", headers=headers).json() == {"allowed": True}
            active["sid"] = "different-active-session"
            response = client.get("/protected", headers=headers)
            assert response.status_code == 401
        assert recorded == [(authority.issuer, "session-for-old-token")] * 2
    security._jwks_client.cache_clear()
