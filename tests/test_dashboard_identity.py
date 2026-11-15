from hashlib import sha256

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import app

client = TestClient(app)


@pytest.mark.parametrize("role,expected", [
    ("viewer", ["viewer"]),
    ("analyst", ["analyst", "viewer"]),
    ("admin", ["admin", "analyst", "responder", "viewer"]),
])
def test_identity_uses_verified_principal_without_credentials(monkeypatch, role, expected):
    key = "synthetic-ui-key"
    settings = Settings(
        _env_file=None, auth_mode="api_key", api_key_sha256=sha256(key.encode()).hexdigest(),
        api_key_subject="verified-viewer", api_key_tenant_id="verified-tenant", api_key_roles=role,
    )
    monkeypatch.setattr("app.security.get_settings", lambda: settings)
    assert client.get("/auth/me").status_code == 401
    assert client.get("/auth/me", headers={"X-API-Key": "incorrect"}).status_code == 401
    response = client.get("/auth/me?tenant_id=other-tenant", headers={
        "X-API-Key": key, "X-User": "other-user", "X-Tenant-ID": "other-tenant",
    })
    assert response.status_code == 200
    assert response.json() == {
        "subject": "verified-viewer", "tenant_id": "verified-tenant",
        "roles": expected, "auth_method": "api_key",
    }
    assert response.headers["cache-control"] == "no-store"
    assert key not in response.text
    assert sha256(key.encode()).hexdigest() not in response.text
    if role == "viewer":
        assert client.post("/events/simulate", headers={"X-API-Key": key},
                           json={"count": 1}).status_code == 403
