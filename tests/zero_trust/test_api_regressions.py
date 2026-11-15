"""Isolated HTTP authorization, contract and storage-failure regression tests."""

import sqlite3
from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.security import Principal, Role, get_principal
from app.zero_trust_api import zero_trust_router

ROUTES = [
    ("policies", "GET", "/zero-trust/policies", "viewer"),
    ("sessions", "GET", "/zero-trust/sessions", "viewer"),
    ("history", "GET", "/zero-trust/sessions/session-a", "viewer"),
    ("sources", "GET", "/zero-trust/signals/status", "viewer"),
    ("evaluate", "POST", "/zero-trust/sessions/evaluate", "analyst"),
    ("signed", "POST", "/zero-trust/signals/evaluate", "analyst"),
    ("access", "POST", "/zero-trust/protected-access", "analyst"),
    ("revoke", "POST", "/zero-trust/sessions/session-a/revoke", "responder"),
]
ROLE_ACCESS = {
    "none": set(),
    "viewer": {"viewer"},
    "analyst": {"viewer", "analyst"},
    "responder": {"viewer", "analyst", "responder"},
    "admin": {"viewer", "analyst", "responder"},
}


def body_for(lab, name, token):
    if name == "evaluate":
        return lab.request(version=1, event_id="next-event",
                           when=lab.now + timedelta(seconds=1)).model_dump(mode="json")
    if name == "signed":
        return lab.signed(session="signed-session", event_id="signed-event").model_dump(mode="json")
    if name == "access":
        return {"session_id": "session-a", "resource_id": "zt-demo-documents",
                "action": "READ", "grant_token": token}
    if name == "revoke":
        return {"expected_version": 1, "note": "operator review"}
    return None


@pytest.mark.parametrize("role", ROLE_ACCESS)
@pytest.mark.parametrize("name,method,path,required", ROUTES, ids=[row[0] for row in ROUTES])
def test_http_role_matrix(lab, api, role, name, method, path, required):
    first = lab.evaluate()
    roles = frozenset() if role == "none" else frozenset({Role(role)})
    principal = Principal(lab.operator.subject, lab.operator.tenant_id, roles, "api_key")
    api.app.dependency_overrides[get_principal] = lambda: principal
    response = api.client.request(method, path, json=body_for(lab, name, first.grant_token))
    permitted = required in ROLE_ACCESS[role]
    assert response.status_code == (200 if permitted else 403), response.text
    if not permitted:
        assert response.json() == {"detail": "Insufficient role for this operation"}
        assert first.grant_token not in response.text
        assert lab.service.integrity()["verified_entries"] == 1
        assert lab.access(first.grant_token).allowed


@pytest.mark.parametrize("name,method,path,required", ROUTES, ids=[row[0] for row in ROUTES])
def test_every_simulation_endpoint_is_disabled_without_a_local_service(
    lab, name, method, path, required,
):
    application = FastAPI()
    application.include_router(zero_trust_router(None))
    application.dependency_overrides[get_principal] = lambda: lab.operator
    with TestClient(application) as client:
        response = client.request(method, path, json=body_for(lab, name, "x" * 43))
    assert response.status_code == 404
    assert response.json() == {"detail": "Local Zero Trust simulation is disabled in production"}
    assert lab.service.sessions(lab.operator) == []


@pytest.mark.parametrize("name,method,path,required", [
    row for row in ROUTES if row[0] in {"sessions", "history", "evaluate", "signed", "access", "revoke"}
], ids=[row[0] for row in ROUTES if row[0] in {
    "sessions", "history", "evaluate", "signed", "access", "revoke",
}])
def test_unavailable_store_never_returns_success_or_protected_content(
    lab, api, name, method, path, required,
):
    first = lab.evaluate()
    with sqlite3.connect(lab.service.path) as connection:
        connection.execute("DROP TABLE journal")
    response = api.client.request(method, path, json=body_for(lab, name, first.grant_token))
    assert response.status_code == 503
    assert response.json() == {"detail": "Zero Trust journal unavailable; access denied"}
    assert first.grant_token not in response.text
    assert str(lab.service.path) not in response.text


@pytest.mark.parametrize("operation", ["history", "revoke", "access"])
def test_http_cross_tenant_requests_do_not_expose_or_change_the_target_session(lab, api, operation):
    first = lab.evaluate()
    other = Principal("operator-a", "tenant-other", lab.operator.roles, "api_key")
    api.app.dependency_overrides[get_principal] = lambda: other
    route = next(row for row in ROUTES if row[0] == operation)
    _, method, path, _ = route
    response = api.client.request(method, path, json=body_for(lab, operation, first.grant_token))
    if operation == "access":
        assert response.status_code == 403
        assert response.json()["content"] is None
        assert response.json()["session_version"] is None
    else:
        assert response.status_code == 404
        assert response.json() == {"detail": "Session not found"}
    assert first.grant_token not in response.text
    assert lab.service.history("session-a", lab.operator) == [first.session]
    assert lab.access(first.grant_token).allowed


@pytest.mark.parametrize("field,value", [
    ("session_id", "../session-a"),
    ("session_id", "ab"),
    ("session_id", "a" * 65),
    ("expected_version", -1),
    ("expected_version", 201),
    ("decision", "ALLOW"),
    ("tenant_id", "tenant-other"),
    ("grant_token", "injected-token"),
])
def test_invalid_or_server_owned_evaluation_fields_are_rejected_without_mutation(lab, api, field, value):
    payload = lab.request().model_dump(mode="json")
    payload[field] = value
    response = api.client.post("/zero-trust/sessions/evaluate", json=payload)
    assert response.status_code == 422
    assert lab.service.sessions(lab.operator) == []
    assert lab.service.integrity()["verified_entries"] == 0


@pytest.mark.parametrize("field,value", [
    ("grant_token", "x" * 31),
    ("grant_token", "x" * 129),
    ("action", "DELETE"),
    ("resource_id", ""),
    ("allowed", True),
])
def test_invalid_access_contract_does_not_consume_the_real_grant(lab, api, field, value):
    first = lab.evaluate()
    payload = body_for(lab, "access", first.grant_token)
    payload[field] = value
    response = api.client.post("/zero-trust/protected-access", json=payload)
    assert response.status_code == 422
    assert lab.service.integrity()["verified_entries"] == 1
    assert lab.access(first.grant_token).allowed


def test_http_version_conflict_preserves_current_state(lab, api):
    first = lab.evaluate()
    payload = body_for(lab, "evaluate", first.grant_token)
    payload["expected_version"] = 0
    response = api.client.post("/zero-trust/sessions/evaluate", json=payload)
    assert response.status_code == 409
    assert response.json() == {"detail": "Session version, identity, order or event conflict"}
    assert lab.service.history("session-a", lab.operator) == [first.session]
    assert lab.access(first.grant_token).allowed


def test_http_bad_signature_returns_401_and_never_creates_a_session(lab, api):
    payload = lab.signed().model_dump(mode="json")
    payload["signature"] = "A" * 86
    response = api.client.post("/zero-trust/signals/evaluate", json=payload)
    assert response.status_code == 401
    assert response.json() == {"detail": "Signal source, signature, scope or freshness rejected"}
    assert lab.service.sessions(lab.operator) == []


def test_http_registry_failure_returns_503_without_leaking_keys_or_a_token(lab, api):
    first = lab.service.evaluate_signed(lab.signed(), lab.operator, now=lab.now)
    lab.registry_path.write_text("broken registry", encoding="utf-8")
    response = api.client.post("/zero-trust/protected-access",
                               json=body_for(lab, "access", first.grant_token))
    assert response.status_code == 503
    assert response.json() == {"detail": "Trusted signal registry unavailable; access denied"}
    assert first.grant_token not in response.text
    assert "PRIVATE KEY" not in response.text and "PUBLIC KEY" not in response.text
