"""Distinct server-bound API keys exercise approval without identity overrides."""

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.response_api import response_router
from tests import test_response_actions as cases
from tests.test_api_key_accounts import account, sha
from tests.test_response_actions import command, create, review


@pytest.fixture
def response_lab(tmp_path, monkeypatch):
    return cases.response_lab.__wrapped__(tmp_path, monkeypatch)


def test_api_credentials_bind_subject_and_cannot_count_rotated_key_as_second_person(
    response_lab, tmp_path, monkeypatch
):
    e = response_lab
    path = tmp_path / "http-accounts.json"
    path.write_text(
        json.dumps(
            {
                "schema": "api-key-accounts-1",
                "accounts": [
                    account("reviewer-a", "review-key-a"),
                    account("reviewer-a", "review-key-a-rotated"),
                    account("reviewer-b", "review-key-b"),
                    account("reader", "reader-key", roles=["viewer"]),
                    account("foreign", "foreign-key", tenant_id="tenant-b"),
                ],
            }
        )
    )
    settings = Settings(
        auth_mode="api_key",
        api_key_sha256=sha("operator-key"),
        api_key_subject=e.requester.subject,
        api_key_tenant_id="tenant-a",
        api_key_roles="responder",
        api_key_accounts_path=path,
    )
    monkeypatch.setattr("app.security.get_settings", lambda: settings)
    app = FastAPI()
    app.include_router(response_router(e.service))
    client = TestClient(app)

    def headers(key):
        return {"X-API-Key": key, "X-Subject": "forged-reviewer", "X-Roles": "admin"}

    request, _ = create(e)
    view = client.post(
        "/response/requests", headers=headers("operator-key"), json=request.model_dump(mode="json")
    ).json()
    url = "/response/requests/" + request.request_id
    first = review(view).model_dump()
    assert (
        client.post(url + "/approvals", headers=headers("operator-key"), json=first).status_code
        == 403
    )
    assert (
        client.post(url + "/approvals", headers=headers("reader-key"), json=first).status_code
        == 403
    )
    assert (
        client.post(url + "/approvals", headers=headers("foreign-key"), json=first).status_code
        == 404
    )
    assert (
        client.post(url + "/approvals", headers=headers("unknown"), json=first).status_code == 401
    )
    response = client.post(url + "/approvals", headers=headers("review-key-a"), json=first)
    assert response.status_code == 200
    view = response.json()
    duplicate = client.post(url + "/approvals", headers=headers("review-key-a-rotated"), json=first)
    assert duplicate.status_code == 200 and duplicate.json()["duplicate"]
    assert duplicate.json()["approved_by"] == ["reviewer-a"]
    assert (
        client.post(
            url + "/execute", headers=headers("operator-key"), json=command(view).model_dump()
        ).status_code
        == 409
    )
    response = client.post(
        url + "/approvals", headers=headers("review-key-b"), json=review(view).model_dump()
    )
    assert response.status_code == 200
    view = response.json()
    result = client.post(
        url + "/execute", headers=headers("operator-key"), json=command(view).model_dump()
    )
    assert result.status_code == 200 and result.json()["result"]["effect_applied"] is False
    assert result.json()["approved_by"] == ["reviewer-a", "reviewer-b"]
