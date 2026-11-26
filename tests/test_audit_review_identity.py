"""A caller's observed review version cannot be reused under another identity."""

import asyncio
from types import SimpleNamespace

import pytest
from test_audit_query_admission import api as api  # noqa: PLC0414

from app import main
from app.services.audit import AuditStore
from app.services.audit_review_preconditions import review_identity

URL = "/results/audit-cancel-1"
BODY = {
    "status": "IN_REVIEW",
    "reviewer": "untrusted-body-name",
    "note": "review observed evidence",
}


def observed(api):
    response = api.client.get(URL, headers=api.headers)
    assert response.status_code == 200
    return api.headers | {
        "If-Match": response.headers["ETag"],
        "X-Review-Identity": response.headers["X-Review-Identity"],
    }


def test_observed_caller_and_version_success_return_new_version(api):
    headers = observed(api)
    assert api.client.get(URL, headers=api.headers).headers["X-Review-Mode"] == "conditional"
    response = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert response.status_code == 200
    assert response.json()["reviewer"] == "local-auditor"
    assert response.headers["X-Review-Identity"] == headers["X-Review-Identity"]
    assert response.headers["ETag"] != headers["If-Match"]
    assert response.headers["Cache-Control"] == "no-store"
    replay = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert replay.status_code == 412 and api.store.integrity()["verified_lines"] == 3


@pytest.mark.parametrize(
    "field,value", [("subject", "다른 운영자"), ("tenant_id", "other"), ("auth_method", "oidc")]
)
def test_binding_distinguishes_identity_dimensions(field, value):
    fields = {"subject": "운영자", "tenant_id": "local", "auth_method": "api_key"}
    first = review_identity(SimpleNamespace(**fields))
    assert len(first) == 64 and int(first, 16) >= 0
    assert first == review_identity(SimpleNamespace(**fields))
    assert first != review_identity(SimpleNamespace(**(fields | {field: value})))


@pytest.mark.parametrize("changed", ["subject", "tenant_id"])
def test_same_key_remapped_before_write_cannot_reuse_old_binding(api, changed):
    headers = observed(api)
    setattr(main.settings, "api_key_" + changed, "other")
    response = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert response.status_code == 403 and api.store.integrity()["verified_lines"] == 2
    if changed == "subject":
        fresh = observed(api)
        assert fresh["If-Match"] == headers["If-Match"]
        assert fresh["X-Review-Identity"] != headers["X-Review-Identity"]
        accepted = api.client.patch(URL + "/review", headers=fresh, json=BODY)
        assert accepted.status_code == 200 and accepted.json()["reviewer"] == "other"


@pytest.mark.parametrize("bad", ["", "0" * 63, "A" * 64, "0" * 65, "0" * 64 + "," + "1" * 64])
def test_invalid_identity_never_reads_or_appends(api, monkeypatch, bad):
    headers = observed(api) | {"X-Review-Identity": bad}
    monkeypatch.setattr(api.store, "get", lambda *_: pytest.fail("invalid binding read audit"))
    response = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert response.status_code == 400 and api.store.integrity()["verified_lines"] == 2


def test_duplicate_identity_never_reads_or_appends(api, monkeypatch):
    headers = observed(api)
    duplicate = [*headers.items(), ("X-Review-Identity", headers["X-Review-Identity"])]
    monkeypatch.setattr(api.store, "get", lambda *_: pytest.fail("duplicate binding read audit"))
    response = api.client.patch(URL + "/review", headers=duplicate, json=BODY)
    assert response.status_code == 400 and api.store.integrity()["verified_lines"] == 2


def test_identity_without_version_never_reads_or_appends(api, monkeypatch):
    headers = observed(api)
    del headers["If-Match"]
    monkeypatch.setattr(api.store, "get", lambda *_: pytest.fail("unversioned binding read audit"))
    response = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert response.status_code == 400 and api.store.integrity()["verified_lines"] == 2


def test_other_binding_rejected_before_result_lookup(api, monkeypatch):
    headers = observed(api) | {"X-Review-Identity": "0" * 64}
    monkeypatch.setattr(api.store, "get", lambda *_: pytest.fail("wrong caller read audit"))
    response = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert response.status_code == 403 and api.store.integrity()["verified_lines"] == 2


def test_legacy_version_client_stays_compatible(api):
    headers = observed(api)
    del headers["X-Review-Identity"]
    main.settings.audit_review_require_if_match = True
    assert api.client.patch(URL + "/review", headers=headers, json=BODY).status_code == 200


def test_jsonl_advertises_unavailable_and_never_downgrades(api, monkeypatch, tmp_path):
    store = AuditStore(tmp_path / "audit.jsonl")
    asyncio.run(store.save(api.first))
    monkeypatch.setattr(main, "audit_store", store)
    response = api.client.get(URL, headers=api.headers)
    assert response.status_code == 200 and response.headers["X-Review-Mode"] == "unavailable"
    headers = observed(api)
    before = store._path.read_bytes()
    assert api.client.patch(URL + "/review", headers=headers, json=BODY).status_code == 503
    assert store._path.read_bytes() == before
