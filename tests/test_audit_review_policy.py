"""Opt-in server enforcement of observed version and authenticated caller intent."""

import asyncio

import pytest
from pydantic import ValidationError
from test_audit_query_admission import api as api  # noqa: PLC0414
from test_audit_review_identity import BODY, URL, observed

from app import main, security
from app.config import Settings
from app.services.audit import AuditStore
from scripts.local_oidc_authority import LocalOIDCAuthority


def enable(api, monkeypatch):
    values = main.settings.model_dump() | {
        "audit_backend": "sqlite",
        "audit_review_require_if_match": True,
        "audit_review_require_identity": True,
    }
    config = Settings(_env_file=None, **values)
    monkeypatch.setattr(main, "settings", config)
    monkeypatch.setattr(security, "get_settings", lambda: config)
    return config


def test_identity_required_policy_rejects_version_only_before_audit_read(api, monkeypatch):
    enable(api, monkeypatch)
    headers = observed(api)
    del headers["X-Review-Identity"]
    reads = []
    original = api.store.get

    def tracked(*args):
        reads.append(args)
        return original(*args)

    monkeypatch.setattr(api.store, "get", tracked)
    response = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert response.status_code == 428
    assert not reads
    assert api.store.integrity()["verified_lines"] == 2


@pytest.mark.parametrize("missing", ["both", "If-Match"])
def test_required_preconditions_cannot_be_omitted(api, monkeypatch, missing):
    enable(api, monkeypatch)
    headers = observed(api)
    del headers["If-Match"]
    if missing == "both":
        del headers["X-Review-Identity"]
    monkeypatch.setattr(api.store, "get", lambda *_: pytest.fail("missing version read audit"))
    response = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert response.status_code == 428 and api.store.integrity()["verified_lines"] == 2


def test_bound_review_accepts_current_intent_and_rejects_replay(api, monkeypatch):
    enable(api, monkeypatch)
    headers = observed(api)
    response = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert response.status_code == 200
    assert response.json()["reviewer"] == "local-auditor"
    assert response.headers["ETag"] != headers["If-Match"]
    assert response.headers["X-Review-Identity"] == headers["X-Review-Identity"]
    assert response.headers["Cache-Control"] == "no-store"
    replay = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert replay.status_code == 412 and api.store.integrity()["verified_lines"] == 3


@pytest.mark.parametrize("header", ["If-Match", "X-Review-Identity"])
@pytest.mark.parametrize("kind", ["malformed", "duplicate"])
def test_required_policy_retains_header_validation(api, monkeypatch, header, kind):
    enable(api, monkeypatch)
    headers = observed(api)
    if kind == "malformed":
        headers[header] = "*"
    else:
        headers = [*headers.items(), (header, headers[header])]
    monkeypatch.setattr(api.store, "get", lambda *_: pytest.fail("invalid precondition read audit"))
    response = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert response.status_code == 400 and api.store.integrity()["verified_lines"] == 2


@pytest.mark.parametrize("change", ["subject", "tenant_id", "role", "revoked"])
def test_required_binding_does_not_replace_current_authority(api, monkeypatch, change):
    config = enable(api, monkeypatch)
    headers = observed(api)
    if change in {"subject", "tenant_id"}:
        setattr(config, "api_key_" + change, "different")
    elif change == "role":
        config.api_key_roles = "viewer"
    else:
        config.api_key_sha256 = None
    response = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert response.status_code == (401 if change == "revoked" else 403)
    assert api.store.integrity()["verified_lines"] == 2


@pytest.mark.parametrize("boundary", [1, 2, 3])
def test_policy_enabled_during_authority_io_is_rechecked_before_append(api, monkeypatch, boundary):
    headers = observed(api)
    del headers["X-Review-Identity"]
    original = main._audit_boundary
    calls = 0

    async def strengthen(*args):
        nonlocal calls
        await original(*args)
        calls += 1
        if calls == boundary:
            main.settings.audit_review_require_identity = True

    monkeypatch.setattr(main, "_audit_boundary", strengthen)
    response = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert response.status_code == 428 and api.store.integrity()["verified_lines"] == 2
    assert api.capacity._value == 1


def test_identity_policy_still_requires_version_if_runtime_settings_are_inconsistent(
    api, monkeypatch
):
    config = enable(api, monkeypatch)
    config.audit_review_require_if_match = False
    headers = observed(api)
    del headers["If-Match"]
    response = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert response.status_code == 428 and api.store.integrity()["verified_lines"] == 2


def test_runtime_backend_change_cannot_silently_downgrade_bound_review(api, monkeypatch, tmp_path):
    enable(api, monkeypatch)
    store = AuditStore(tmp_path / "legacy.jsonl")
    asyncio.run(store.save(api.first))
    monkeypatch.setattr(main, "audit_store", store)
    headers = observed(api)
    before = store._path.read_bytes()
    response = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert response.status_code == 503 and store._path.read_bytes() == before


def test_runtime_auth_disabled_cannot_submit_a_bound_review(api, monkeypatch):
    config = enable(api, monkeypatch)
    config.auth_mode = "disabled"
    headers = observed(api)
    response = api.client.patch(URL + "/review", headers=headers, json=BODY)
    assert response.status_code == 403 and api.store.integrity()["verified_lines"] == 2


def test_required_binding_does_not_disclose_foreign_event(api, monkeypatch):
    enable(api, monkeypatch)
    headers = observed(api)
    response = api.client.patch("/results/audit-cancel-2/review", headers=headers, json=BODY)
    assert response.status_code == 404 and "ETag" not in response.headers
    assert api.store.integrity()["verified_lines"] == 2


@pytest.mark.parametrize("bound", [False, True])
def test_legacy_policy_remains_explicitly_compatible(api, bound):
    main.settings.audit_review_require_if_match = bound
    headers = observed(api) if bound else api.headers
    if bound:
        del headers["X-Review-Identity"]
    assert api.client.patch(URL + "/review", headers=headers, json=BODY).status_code == 200


@pytest.mark.parametrize("different_subject", [False, True])
def test_local_signed_oidc_can_use_required_policy(api, monkeypatch, different_subject):
    with LocalOIDCAuthority() as authority:
        config = Settings(
            _env_file=None,
            app_environment="test",
            auth_mode="oidc",
            oidc_issuer=authority.issuer,
            oidc_audience=authority.audience,
            oidc_jwks_url=authority.jwks_url,
            audit_backend="sqlite",
            audit_review_require_if_match=True,
            audit_review_require_identity=True,
        )
        monkeypatch.setattr(main, "settings", config)
        monkeypatch.setattr(security, "get_settings", lambda: config)
        original_headers = api.headers
        api.headers = {
            "Authorization": "Bearer " + authority.issue(tenant_id="local", roles=["responder"])
        }
        try:
            headers = observed(api)
            if different_subject:
                headers["Authorization"] = "Bearer " + authority.issue(
                    sub="other-person", tenant_id="local", roles=["responder"]
                )
            response = api.client.patch(URL + "/review", headers=headers, json=BODY)
            assert response.status_code == (403 if different_subject else 200)
            assert api.store.integrity()["verified_lines"] == (2 if different_subject else 3)
            assert authority.fetches >= 1
        finally:
            api.headers = original_headers
            security._jwks_client.cache_clear()


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"audit_backend": "jsonl"}, "sqlite"),
        ({"audit_backend": "dynamodb"}, "sqlite"),
        ({"auth_mode": "disabled"}, "authentication"),
        ({"audit_review_require_if_match": False}, "IF_MATCH"),
    ],
)
def test_startup_rejects_unsupported_required_policy(changes, reason):
    values = {
        "auth_mode": "api_key",
        "api_key_sha256": "a" * 64,
        "audit_backend": "sqlite",
        "audit_review_require_if_match": True,
        "audit_review_require_identity": True,
    }
    with pytest.raises(ValidationError, match=reason):
        Settings(_env_file=None, **(values | changes))


def test_policy_environment_is_parsed_without_changing_default(monkeypatch):
    monkeypatch.delenv("AUDIT_REVIEW_REQUIRE_IDENTITY", raising=False)
    assert Settings(_env_file=None).audit_review_require_identity is False
    monkeypatch.setenv("AUDIT_REVIEW_REQUIRE_IDENTITY", "true")
    config = Settings(
        _env_file=None,
        auth_mode="api_key",
        api_key_sha256="a" * 64,
        audit_backend="sqlite",
        audit_review_require_if_match=True,
    )
    assert config.audit_review_require_identity is True
