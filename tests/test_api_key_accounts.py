"""Server-owned identities fail closed on revocation, ambiguity and bad files."""

import hashlib
import json

import pytest
from fastapi import HTTPException

from app.api_key_accounts import MAX_BYTES
from app.config import Settings
from app.security import Role, _api_key_principal


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def account(subject="reviewer-a", key="temporary-review-key", **extra):
    return {
        "subject": subject,
        "sha256": sha(key),
        "tenant_id": "tenant-a",
        "roles": ["responder"],
        "enabled": True,
        **extra,
    }


@pytest.fixture
def identities(tmp_path):
    path = tmp_path / "accounts.json"
    settings = Settings(
        auth_mode="api_key",
        api_key_sha256=sha("temporary-operator-key"),
        api_key_subject="operator",
        api_key_tenant_id="tenant-a",
        api_key_roles="responder",
        api_key_accounts_path=path,
    )

    def save(entries):
        path.write_text(json.dumps({"schema": "api-key-accounts-1", "accounts": entries}))

    save([account()])
    return settings, path, save


def test_legacy_key_and_distinct_review_keys_keep_server_roles(identities):
    settings, _, save = identities
    legacy = _api_key_principal("temporary-operator-key", settings)
    reviewer = _api_key_principal("temporary-review-key", settings)
    assert legacy.subject == "operator" and reviewer.subject == "reviewer-a"
    assert reviewer.tenant_id == "tenant-a" and reviewer.roles == frozenset({Role.RESPONDER})
    # Two credentials for one person keep the same subject; they are not two approvals.
    save([account(), account(key="rotated-review-key")])
    assert _api_key_principal("rotated-review-key", settings) == reviewer
    save([account(tenant_id="tenant-b", roles=["viewer"])])
    restricted = _api_key_principal("temporary-review-key", settings)
    assert restricted.tenant_id == "tenant-b" and Role.RESPONDER not in restricted.effective_roles


def test_disabled_key_takes_effect_without_process_restart(identities):
    settings, _, save = identities
    assert _api_key_principal("temporary-review-key", settings).subject == "reviewer-a"
    save([account(enabled=False)])
    with pytest.raises(HTTPException) as denied:
        _api_key_principal("temporary-review-key", settings)
    assert denied.value.status_code == 401
    assert _api_key_principal("temporary-operator-key", settings).subject == "operator"


@pytest.mark.parametrize(
    "entries",
    [
        [account(), account(subject="different")],
        [account(key="temporary-operator-key")],
        [account(roles=["root"])],
        [account(roles=["responder", "responder"])],
        [account(enabled="true")],
        [account(subject=" reviewer ")],
        [account(raw_key="must-not-be-accepted")],
    ],
)
def test_invalid_config_never_falls_back_to_legacy_operator(identities, entries):
    settings, _, save = identities
    save(entries)
    with pytest.raises(HTTPException) as denied:
        _api_key_principal("temporary-operator-key", settings)
    assert denied.value.status_code == 503
    assert denied.value.detail == "Authentication configuration is unavailable"


@pytest.mark.parametrize(
    "failure", ["missing", "symlink", "directory", "oversize", "malformed", "duplicate_json"]
)
def test_untrusted_or_incomplete_files_fail_closed(identities, failure):
    settings, path, _ = identities
    if failure == "missing":
        path.unlink()
    elif failure == "symlink":
        original = path.with_suffix(".original")
        path.rename(original)
        path.symlink_to(original)
    elif failure == "directory":
        path.unlink()
        path.mkdir()
    elif failure == "oversize":
        path.write_bytes(b" " * (MAX_BYTES + 1))
    elif failure == "malformed":
        path.write_text("{")
    else:
        path.write_text('{"schema":"api-key-accounts-1","accounts":[],"accounts":[]}')
    with pytest.raises(HTTPException) as denied:
        _api_key_principal("temporary-operator-key", settings)
    assert denied.value.status_code == 503


def test_unconfigured_optional_registry_preserves_legacy_authentication():
    settings = Settings(
        auth_mode="api_key", api_key_sha256=sha("original-key"), api_key_subject="original"
    )
    assert _api_key_principal("original-key", settings).subject == "original"
    for key in [None, "", "wrong", "x" * 4097]:
        with pytest.raises(HTTPException) as denied:
            _api_key_principal(key, settings)
        assert denied.value.status_code == 401
