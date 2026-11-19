"""The CLI's observed caller is checked by the server at the actual write."""

import asyncio
import copy

import pytest
from test_audit_query_admission import api as api  # noqa: PLC0414
from test_audit_review_client import operator as operator  # noqa: PLC0414
from test_audit_review_client import snapshot

from app import main
from app.services.audit import AuditStore
from scripts.audit_review_client import ReviewClientError, identity_binding


def test_same_key_remapped_after_final_who_cannot_commit_as_another_caller(operator):
    observed = snapshot(operator)
    before = operator.api.store.integrity()["verified_lines"]

    def remap_after_who(response):
        if str(response.url).endswith("/auth/me"):
            main.settings.api_key_subject = "remapped-after-cli-check"
        return response

    operator.opener.transform = remap_after_who
    with pytest.raises(ReviewClientError) as failure:
        operator.client.review(observed, "IN_REVIEW", "Must stay bound to the observed caller")
    assert operator.api.store.integrity()["verified_lines"] == before
    assert "HTTP 403" in str(failure.value)


def test_snapshot_v2_and_actual_patch_share_the_server_observed_binding(operator):
    observed = snapshot(operator)
    assert observed["schema"] == "operator-audit-review-snapshot-2"
    assert observed["review_mode"] == "conditional"
    assert observed["review_identity"] == identity_binding(observed["identity"])
    delivered = []

    def capture(response):
        if response.request.method == "PATCH":
            delivered.append(response.request.headers["x-review-identity"])
        return response

    operator.opener.transform = capture
    result = operator.client.review(observed, "IN_REVIEW", "Bound snapshot and real API review")
    assert delivered == [observed["review_identity"]]
    assert result.reviewer == observed["identity"]["subject"]


@pytest.mark.parametrize(
    "header,value,duplicate",
    [
        ("x-review-identity", None, False),
        ("x-review-identity", "", False),
        ("x-review-identity", "*", False),
        ("x-review-identity", "A" * 64, False),
        ("x-review-identity", "0" * 64, False),
        ("x-review-identity", None, True),
        ("x-review-mode", None, False),
        ("x-review-mode", "", False),
        ("x-review-mode", "unavailable", False),
        ("x-review-mode", "conditional,conditional", False),
        ("x-review-mode", None, True),
    ],
)
def test_bad_or_duplicate_read_metadata_cannot_produce_a_snapshot(
    operator, header, value, duplicate
):
    def change(response):
        if "/results/" in str(response.url):
            original = response.headers[header]
            pairs = [(key, val) for key, val in response.headers.multi_items() if key != header]
            if duplicate:
                pairs += [(header, original), (header, original)]
            elif value is not None:
                pairs.append((header, value))
            response.headers = type(response.headers)(pairs)
        return response

    operator.opener.transform = change
    with pytest.raises(ReviewClientError):
        snapshot(operator)
    assert not any(method == "PATCH" for method, _, _ in operator.opener.calls)
    assert operator.api.store.integrity()["verified_lines"] == 2


@pytest.mark.parametrize(
    "mutation", ["v1", "binding", "binding_type", "mode", "auth_method", "subject", "missing"]
)
def test_unsupported_or_inconsistent_snapshot_is_rejected_without_network(operator, mutation):
    observed = copy.deepcopy(snapshot(operator))
    if mutation == "v1":
        observed["schema"] = "operator-audit-review-snapshot-1"
        del observed["review_identity"], observed["review_mode"]
    elif mutation == "binding":
        observed["review_identity"] = "0" * 64
    elif mutation == "binding_type":
        observed["review_identity"] = [observed["review_identity"]]
    elif mutation == "mode":
        observed["review_mode"] = "unavailable"
    elif mutation == "auth_method":
        observed["identity"]["auth_method"] = "disabled"
    elif mutation == "subject":
        observed["identity"]["subject"] = "다른 검토자"
    else:
        del observed["review_identity"]
    before = len(operator.opener.calls)
    with pytest.raises(ReviewClientError) as failure:
        operator.client.review(observed, "IN_REVIEW", "No silent legacy snapshot upgrade")
    if mutation == "v1":
        assert "prepare and inspect a new snapshot" in str(failure.value)
    assert len(operator.opener.calls) == before


@pytest.mark.parametrize("kind", ["missing", "different", "duplicate"])
def test_commit_with_unverifiable_reply_binding_is_not_reported_as_success_or_retried(
    operator, kind
):
    observed = snapshot(operator)

    def change(response):
        if response.request.method == "PATCH":
            header = "x-review-identity"
            original = response.headers[header]
            pairs = [(key, val) for key, val in response.headers.multi_items() if key != header]
            if kind == "different":
                pairs.append((header, "0" * 64))
            elif kind == "duplicate":
                pairs += [(header, original), (header, original)]
            response.headers = type(response.headers)(pairs)
        return response

    operator.opener.transform = change
    with pytest.raises(ReviewClientError, match="caller binding mismatch"):
        operator.client.review(
            observed, "IN_REVIEW", "Server may commit before response is checked"
        )
    assert operator.api.store.integrity()["verified_lines"] == 3
    assert sum(method == "PATCH" for method, _, _ in operator.opener.calls) == 1
    operator.opener.transform = lambda response: response
    with pytest.raises(ReviewClientError, match="HTTP 412"):
        operator.client.review(observed, "IN_REVIEW", "Do not repeat an uncertain committed review")
    assert operator.api.store.integrity()["verified_lines"] == 3


def test_nontransactional_source_is_rejected_during_prepare(operator, tmp_path, monkeypatch):
    store = AuditStore(tmp_path / "nontransactional.jsonl")
    asyncio.run(store.save(operator.api.first))
    monkeypatch.setattr(main, "audit_store", store)
    before = store._path.read_bytes()
    with pytest.raises(ReviewClientError, match="Conditional review backend"):
        snapshot(operator)
    assert store._path.read_bytes() == before
    assert not any(method == "PATCH" for method, _, _ in operator.opener.calls)
