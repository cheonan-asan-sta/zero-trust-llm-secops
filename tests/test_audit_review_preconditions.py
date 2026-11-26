"""Bind a human review to the exact representation the client observed."""

import asyncio
from datetime import timedelta

import pytest
from pydantic import ValidationError
from test_audit_query_admission import api as api  # noqa: PLC0414

from app import main
from app.config import Settings
from app.models import AnalysisResult, ReviewStatus
from app.services.audit import AuditStore
from app.services.audit_review_preconditions import review_etag


def test_result_detail_returns_an_exact_representation_etag(api):
    first = api.client.get("/results/audit-cancel-1", headers=api.headers)
    second = api.client.get("/results/audit-cancel-1", headers=api.headers)
    assert first.status_code == second.status_code == 200
    tag = first.headers.get("ETag")
    assert tag is not None and tag.startswith('"') and tag.endswith('"')
    assert second.headers.get("ETag") == tag
    assert first.headers.get("Cache-Control") == "no-store"


def test_stale_client_review_is_rejected_without_rewriting_other_review(api):
    original = api.client.get("/results/audit-cancel-1", headers=api.headers)
    tag = original.headers.get("ETag", '"r1-' + "0" * 64 + '"')
    current = api.client.patch(
        "/results/audit-cancel-1/review",
        headers=api.headers,
        json={"status": "IN_REVIEW", "note": "another operator already started"},
    )
    assert current.status_code == 200
    before = api.store.integrity()["verified_lines"]
    stale = api.client.patch(
        "/results/audit-cancel-1/review",
        headers={**api.headers, "If-Match": tag},
        json={"status": "RESOLVED", "note": "stale screen must not overwrite review"},
    )
    assert stale.status_code == 412
    assert api.store.integrity()["verified_lines"] == before
    saved = api.store.get("audit-cancel-1", "local")
    assert saved.review_note == "another operator already started"


def test_matching_review_returns_new_etag_and_old_token_cannot_be_replayed(api):
    original = api.client.get("/results/audit-cancel-1", headers=api.headers)
    tag = original.headers["ETag"]
    payload = {"status": "IN_REVIEW", "note": "review exact observed representation"}
    current = api.client.patch(
        "/results/audit-cancel-1/review",
        headers={**api.headers, "If-Match": tag},
        json=payload,
    )
    assert current.status_code == 200 and current.headers["ETag"] != tag
    assert (
        current.headers["ETag"]
        == api.client.get(
            "/results/audit-cancel-1",
            headers=api.headers,
        ).headers["ETag"]
    )
    before = api.store.integrity()["verified_lines"]
    replayed = api.client.patch(
        "/results/audit-cancel-1/review",
        headers={**api.headers, "If-Match": tag},
        json=payload,
    )
    assert replayed.status_code == 412 and api.store.integrity()["verified_lines"] == before


def test_strict_policy_requires_a_tag_before_saving_and_accepts_matching_tag(api):
    main.settings.audit_review_require_if_match = True
    payload = {"status": "IN_REVIEW", "note": "review requires an observed version"}
    denied = api.client.patch("/results/audit-cancel-1/review", headers=api.headers, json=payload)
    assert denied.status_code == 428 and api.store.integrity()["verified_lines"] == 2
    tag = api.client.get("/results/audit-cancel-1", headers=api.headers).headers["ETag"]
    accepted = api.client.patch(
        "/results/audit-cancel-1/review",
        headers={**api.headers, "If-Match": tag},
        json=payload,
    )
    assert accepted.status_code == 200


def test_policy_enabled_during_final_authority_io_is_not_bypassed(api, monkeypatch):
    original = main._audit_boundary
    calls = 0

    async def change_policy(*args):
        nonlocal calls
        await original(*args)
        calls += 1
        if calls == 3:
            main.settings.audit_review_require_if_match = True

    monkeypatch.setattr(main, "_audit_boundary", change_policy)
    response = api.client.patch(
        "/results/audit-cancel-1/review",
        headers=api.headers,
        json={"status": "IN_REVIEW", "note": "policy became mandatory while validating"},
    )
    assert response.status_code == 428 and api.store.integrity()["verified_lines"] == 2


@pytest.mark.parametrize(
    "bad",
    [
        "*",
        'W/"r1-' + "0" * 64 + '"',
        '"r1-' + "A" * 64 + '"',
        "",
        "r1-" + "0" * 64,
        '"r1-' + "0" * 64 + '","r1-' + "1" * 64 + '"',
        "x" * 257,
    ],
)
def test_ambiguous_or_invalid_tags_never_read_or_write_the_audit(api, monkeypatch, bad):
    calls = []
    monkeypatch.setattr(api.store, "get", lambda *_: calls.append(True))
    response = api.client.patch(
        "/results/audit-cancel-1/review",
        headers={**api.headers, "If-Match": bad},
        json={"status": "IN_REVIEW", "note": "invalid version must be rejected"},
    )
    assert response.status_code == 400 and not calls
    assert api.store.integrity()["verified_lines"] == 2


def test_duplicate_if_match_headers_are_not_silently_reduced_to_one(api):
    tag = review_etag(api.first)
    response = api.client.patch(
        "/results/audit-cancel-1/review",
        headers=[*api.headers.items(), ("If-Match", tag), ("If-Match", tag)],
        json={"status": "IN_REVIEW", "note": "duplicate headers must be rejected"},
    )
    assert response.status_code == 400 and api.store.integrity()["verified_lines"] == 2


def test_if_match_never_reveals_another_tenants_result(api):
    response = api.client.patch(
        "/results/audit-cancel-2/review",
        headers={**api.headers, "If-Match": review_etag(api.first)},
        json={"status": "IN_REVIEW", "note": "no cross tenant review access"},
    )
    assert response.status_code == 404 and "ETag" not in response.headers
    assert api.store.integrity()["verified_lines"] == 2


def test_old_tag_cannot_review_new_analysis_with_same_event_id(api):
    tag = api.client.get("/results/audit-cancel-1", headers=api.headers).headers["ETag"]
    latest = api.first.model_copy(
        update={
            "analysis_id": "new-analysis-for-same-event",
            "analyzed_at": api.first.analyzed_at + timedelta(seconds=1),
        }
    )
    asyncio.run(api.store.save(latest))
    response = api.client.patch(
        "/results/audit-cancel-1/review",
        headers={**api.headers, "If-Match": tag},
        json={"status": "IN_REVIEW", "note": "stale screen selected another analysis"},
    )
    assert response.status_code == 412 and api.store.integrity()["verified_lines"] == 3
    assert api.store.get(latest.event_id, "local").review_updated_at is None


def test_conditional_sqlite_race_is_412_and_preserves_winning_review(api, monkeypatch):
    tag = api.client.get("/results/audit-cancel-1", headers=api.headers).headers["ETag"]
    original = api.store.save_review

    async def race(updated, expected):
        winner = expected.model_copy(
            update={
                "review_status": ReviewStatus.IN_REVIEW,
                "reviewer": "winning-reviewer",
                "review_note": "other writer committed first",
                "review_updated_at": expected.analyzed_at + timedelta(seconds=1),
            }
        )
        await original(winner, expected)
        await original(updated, expected)

    monkeypatch.setattr(api.store, "save_review", race)
    response = api.client.patch(
        "/results/audit-cancel-1/review",
        headers={**api.headers, "If-Match": tag},
        json={"status": "IN_REVIEW", "note": "losing writer must not overwrite"},
    )
    assert response.status_code == 412 and api.store.integrity()["verified_lines"] == 3
    assert api.store.get("audit-cancel-1", "local").reviewer == "winning-reviewer"


def test_jsonl_does_not_silently_claim_transactional_if_match_support(api, tmp_path, monkeypatch):
    store = AuditStore(tmp_path / "audit.jsonl")
    asyncio.run(store.save(api.first))
    monkeypatch.setattr(main, "audit_store", store)
    before = store._path.read_bytes()
    response = api.client.patch(
        "/results/audit-cancel-1/review",
        headers={**api.headers, "If-Match": review_etag(api.first)},
        json={"status": "IN_REVIEW", "note": "transactional condition cannot be ignored"},
    )
    assert response.status_code == 503 and store._path.read_bytes() == before


def test_required_conditional_review_configuration_needs_sqlite():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, audit_review_require_if_match=True)
    assert Settings(_env_file=None, audit_backend="sqlite", audit_review_require_if_match=True)


def test_etag_uses_serialized_json_and_distinguishes_boolean_from_number(api):
    first = api.first.model_copy(update={"llm_trace": {"tools": ("a",), "counts": {1: 2}}})
    restored = AnalysisResult.model_validate_json(first.model_dump_json())
    assert review_etag(first) == review_etag(restored)
    numeric = api.first.model_copy(update={"llm_trace": {"count": 1}})
    boolean = api.first.model_copy(update={"llm_trace": {"count": True}})
    assert review_etag(numeric) != review_etag(boolean)


@pytest.mark.parametrize("change,status", [("viewer", 403), ("revoked", 401)])
def test_etag_is_not_a_substitute_for_current_caller_authority(api, change, status):
    tag = api.client.get("/results/audit-cancel-1", headers=api.headers).headers["ETag"]
    if change == "viewer":
        main.settings.api_key_roles = "viewer"
    else:
        api.withdraw()
    response = api.client.patch(
        "/results/audit-cancel-1/review",
        headers={**api.headers, "If-Match": tag},
        json={"status": "IN_REVIEW", "note": "etag never grants responder authority"},
    )
    assert response.status_code == status and api.store.integrity()["verified_lines"] == 2
