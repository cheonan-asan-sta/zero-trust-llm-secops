"""Legacy local harnesses retain observed versions and authenticated identities."""

import asyncio
from contextlib import ExitStack

import pytest
from test_audit_query_admission import api as api  # noqa: PLC0414

from app import main
from scripts.audit_review_client import ReviewClientError
from scripts.f1_lab.audit_recovery_controls import run as run_recovery
from scripts.local_review_intent import LocalReviewClient, review_observed


def strict():
    main.settings.audit_review_require_if_match = True
    main.settings.audit_review_require_identity = True


def test_harness_reviews_exact_observed_record_under_required_policy(api):
    strict()
    response = review_observed(
        api.client,
        api.headers,
        api.first.model_dump(mode="json"),
        status="RESOLVED",
        note="Owned local acceptance",
    )
    assert response.status_code == 200
    assert response.json()["reviewer"] == "local-auditor"
    assert api.store.integrity()["verified_lines"] == 3


def test_harness_expected_record_mismatch_never_writes(api):
    strict()
    expected = api.first.model_dump(mode="json")
    expected["actor_id"] = "unexpected-local-actor"
    with pytest.raises(ReviewClientError, match="Observed record changed"):
        review_observed(api.client, api.headers, expected, status="RESOLVED", note="Do not write")
    assert api.store.integrity()["verified_lines"] == 2


@pytest.mark.parametrize("change", ["caller", "version", "withdraw"])
def test_snapshot_does_not_rebind_retry_or_overwrite(api, change):
    strict()
    operator = LocalReviewClient(api.client, api.headers)
    snapshot = operator.prepare(api.first.event_id)
    if change == "caller":
        main.settings.api_key_subject = "new-local-subject"
    elif change == "withdraw":
        api.withdraw()
    else:
        operator.review(snapshot, "IN_REVIEW", "Concurrent winning review")
    with pytest.raises(ReviewClientError):
        operator.review(snapshot, "RESOLVED", "Stale intent")
    expected_rows = 3 if change == "version" else 2
    assert api.store.integrity()["verified_lines"] == expected_rows


def test_required_policy_rejects_legacy_unbound_write(api):
    strict()
    response = api.client.patch(
        f"/results/{api.first.event_id}/review",
        headers=api.headers,
        json={"status": "RESOLVED", "note": "Legacy client"},
    )
    assert response.status_code == 428
    assert api.store.integrity()["verified_lines"] == 2


def test_actual_recovery_harness_can_review_under_required_policy(api, tmp_path):
    strict()
    contextual = api.first.model_copy(
        update={
            "analysis_id": "local-contextual-recovery-analysis",
            "event_id": "local-contextual-recovery-event",
            "verification_context": {"local_recovery_fixture": True},
        }
    )
    asyncio.run(api.store.save(contextual))
    passed = []
    with ExitStack() as stack:
        result = run_recovery(
            api.store,
            contextual.model_dump(mode="json"),
            api.client,
            api.headers,
            tmp_path,
            passed.append,
            stack,
        )
    assert result["original_database_unchanged"]
    assert result["candidate_review_head"]["seq"] == result["snapshot_head"]["seq"] + 1
    assert result["checkpoint"]["independent_storage_verified"] is False
    assert "native_audit_candidate_http_query_and_cas_review_preserve_advisory_assessment" in passed
