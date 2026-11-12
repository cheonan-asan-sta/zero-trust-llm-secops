import asyncio

import httpx
import pytest

from scripts import m6_shadow_assist as assist
from scripts.evaluate_m6_shadow import WireAudit, compare, run_provider, score_explanation

FACT = {"id": "ev-123", "kind": "source_validation", "detail": "The signature was rejected."}
REQUEST = assist.make_request("case-123", "unknown", [FACT])
RULE = {"verdict": "unknown", "reason": "identity_unconfirmed", "priority": "medium", "claims": []}
SCORE = {
    "family": "case_fixture", "expected_label": "threat",
    "expected_priority": "high", "required_kinds": ["source_validation"],
}
CLAIM = {"evidence_id": FACT["id"], "fact_code": FACT["kind"]}
PREPARED = [(SCORE, REQUEST, RULE)]


def test_shadow_grounding_checks_fact_kind_case_and_duplicates():
    wrong_kind = CLAIM | {"fact_code": "enforcement"}
    foreign_id = CLAIM | {"evidence_id": "ev-other"}
    answer = {"claims": [CLAIM, wrong_kind, foreign_id, CLAIM]}
    score = score_explanation(answer, REQUEST, SCORE["required_kinds"])
    assert score == {
        "grounded": False, "rendered": [FACT],
        "unsupported": [wrong_kind, foreign_id, CLAIM], "missing_key_evidence": [],
    }


def test_shadow_assistance_does_not_change_detection_and_errors_count_as_missing():
    response = {"status": "completed", "answer": {"priority": "high", "claims": [CLAIM]}}
    with_assistance = compare(PREPARED, {REQUEST["case_id"]: response})
    failed = compare(PREPARED, {REQUEST["case_id"]: {"status": "timeout"}})
    assert with_assistance["detection_both_arms"] == failed["detection_both_arms"]
    assert with_assistance["detection_both_arms"]["missed_threats"] == 1
    assert with_assistance["assisted"]["explanation_grounded_and_complete"] == 1
    assert with_assistance["assisted"]["priority_correct"] == 1
    assert failed["assisted"]["explanation_grounded_and_complete"] == 0
    assert failed["assisted"]["expected_high_not_ranked_high"] == 1


def test_shadow_wire_rejects_private_data_inserted_into_user_payload():
    audit = WireAudit(PREPARED)
    payload = assist.request_body(REQUEST, count=True)
    payload["input"][0]["content"] = '{"case_id":"case-123","expected_label":"threat"}'
    outgoing = httpx.Request("POST", assist.COUNT_URL, json=payload)
    with pytest.raises(ValueError, match="shadow_wire_unapproved"):
        asyncio.run(audit.check(outgoing))
    assert audit.summary()["unapproved_request_bodies_blocked"] == 1


def test_shadow_bad_preflight_never_sends_generation_request():
    async def bad_count(request):
        assert str(request.url) == assist.COUNT_URL
        return httpx.Response(429)

    receipts, execution = asyncio.run(run_provider(
        PREPARED, "mock-key", transport=httpx.MockTransport(bad_count),
    ))
    assert receipts[REQUEST["case_id"]]["stage"] == "token_preflight"
    assert execution["stop_reason"] == "token_preflight_failed"
    assert execution["wire"]["verified_token_count_requests"] == 1
    assert execution["wire"]["verified_generation_requests"] == 0
