from types import SimpleNamespace

from scripts.replay_hybrid_development import load_published
from scripts.replay_remote_disagreements import compare_routes, review_reason, run


def test_development_report_keeps_baseline_and_counts_new_false_positives(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline replay must not construct a provider")

    monkeypatch.setattr("app.analyzers.hybrid.OpenAIAnalyzer", forbidden)
    report = run(tmp_path / "report")
    assert report["cases"] == 360
    assert report["queued_source_false_negatives"] == 17
    assert report["queued_normal_cases"] == 18
    assert report["fresh_provider_requests"] == 0
    assert report["runtime_adoption"] is report["independent_acceptance"] is False

    simulations = report["binary_promotion_simulations"]
    unconditional = simulations["all_disagreements"]
    claim_filtered = simulations["excluding_event_supplied_scoped_claims"]
    assert unconditional["reference"]["FN"] == 17
    assert unconditional["candidate"]["FP"] == 23
    assert unconditional["candidate"]["FN"] == claim_filtered["candidate"]["FN"] == 0
    assert len(unconditional["new_FP_ids"]) == 17
    assert claim_filtered["new_FP_ids"] == claim_filtered["lost_TP_ids"] == []


def test_scoped_claim_still_requires_review_and_transport_alone_does_not_route():
    _, _, rows, cases = load_published()
    row = next(row for row in rows if row["family_id"] == "remote-approved-support")
    event = cases[row["id"]].event

    assert review_reason(event, False, True) == "scoped_claim_requires_issuer_verification"
    assert review_reason(event, None, True) == "scoped_claim_requires_issuer_verification"
    assert review_reason(event.model_copy(update={"action": "LOGIN"}), False, True) is None
    assert review_reason(event, True, True) is None
    assert review_reason(event, False, False) is None

    without_claim = event.model_copy(
        update={
            "behavior": event.behavior.model_copy(
                update={
                    "policy_exception": None,
                    "policy_exception_approved": False,
                }
            ),
        }
    )
    assert review_reason(without_claim, False, True) == "approval_requires_verification"

    # Issuer truth is not visible in either submitted event. Keep both in the review queue.
    source = [
        dict(row, id="unverified-claim-on-threat", truth=True, prediction=False),
        dict(row, id="missing-claim-on-normal", truth=False, prediction=False),
    ]
    controls = {
        source[0]["id"]: SimpleNamespace(event=event),
        source[1]["id"]: SimpleNamespace(event=without_claim),
    }
    rule_rows = [{"id": item["id"], "prediction": True} for item in source]
    report = compare_routes(source, controls, rule_rows)
    assert len(report["review_queue"]) == 2
    filtered = report["binary_promotion_simulations"]["excluding_event_supplied_scoped_claims"]
    assert filtered["new_FP_ids"] == ["missing-claim-on-normal"]
    assert filtered["candidate"]["FN"] == 1
