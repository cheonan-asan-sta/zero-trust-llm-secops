"""Execution facts are separate authority, never inferred from permission or a label."""

import pytest

from app.behavior_context_models import ApprovalCreate
from app.services.behavior_context import BehaviorContextService
from app.services.behavior_context_store import BehaviorContextStore, ContextRecordConflict
from app.services.trusted_signals import SignalRejected, SignalVerifier
from app.services.zero_trust import ZeroTrustOperations
from tests import test_behavior_context_integration as context_cases


@pytest.fixture
def context_lab(tmp_path, monkeypatch):
    return context_cases.context_lab.__wrapped__(tmp_path, monkeypatch)


def evaluate(lab, target, offset=6):
    return lab.service.evaluate(target.id, lab.analyst, now=lab.at(offset))


def test_legacy_permission_without_execution_policy_cannot_prove_normal(context_lab):
    lab = context_lab
    lab.baseline(execution_policy=False)
    target = lab.capture("legacy", 4)
    result = evaluate(lab, target)
    assert result["verdict"] == "unknown" and result["reason"] == "EXECUTION_POLICY_REQUIRED"


def test_valid_approval_without_observed_execution_holds(context_lab):
    lab = context_lab
    lab.baseline()
    target = lab.capture("missing", 4, execution=False)
    result = evaluate(lab, target)
    assert result["verdict"] == "unknown" and result["reason"] == "EXECUTION_EVIDENCE_REQUIRED"


@pytest.mark.parametrize("missing", ["actor", "destinations"])
def test_missing_execution_fact_is_preserved_and_held(context_lab, missing):
    lab = context_lab
    lab.baseline()
    target = lab.capture("incomplete", 4, execution=False)
    proof = lab.evidence(target, **{missing: None})
    lab.service.accept_execution_evidence(proof, lab.analyst, now=lab.at(4))
    result = evaluate(lab, target)
    assert result["verdict"] == "unknown" and result["execution_status"] == "incomplete"
    saved = next(entry for entry in lab.store.read(lab.operator.tenant_id) if entry["kind"] == "execution")
    assert saved["payload"]["evidence"][missing] is None


@pytest.mark.parametrize("field,value", [
    ("principal_id", "different-principal"), ("workload_id", "different-job"),
    ("executable_sha256", "b" * 64),
])
def test_verified_execution_actor_mismatch_detected_without_grant_mutation(context_lab, field, value):
    lab = context_lab
    lab.baseline()
    target = lab.capture("actor-mismatch", 4, execution=False)
    proof = lab.evidence(target, actor=lab.policy()["actor"] | {field: value})
    lab.service.accept_execution_evidence(proof, lab.analyst, now=lab.at(4))
    before = lab.operations.journal_status()
    result = evaluate(lab, target)
    assert result["verdict"] == "threat" and result["reason"] == "EXECUTION_SCOPE_MISMATCH"
    assert result["execution_evidence_ids"] == [proof.evidence_id]
    assert result["enforcement_eligible"] is False
    assert lab.operations.journal_status() == before
    assert lab.access(target.session).status_code == 200


@pytest.mark.parametrize("destinations", [
    [{"kind": "https", "host": "other.example.test", "port": 443, "path": "/backup"}],
    [{"kind": "https", "host": "archive.example.test", "port": 8443, "path": "/backup"}],
    [{"kind": "https", "host": "archive.example.test", "port": 443, "path": "/other"}],
    [{"kind": "s3", "host": "other-bucket", "port": None, "path": "/backup"}],
])
def test_verified_destination_mismatch_detected(context_lab, destinations):
    lab = context_lab
    lab.baseline()
    target = lab.capture("destination-mismatch", 4, execution=False)
    proof = lab.evidence(target, destinations=destinations)
    lab.service.accept_execution_evidence(proof, lab.analyst, now=lab.at(4))
    assert evaluate(lab, target)["verdict"] == "threat"


def test_every_reported_destination_must_be_authorized(context_lab):
    lab = context_lab
    lab.baseline()
    target = lab.capture("extra-destination", 4, execution=False)
    destinations = lab.policy()["destinations"] + [
        {"kind": "https", "host": "other.example.test", "port": 443, "path": "/backup"},
    ]
    lab.service.accept_execution_evidence(lab.evidence(target, destinations=destinations),
                                          lab.analyst, now=lab.at(4))
    assert evaluate(lab, target)["verdict"] == "threat"


def test_expired_or_revoked_execution_evidence_cannot_keep_normal(context_lab):
    lab = context_lab
    lab.baseline()
    target = lab.capture("expires", 4, execution=False)
    proof = lab.evidence(target, expires_at=lab.at(5))
    lab.service.accept_execution_evidence(proof, lab.analyst, now=lab.at(4))
    assert evaluate(lab, target, 4)["verdict"] == "normal"
    assert evaluate(lab, target)["reason"] == "EXECUTION_EVIDENCE_STALE"
    other = lab.capture("key-retired", 7)
    assert evaluate(lab, other, 7)["verdict"] == "unknown"  # approval quota was already consumed
    # Re-evaluating the already admitted capture also cannot bypass a retired source.
    lab.registry["sources"][-1]["keys"][0]["enabled"] = False
    lab.save()
    assert evaluate(lab, target, 4)["reason"] == "EXECUTION_EVIDENCE_STALE"


def test_conflicting_reports_never_select_the_favourable_one(context_lab):
    lab = context_lab
    lab.baseline()
    target = lab.capture("conflict", 4)
    other = lab.evidence(target, evidence_id="different-report",
                         actor=lab.policy()["actor"] | {"workload_id": "other-job"})
    lab.service.accept_execution_evidence(other, lab.analyst, now=lab.at(4))
    result = evaluate(lab, target)
    assert result["verdict"] == "unknown" and result["reason"] == "EXECUTION_EVIDENCE_CONFLICT"


@pytest.mark.parametrize("field,value", [
    ("session_version", 2), ("session_input_sha256", "b" * 64),
    ("capture_input_sha256", "c" * 64), ("connection_ids", ["wrong-connection"]),
    ("event_ids", ["event-binding-0"]),
])
def test_reusing_report_for_different_or_partial_capture_is_rejected(context_lab, field, value):
    lab = context_lab
    lab.baseline()
    target = lab.capture("binding", 4, execution=False)
    proof = lab.evidence(target, **{field: value})
    with pytest.raises(SignalRejected):
        lab.service.accept_execution_evidence(proof, lab.analyst, now=lab.at(4))
    assert evaluate(lab, target)["verdict"] == "unknown"


def test_exact_response_loss_retry_and_restart_preserve_one_record(context_lab):
    lab = context_lab
    lab.baseline()
    target = lab.capture("retry", 4, execution=False)
    proof = lab.evidence(target)
    receipt = lab.service.accept_execution_evidence(proof, lab.analyst, now=lab.at(4))
    before = lab.store.read(lab.operator.tenant_id)
    reopened = BehaviorContextService(BehaviorContextStore(lab.store_path),
        ZeroTrustOperations(lab.operations_path, signal_verifier=SignalVerifier(lab.registry_path)))
    repeated = reopened.accept_execution_evidence(proof, lab.analyst, now=lab.at(5))
    assert repeated == receipt | {"duplicate": True}
    assert reopened.store.read(lab.operator.tenant_id) == before
    assert reopened.evaluate(target.id, lab.analyst, now=lab.at(5))["verdict"] == "normal"
    with pytest.raises(ContextRecordConflict):
        reopened.accept_execution_evidence(lab.evidence(target, actor=None), lab.analyst, now=lab.at(5))


def test_invalid_permission_does_not_turn_execution_difference_into_intrusion(context_lab):
    lab = context_lab
    lab.baseline(approval_until=5)
    target = lab.capture("expired-permission", 4, execution=False)
    proof = lab.evidence(target, actor=lab.policy()["actor"] | {"workload_id": "other-job"})
    lab.service.accept_execution_evidence(proof, lab.analyst, now=lab.at(4))
    assert evaluate(lab, target)["verdict"] == "unknown"


def test_matching_alternative_prior_permission_is_not_false_alarm(context_lab):
    lab = context_lab
    lab.baseline()
    replacement = lab.policy()["actor"] | {"workload_id": "another-approved-job"}
    lab.service.create_approval(ApprovalCreate(
        approval_id="second-permission", baseline_id="baseline-a", valid_from=lab.at(3),
        valid_until=lab.at(60), note="Second explicitly authorized workload",
        execution_policy=lab.policy() | {"actor": replacement},
    ), lab.operator, now=lab.at(3))
    target = lab.capture("second-workload", 4, execution=False)
    lab.service.accept_execution_evidence(lab.evidence(target, actor=replacement),
                                          lab.analyst, now=lab.at(4))
    result = evaluate(lab, target)
    assert result["verdict"] == "normal" and result["approval_id"] == "second-permission"


def test_eligible_legacy_permission_keeps_mismatch_ambiguous(context_lab):
    lab = context_lab
    lab.baseline()
    lab.service.create_approval(ApprovalCreate(
        approval_id="legacy-alternative", baseline_id="baseline-a", valid_from=lab.at(3),
        valid_until=lab.at(60), note="Older authority without execution detail",
    ), lab.operator, now=lab.at(3))
    target = lab.capture("ambiguous-workload", 4, execution=False)
    lab.service.accept_execution_evidence(lab.evidence(
        target, actor=lab.policy()["actor"] | {"workload_id": "unresolved-job"},
    ), lab.analyst, now=lab.at(4))
    result = evaluate(lab, target)
    assert result["verdict"] == "unknown" and result["reason"] == "EXECUTION_POLICY_REQUIRED"


def test_execution_api_does_not_accept_unprivileged_or_unsigned_facts(context_lab):
    from app.security import Principal, Role, get_principal

    lab = context_lab
    target = lab.capture("api-proof", 4, execution=False)
    lab.clock.now = lab.at(4)
    request = lab.evidence(target).model_dump(mode="json")
    lab.app.dependency_overrides[get_principal] = lambda: Principal(
        "read-only", lab.operator.tenant_id, frozenset({Role.VIEWER}), "test",
    )
    assert lab.client.post("/detections/context/execution-evidence", json=request).status_code == 403
    lab.app.dependency_overrides[get_principal] = lambda: lab.analyst
    request["signature"] = "A" * 86
    assert lab.client.post("/detections/context/execution-evidence", json=request).status_code == 403
