"""Full recovery of real signed context, including approval use and revocation.

The fixed clock proves old grants fail because restoration fences them, not because
an otherwise valid grant happened to expire during the test.
"""

import base64
import json
import shutil
import sqlite3
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.behavior_context_api import behavior_context_router
from app.behavior_context_models import (
    ApprovalCreate,
    BaselineCreate,
    ContextRevocation,
    SignedBehaviorCapture,
)
from app.models import SecurityEvent
from app.scenarios import synthetic_events
from app.security import get_principal
from app.services.behavior_context import BehaviorContextService
from app.services.behavior_context_store import BehaviorContextStore
from app.services.trusted_signals import SignalVerifier, canonical_signal
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import SignedSessionSignal
from scripts import app_state_recovery as recovery
from scripts import app_storage_contract as storage
from scripts.app_storage_fixture import seed_logs
from tests import test_behavior_context_integration as context_cases
from tests.test_behavior_context_integration import capture_bytes, signature

CONTEXT_NAME = "app-behavior-context.sqlite3"


@pytest.fixture
def recovery_context(tmp_path, monkeypatch):
    return context_cases.context_lab.__wrapped__(tmp_path, monkeypatch)


def seed(lab, *, max_uses=2):
    lab.baseline(approve=False)
    approval = ApprovalCreate(
        approval_id="approval-a", baseline_id="baseline-a", valid_from=lab.at(3),
        valid_until=lab.at(60), max_uses=max_uses, note="Reviewed bounded recurring maintenance",
        execution_policy=lab.policy(),
    )
    lab.service.create_approval(approval, lab.operator, now=lab.at(3))
    target = lab.capture("before-recovery", 4)
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(4))["verdict"] == "normal"
    return target, approval


def backup(lab, tmp_path, monkeypatch, *, full_state=False):
    root = tmp_path / "recovery"
    source = root / "data"
    source.mkdir(parents=True)
    for original, name in ((lab.operations_path, "app.sqlite3"),
                           (lab.store_path, CONTEXT_NAME), (lab.registry_path, "sources.json")):
        shutil.copyfile(original, source / name)
    lab.clock.now = lab.at(6)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return lab.clock.now.astimezone(tz) if tz else lab.clock.now.replace(tzinfo=None)

    monkeypatch.setattr(recovery, "datetime", Clock)
    if full_state:
        seed_logs(source)
    store = recovery.Store(root)
    store.initialize(full_state=full_state)
    store.checkpoint()
    saved = store.backup()
    return SimpleNamespace(root=root, source=source, store=store, saved=saved,
                           path=root / "backups" / (saved["backup_id"] + ".sealed"))


def restore(saved, lab):
    outcome = saved.store.restore(saved.saved["backup_id"])
    stage = saved.root / "restores" / outcome["restore_id"]
    operations = ZeroTrustOperations(stage / "app.sqlite3", signal_verifier=SignalVerifier(stage / "sources.json"))
    service = BehaviorContextService(BehaviorContextStore(stage / CONTEXT_NAME), operations)
    application = FastAPI()
    application.include_router(zero_trust_router(operations))
    application.include_router(behavior_context_router(service))
    application.dependency_overrides[get_principal] = lambda: lab.operator
    install_zero_trust_error_handlers(application)
    return SimpleNamespace(stage=stage, service=service, operations=operations,
                           client=TestClient(application), outcome=outcome)


def access(restored, result):
    return restored.client.post("/zero-trust/protected-access", json={
        "session_id": result.session.session_id, "resource_id": result.session.resource_id,
        "action": result.session.action, "grant_token": result.grant_token,
    })


def fresh_capture(restored, lab, name, offset):
    """Generate and verify new session authority after the restore fence."""
    instant = lab.at(offset)
    lab.clock.now = instant
    event = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
    event.update(event_id="session-event-" + name, timestamp=instant, action="READ")
    event["user"].update(user_id=lab.scope.user_id, role="employee", active=True)
    event["device"].update(device_id=lab.scope.device_id, managed=True, security_posture="healthy")
    event["resource"].update(resource_id=lab.scope.resource_id, required_role=None)
    event["auth_context"].update(authentication_result="success", mfa="success")
    signal = SignedSessionSignal(
        session_id="session-" + name, expected_version=0, event=SecurityEvent.model_validate(event),
        tenant_id="tenant-a", source_id="session", key_id="key-1", issued_at=instant,
        expires_at=instant + timedelta(seconds=90), signature="A" * 86,
    )
    signal = signal.model_copy(update={"signature": signature(lab.keys["session"], canonical_signal(signal))})
    session = restored.operations.evaluate_signed(signal, lab.operator, now=instant)
    assert session.session.status == "ACTIVE"
    connection = "credential-" + name
    request = SignedBehaviorCapture(
        tenant_id="tenant-a", capture_id="capture-" + name, source_id="behavior", key_id="key-1",
        issued_at=instant, expires_at=instant + timedelta(seconds=90), scope=lab.scope,
        session_id=session.session.session_id, session_version=session.session.version,
        session_input_sha256=session.session.input_digest_sha256, connection_ids=[connection],
        activity={"source": "cloudtrail", "original_group_id": "group-" + name,
                  "events": [{"id": f"event-{name}-{index}", "timestamp": instant,
                              "kind": "AwsApiCall", "api_service": "s3.amazonaws.com",
                              "api_action": "PutObject", "connection_id": connection,
                              "principal_hash": lab.scope.principal_hash,
                              "resource_hashes": [f"object-{index % 25}"], "outcome": "success"}
                             for index in range(100)]}, signature="A" * 86,
    )
    request = request.model_copy(update={"signature": signature(lab.keys["behavior"], capture_bytes(request))})
    restored.service.accept_capture(request, lab.analyst, now=instant)
    result = SimpleNamespace(request=request, session=session, id=request.capture_id)
    restored.service.accept_execution_evidence(lab.evidence(result), lab.analyst, now=instant)
    return result


@pytest.mark.parametrize("full_state", [False, True])
def test_nonempty_context_history_and_old_token_fence_survive_full_recovery(
    recovery_context, tmp_path, monkeypatch, full_state,
):
    lab = recovery_context
    target, approval = seed(lab)
    cancelled = approval.model_copy(update={"approval_id": "cancelled-maintenance"})
    lab.service.create_approval(cancelled, lab.operator, now=lab.at(3))
    lab.service.revoke("approval", cancelled.approval_id, ContextRevocation(reason="Work cancelled before execution"),
                       lab.operator, now=lab.at(5))
    original = lab.store.read(lab.operator.tenant_id)
    assert {entry["kind"] for entry in original} == {
        "capture", "baseline", "approval", "evaluation", "revocation", "execution",
    }
    saved = backup(lab, tmp_path, monkeypatch, full_state=full_state)
    source_bytes = {path.name: path.read_bytes() for path in saved.source.iterdir() if path.is_file()}
    encrypted = saved.path.read_bytes()
    assert b"SQLite format" not in encrypted and target.session.grant_token.encode() not in encrypted
    assert b"cancelled-maintenance" not in encrypted
    restored = restore(saved, lab)
    assert restored.service.store.read(lab.operator.tenant_id) == original
    if full_state:
        assert storage.inspect(restored.stage) == storage.inspect(saved.source)
        for name in ("storage.json", *storage.FILES.values()):
            assert (restored.stage / name).read_bytes() == source_bytes[name]
    assert lab.at(6) < target.request.expires_at
    assert access(restored, target.session).status_code == 403
    assert restored.service.evaluate(target.id, lab.analyst, now=lab.at(6))["verdict"] == "unknown"
    assert recovery.verify_admission(restored.stage, saved.store.public)["admission_verified"]
    reopened = BehaviorContextStore(restored.stage / CONTEXT_NAME)
    assert reopened.read(lab.operator.tenant_id)[:len(original)] == original
    assert {path.name: path.read_bytes() for path in saved.source.iterdir() if path.is_file()} == source_bytes


@pytest.mark.parametrize("max_uses", [1, 2])
def test_approval_consumption_is_not_reset_by_restore_or_restart(recovery_context, tmp_path, monkeypatch, max_uses):
    lab = recovery_context
    old, _ = seed(lab, max_uses=max_uses)
    saved = backup(lab, tmp_path, monkeypatch)
    restored = restore(saved, lab)
    assert access(restored, old.session).status_code == 403
    current = fresh_capture(restored, lab, "after-recovery", 7)
    verdict = restored.service.evaluate(current.id, lab.analyst, now=lab.at(7))
    assert verdict["verdict"] == ("normal" if max_uses == 2 else "unknown")
    repeated = restored.service.evaluate(current.id, lab.analyst, now=lab.at(8))
    assert repeated["duplicate"] is True and repeated["verdict"] == verdict["verdict"]
    assert access(restored, current.session).status_code == 200
    assert recovery.verify_admission(restored.stage, saved.store.public)["admission_verified"]
    restored.service = BehaviorContextService(BehaviorContextStore(restored.stage / CONTEXT_NAME), restored.operations)
    following = fresh_capture(restored, lab, "after-restart", 9)
    assert restored.service.evaluate(following.id, lab.analyst, now=lab.at(9))["verdict"] == "unknown"
    used = {entry["payload"]["capture_id"] for entry in restored.service.store.read(lab.operator.tenant_id)
            if entry["kind"] == "evaluation" and entry["payload"].get("verdict") == "normal"}
    assert len(used) == max_uses
    assert recovery.verify_admission(restored.stage, saved.store.public)["admission_verified"]


@pytest.mark.parametrize("kind,identifier", [("baseline", "baseline-a"), ("approval", "approval-a")])
def test_revoked_context_and_duplicate_identity_survive_recovery(recovery_context, tmp_path, monkeypatch, kind, identifier):
    lab = recovery_context
    seed(lab)
    request = next(entry["payload"]["request"] for entry in lab.store.read(lab.operator.tenant_id)
                   if entry["kind"] == kind and entry["record_id"] == identifier)
    lab.service.revoke(kind, identifier, ContextRevocation(reason="Approval withdrawn before recovery"),
                       lab.operator, now=lab.at(5))
    saved = backup(lab, tmp_path, monkeypatch)
    restored = restore(saved, lab)
    before = restored.service.store.read(lab.operator.tenant_id)
    model, method = ((BaselineCreate, restored.service.create_baseline) if kind == "baseline"
                     else (ApprovalCreate, restored.service.create_approval))
    result = method(model.model_validate(request), lab.operator, now=lab.at(7))
    assert result["duplicate"] and result["revoked"]
    assert restored.service.store.read(lab.operator.tenant_id) == before
    current = fresh_capture(restored, lab, "after-revocation", 7)
    assert restored.service.evaluate(current.id, lab.analyst, now=lab.at(7))["verdict"] == "unknown"
    assert recovery.verify_admission(restored.stage, saved.store.public)["admission_verified"]


@pytest.mark.parametrize("damage", ["deleted", "empty-replacement", "row-missing", "payload-changed", "valid-rehashed"])
def test_restored_context_damage_cannot_pass_admission(recovery_context, tmp_path, monkeypatch, damage):
    lab = recovery_context
    seed(lab)
    saved = backup(lab, tmp_path, monkeypatch)
    restored = restore(saved, lab)
    path = restored.stage / CONTEXT_NAME
    if damage == "valid-rehashed":
        entries = restored.service.store.read(lab.operator.tenant_id)
        next(entry for entry in entries if entry["kind"] == "approval")["payload"]["request"]["note"] = "Changed approved intent"
        path.unlink()
        replacement = BehaviorContextStore(path)
        with replacement.transaction() as transaction:
            for entry in entries:
                transaction.append(entry)
    elif damage in {"deleted", "empty-replacement"}:
        path.unlink()
        if damage == "empty-replacement":
            BehaviorContextStore(path)
    else:
        with sqlite3.connect(path) as db:
            if damage == "row-missing":
                db.execute("DELETE FROM behavior_context_entries WHERE kind='evaluation'")
            else:
                db.execute("UPDATE behavior_context_entries SET payload='{}' WHERE kind='approval'")
    with pytest.raises(recovery.RecoveryError):
        recovery.verify_admission(restored.stage, saved.store.public)


def test_restore_interruption_invalidates_prior_copy_and_retry_preserves_history(recovery_context, tmp_path, monkeypatch):
    lab = recovery_context
    seed(lab)
    expected = lab.store.read(lab.operator.tenant_id)
    saved = backup(lab, tmp_path, monkeypatch)
    previous = restore(saved, lab)
    original = recovery.atomic

    def fail_context_write(path, payload):
        if path.name == CONTEXT_NAME:
            raise OSError("injected context write interruption")
        return original(path, payload)

    monkeypatch.setattr(recovery, "atomic", fail_context_write)
    with pytest.raises(OSError, match="context write interruption"):
        restore(saved, lab)
    assert recovery.read_json(saved.store.public / "current.json")["restore_id"] is None
    with pytest.raises(recovery.RecoveryError):
        recovery.verify_admission(previous.stage, saved.store.public)
    partial = [path for path in (saved.root / "restores").iterdir() if path != previous.stage]
    assert len(partial) == 1 and not (partial[0] / "release.json").exists()
    monkeypatch.setattr(recovery, "atomic", original)
    retried = restore(saved, lab)
    assert retried.service.store.read(lab.operator.tenant_id) == expected
    assert recovery.verify_admission(retried.stage, saved.store.public)["admission_verified"]


def test_encrypted_context_backup_cannot_be_modified(recovery_context, tmp_path, monkeypatch):
    lab = recovery_context
    seed(lab)
    saved = backup(lab, tmp_path, monkeypatch)
    envelope = recovery.read_json(saved.path)
    ciphertext = bytearray(base64.b64decode(envelope["ciphertext"], validate=True))
    ciphertext[len(ciphertext) // 2] ^= 1
    envelope["ciphertext"] = base64.b64encode(ciphertext).decode()
    saved.path.write_text(json.dumps(envelope))
    with pytest.raises(recovery.RecoveryError, match="authentication"):
        restore(saved, lab)
    assert not list((saved.root / "restores").iterdir())


@pytest.mark.parametrize("mutation", ["missing", "digest", "valid-empty-replacement"])
def test_context_database_is_bound_to_authenticated_checkpoint(recovery_context, tmp_path, monkeypatch, mutation):
    lab = recovery_context
    seed(lab)
    saved = backup(lab, tmp_path, monkeypatch)
    envelope = recovery.read_json(saved.path)
    key = recovery.read_file(saved.store.control / "backup.key", 32)
    payload = recovery.opened(envelope, key)
    if mutation == "missing":
        payload.pop("behavior_context_database")
    elif mutation == "digest":
        raw = bytearray(base64.b64decode(payload["behavior_context_database"], validate=True))
        raw[-1] ^= 1
        payload["behavior_context_database"] = base64.b64encode(raw).decode()
    else:
        empty = tmp_path / "replacement.sqlite3"
        BehaviorContextStore(empty)
        raw = empty.read_bytes()
        payload["behavior_context_database"] = base64.b64encode(raw).decode()
        envelope["manifest"]["behavior_context_database_sha256"] = recovery.sha(raw)
    forged = recovery.sealed(payload, key, envelope["manifest"])
    saved.path.write_bytes(recovery.canonical(forged))
    with pytest.raises(recovery.RecoveryError):
        restore(saved, lab)
    assert all(not (path / "release.json").exists() for path in (saved.root / "restores").iterdir())
