"""Policy decisions retain their meaning across archived prefixes and restarts."""

import base64
import hashlib
import http.client
import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_observation_collector_process import running_api

from app.continuous_signal_models import SignedContinuousSignal
from app.scenarios import synthetic_events
from app.security import Principal, Role, get_principal
from app.services.continuous_signals import ContinuousSignalService
from app.services.policy_journal import JournalLimits
from app.services.signal_inbox import SignalInbox
from app.services.trusted_signals import SignalVerifier, canonical_observation, canonical_signal
from app.services.zero_trust import JournalUnavailable, SessionConflict, ZeroTrustOperations
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import (
    ProtectedAccessRequest,
    SessionRevocationRequest,
    SignedSessionSignal,
)

ROOT = Path(__file__).parents[1]


def logical(service):
    with service._transaction() as transaction:
        return json.loads(json.dumps(transaction[1]))


def fill(service, count):
    # Exercise the actual append/archive path with one SQLite transaction. A
    # separate HTTP request for every audit row would hide O(n²) test overhead.
    with service._transaction() as transaction:
        first = len(transaction[1])
        for index in range(count):
            service._append(transaction, {"kind": "access", "allowed": False,
                "tenant_id": "unrelated-tenant", "session_id": f"filler-{first + index}"})


def snapshot(service):
    with sqlite3.connect(service.path) as connection:
        tables = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )]
        return {name: connection.execute(f'SELECT * FROM "{name}" ORDER BY rowid').fetchall()
                for name in tables}


@pytest.fixture
def journal_lab(tmp_path):
    now = datetime.now(UTC) - timedelta(seconds=2)
    limits = JournalLimits(max_active_records=8, archive_batch_size=4,
                           max_archive_records=200, max_archive_segments=100)
    session_key, observation_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    principals = {tenant: Principal("operator", tenant, frozenset({Role.ADMIN}), "api_key")
                  for tenant in ("tenant-a", "tenant-b")}

    def public(key):
        return key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    registry = {"sources": []}
    for tenant in principals:
        for source, key, kinds in (("session-source", session_key, []),
                                   ("observation-source", observation_key, ["identity"])):
            registry["sources"].append({
                "tenant_id": tenant, "source_id": source, "observation_kinds": kinds,
                "user_ids": ["user-a", "user-b"], "device_ids": ["device-a", "device-b"],
                "roles": ["employee"], "keys": [{"key_id": "key-1", "public_key_pem": public(key),
                    "not_before": (now - timedelta(days=1)).isoformat(),
                    "not_after": (now + timedelta(days=1)).isoformat()}],
            })
    registry_path, path = tmp_path / "sources.json", tmp_path / "policy.sqlite3"

    def save():
        registry_path.write_text(json.dumps(registry), encoding="utf-8")

    save()

    def reopen(custom_limits=limits):
        return ZeroTrustOperations(path, signal_verifier=SignalVerifier(registry_path),
                                   journal_limits=custom_limits)

    service = reopen()

    def signal(session="session-a", *, tenant="tenant-a", user="user-a", device="device-a",
               version=0, at=None, event_id=None, active=True):
        at = at or now
        event = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
        event.update(event_id=event_id or f"{tenant}-{session}-{version}", timestamp=at)
        event["user"].update(user_id=user, role="employee", active=active)
        event["device"].update(device_id=device, managed=True, security_posture="healthy")
        event["resource"].update(resource_id="zt-demo-documents", required_role=None)
        event["auth_context"].update(authentication_result="success", mfa="success")
        request = SignedSessionSignal(
            session_id=session, expected_version=version, event=event, tenant_id=tenant,
            source_id="session-source", key_id="key-1", issued_at=at,
            expires_at=at + timedelta(seconds=90), signature="A" * 86,
        )
        signed = base64.urlsafe_b64encode(session_key.sign(canonical_signal(request))).decode().rstrip("=")
        return request.model_copy(update={"signature": signed})

    def create(session="session-a", *, operations=None, **kwargs):
        request = signal(session, **kwargs)
        return (operations or service).evaluate_signed(request, principals[request.tenant_id], now=request.issued_at)

    def observation(event_id="risk-observation", *, positive=False, at=None):
        at = at or now + timedelta(seconds=1)
        request = SignedContinuousSignal(
            tenant_id="tenant-a", event_id=event_id, source_id="observation-source", key_id="key-1",
            issued_at=at, expires_at=at + timedelta(seconds=90), observed_at=at,
            observation={"kind": "identity", "subject_id": "user-a", "active": True,
                         "authentication_result": "success" if positive else "failure"},
            signature="A" * 86,
        )
        signed = base64.urlsafe_b64encode(observation_key.sign(canonical_observation(request))).decode().rstrip("=")
        return request.model_copy(update={"signature": signed})

    def apply(request, operations=None):
        operations = operations or service
        proof = operations.signal_verifier.verify_observation(request, principals["tenant-a"], request.issued_at)
        return operations.apply_observation(request, proof.input_digest, now=request.issued_at)

    def access(token, *, session="session-a", tenant="tenant-a", operations=None):
        return (operations or service).access(ProtectedAccessRequest(
            session_id=session, resource_id="zt-demo-documents", action="READ", grant_token=token,
        ), principals[tenant], now=now + timedelta(seconds=3))

    def application(operations=None):
        app = FastAPI()
        app.include_router(zero_trust_router(operations or service))
        install_zero_trust_error_handlers(app)
        app.dependency_overrides[get_principal] = lambda: principals["tenant-a"]
        return app

    return SimpleNamespace(now=now, limits=limits, service=service, reopen=reopen, create=create,
                           signal=signal, observation=observation, apply=apply, access=access,
                           principals=principals, registry=registry, registry_path=registry_path,
                           save=save, application=application)


def test_default_archive_crosses_ten_thousand_then_evaluates_access_and_worker(journal_lab):
    lab = journal_lab
    service = lab.reopen(None)
    fill(service, 10020)
    storage = service.journal_status()
    assert storage["total_records"] == 10020
    assert storage["active_records"] <= 10000 and storage["archived_records"] > 0
    first = lab.create(operations=service)
    inbox = SignalInbox(service.path)
    worker = ContinuousSignalService(service, inbox)
    request = lab.observation()
    assert worker.accept(request, lab.principals["tenant-a"], now=request.issued_at)["state"] == "pending"
    assert worker.process_one(now=request.issued_at)["state"] == "completed"
    assert lab.access(first.grant_token, operations=service).reason_code == "SESSION_NOT_AUTHORIZED"
    assert service.history("session-a", lab.principals["tenant-a"])[-1].version == 2
    assert service.integrity()["verified_entries"] > 10020
    assert service.journal_status()["active_records"] <= 10000


def test_archived_consumption_revocation_and_tenant_history_survive_compaction(journal_lab):
    lab = journal_lab
    consumed = lab.create()
    assert lab.access(consumed.grant_token).allowed
    revoked = lab.create("revoked-session", user="user-b", device="device-b")
    lab.service.revoke("revoked-session", SessionRevocationRequest(expected_version=1, note="explicit revocation"),
                       lab.principals["tenant-a"], now=lab.now + timedelta(seconds=1))
    other = lab.create(tenant="tenant-b")
    histories = {tenant: lab.service.history("session-a", principal)
                 for tenant, principal in lab.principals.items()}
    fill(lab.service, 25)
    before = logical(lab.service)
    result = lab.service.compact_journal()
    assert isinstance(result, dict) and result["archived_records"] > 0
    assert logical(lab.service) == before
    restarted = lab.reopen()
    for tenant, principal in lab.principals.items():
        assert restarted.history("session-a", principal) == histories[tenant]
    assert lab.access(consumed.grant_token, operations=restarted).reason_code == "GRANT_ALREADY_USED"
    assert lab.access(revoked.grant_token, session="revoked-session", operations=restarted).reason_code == "SESSION_NOT_AUTHORIZED"
    assert not lab.access(consumed.grant_token, tenant="tenant-b", operations=restarted).allowed
    assert lab.access(other.grant_token, tenant="tenant-b", operations=restarted).allowed
    assert restarted.integrity()["ok"]


def test_archived_evaluation_is_idempotent_and_changed_reuse_is_http_409(journal_lab):
    lab = journal_lab
    request = lab.signal()
    lab.service.evaluate_signed(request, lab.principals["tenant-a"], now=lab.now)
    fill(lab.service, 20)
    lab.service.compact_journal()
    before = lab.service.integrity()["verified_entries"]
    with TestClient(lab.application(lab.reopen())) as client:
        duplicate = client.post("/zero-trust/signals/evaluate", json=request.model_dump(mode="json"))
        assert duplicate.status_code == 200
        assert duplicate.json()["duplicate"] and duplicate.json()["grant_token"] is None
        changed = lab.signal(active=False)
        assert client.post("/zero-trust/signals/evaluate", json=changed.model_dump(mode="json")).status_code == 409
    assert lab.service.integrity()["verified_entries"] == before


def test_archived_adverse_observation_remains_sticky_for_new_sessions(journal_lab):
    lab = journal_lab
    first = lab.create()
    adverse = lab.observation()
    assert lab.apply(adverse)["changed_sessions"] == 1
    fill(lab.service, 20)
    lab.service.compact_journal()
    restarted = lab.reopen()
    assert lab.apply(lab.observation("positive", positive=True, at=lab.now + timedelta(seconds=2)),
                     operations=restarted)["changed_sessions"] == 0
    newer = lab.create("new-session", at=lab.now + timedelta(seconds=3), operations=restarted)
    assert newer.session.status == "REVOKED" and newer.grant_token is None
    assert lab.access(first.grant_token, operations=restarted).reason_code == "SESSION_NOT_AUTHORIZED"
    assert len(restarted.history("session-a", lab.principals["tenant-a"])) == 2


def test_archived_marker_reconciles_final_attempt_after_key_revocation(journal_lab):
    lab = journal_lab
    first = lab.create()
    inbox = SignalInbox(lab.service.path, max_attempts=1, lease_seconds=1)
    worker = ContinuousSignalService(lab.service, inbox)
    request = lab.observation()
    worker.accept(request, lab.principals["tenant-a"], now=request.issued_at)
    assert inbox.claim(now=request.issued_at)["attempts"] == 1
    # Effects commit while the receiver's completion ACK remains unknown.
    assert lab.apply(request)["changed_sessions"] == 1
    fill(lab.service, 20)
    lab.service.compact_journal()
    next(source for source in lab.registry["sources"]
         if source["tenant_id"] == "tenant-a" and source["source_id"] == "observation-source")["keys"][0]["enabled"] = False
    lab.save()
    restarted = lab.reopen()
    recovered = ContinuousSignalService(restarted, inbox).process_one(now=request.issued_at + timedelta(seconds=2))
    assert recovered["state"] == "completed"
    assert recovered["result"]["duplicate"] and recovered["result"]["changed_sessions"] == 0
    digest = hashlib.sha256(canonical_observation(request)).hexdigest()
    assert restarted.observation_result("tenant-b", request.event_id, digest) is None
    assert len(restarted.history("session-a", lab.principals["tenant-a"])) == 2
    assert lab.access(first.grant_token, operations=restarted).reason_code == "SESSION_NOT_AUTHORIZED"


@pytest.mark.parametrize("bound", ["archive_records", "archive_segments"])
def test_archive_limit_refuses_atomic_observation_fanout_without_partial_effects(journal_lab, bound):
    lab = journal_lab
    limits = JournalLimits(max_active_records=4, archive_batch_size=2,
                           max_archive_records=2 if bound == "archive_records" else 100,
                           max_archive_segments=1 if bound == "archive_segments" else 100)
    service = lab.reopen(limits)
    first = lab.create(operations=service).session
    second = lab.create("second-session", operations=service).session
    fill(service, 3)
    before = snapshot(service)
    with pytest.raises(JournalUnavailable):
        lab.apply(lab.observation(), operations=service)
    assert snapshot(service) == before
    assert service.history("session-a", lab.principals["tenant-a"])[-1] == first
    assert service.history("second-session", lab.principals["tenant-a"])[-1] == second


def test_archiving_does_not_raise_the_session_version_limit(journal_lab):
    lab = journal_lab
    first = lab.create().session
    capped = first.model_copy(update={"version": 200, "event_id": "session-capacity-marker"})
    with lab.service._transaction() as transaction:
        lab.service._append(transaction, {"kind": "decision", "session": capped.model_dump(mode="json"),
                                          "grant_hash": None})
    fill(lab.service, 20)
    lab.service.compact_journal()
    with pytest.raises(SessionConflict):
        lab.create(version=200, at=lab.now + timedelta(seconds=1), operations=lab.reopen())
    assert lab.service.history("session-a", lab.principals["tenant-a"])[-1] == capped


def test_compaction_and_single_use_access_serialize_with_actual_sqlite(journal_lab):
    lab = journal_lab
    first = lab.create()
    fill(lab.service, 25)
    barrier = Barrier(4)

    def run(index):
        service = lab.reopen()
        barrier.wait(timeout=5)
        return (lab.access(first.grant_token, operations=service) if index < 2
                else service.compact_journal())

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(run, range(4)))
    assert sum(result.allowed for result in results[:2]) == 1
    assert lab.access(first.grant_token).reason_code == "GRANT_ALREADY_USED"
    assert len(lab.service.history("session-a", lab.principals["tenant-a"])) == 1
    assert lab.service.integrity()["ok"]


@pytest.mark.parametrize("boundary", ["before_commit", "after_commit"])
def test_compact_cli_process_death_preserves_denial_over_real_http(journal_lab, boundary):
    lab = journal_lab
    consumed = lab.create()
    assert lab.access(consumed.grant_token).allowed
    revoked = lab.create("revoked-session", user="user-b", device="device-b")
    lab.service.revoke("revoked-session", SessionRevocationRequest(expected_version=1, note="operator stop"),
                       lab.principals["tenant-a"], now=lab.now + timedelta(seconds=1))
    fill(lab.service, 8)
    before = logical(lab.service)
    code = """
import os,sqlite3,sys
from app.services.zero_trust import ZeroTrustOperations
from scripts.policy_journal import main
active=False
connect=sqlite3.connect
class FaultConnection(sqlite3.Connection):
 def execute(self,sql,*args,**kwargs):
  result=super().execute(sql,*args,**kwargs)
  if active and BOUNDARY=='before_commit' and sql.lstrip().upper().startswith('DELETE FROM JOURNAL '):os._exit(73)
  return result
def fault_connect(*args,**kwargs):
 kwargs['factory']=FaultConnection
 return connect(*args,**kwargs)
sqlite3.connect=fault_connect
compact=ZeroTrustOperations.compact_journal
def fault_compact(self,*args,**kwargs):
 global active
 active=True
 result=compact(self,*args,**kwargs)
 if BOUNDARY=='after_commit':os._exit(73)
 return result
ZeroTrustOperations.compact_journal=fault_compact
raise SystemExit(main(['compact','--database',sys.argv[1],'--limit','2']))
""".replace("BOUNDARY", repr(boundary))
    child = subprocess.run([sys.executable, "-c", code, str(lab.service.path)], cwd=ROOT,
        env=os.environ | {"APP_ENVIRONMENT": "test", "ANALYZER_MODE": "rule"},
        capture_output=True, text=True, timeout=15, check=False)
    assert child.returncode == 73
    restarted = lab.reopen()
    assert logical(restarted) == before
    restarted.compact_journal()
    with running_api(lab.application(restarted)) as port:
        for session, token, reason in (("session-a", consumed.grant_token, "GRANT_ALREADY_USED"),
                                       ("revoked-session", revoked.grant_token, "SESSION_NOT_AUTHORIZED")):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                connection.request("POST", "/zero-trust/protected-access", json.dumps({
                    "session_id": session, "resource_id": "zt-demo-documents", "action": "READ", "grant_token": token,
                }), {"Content-Type": "application/json"})
                response = connection.getresponse()
                result = json.loads(response.read())
                assert response.status == 403 and result["reason_code"] == reason
                assert result["content"] is None
            finally:
                connection.close()
