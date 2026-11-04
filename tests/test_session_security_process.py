"""Bounded security-only session tails survive processes, archives and HTTP access."""

import base64
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_observation_collector_process import running_api

from app.continuous_signal_models import SignedContinuousSignal
from app.scenarios import synthetic_events
from app.security import Principal, Role, get_principal
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import SignalInbox
from app.services.trusted_signals import SignalVerifier, canonical_observation, canonical_signal
from app.services.zero_trust import SessionConflict, ZeroTrustOperations
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import SessionDecision, SessionRevocationRequest, SignedSessionSignal

ROOT = Path(__file__).parents[1]
BASE = "/zero-trust/signals/inbox"


@pytest.fixture
def security_lab(tmp_path):
    now = datetime.now(UTC) - timedelta(seconds=5)
    keys = {name: Ed25519PrivateKey.generate() for name in ("idp", "independent-idp", "observer")}
    principals = {tenant: Principal("operator", tenant, frozenset({Role.ADMIN}), "api_key")
                  for tenant in ("tenant-a", "tenant-b")}
    registry = {"sources": []}
    for tenant, names in (("tenant-a", keys), ("tenant-b", ("idp",))):
        for name in names:
            registry["sources"].append({
                "tenant_id": tenant, "source_id": name, "observation_kinds": (
                    ["identity", "device"] if name == "observer" else []),
                "user_ids": ["user-a", "user-b"], "device_ids": ["device-a", "device-b"],
                "roles": ["employee"], "keys": [{"key_id": "key-1", "public_key_pem": keys[name].public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
                    "not_before": (now - timedelta(days=1)).isoformat(),
                    "not_after": (now + timedelta(days=1)).isoformat()}],
            })
    path, database = tmp_path / "sources.json", tmp_path / "sessions.sqlite3"

    def save():
        temporary = path.with_suffix(".next")
        temporary.write_text(json.dumps(registry), encoding="utf-8")
        temporary.replace(path)

    save()

    def reopen():
        return ZeroTrustOperations(database, signal_verifier=SignalVerifier(path))

    operations = reopen()

    def signed(session="session-a", *, version=0, tenant="tenant-a", user="user-a",
               device="device-a", source="idp", at=None):
        at = at or now + timedelta(microseconds=version)
        event = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
        event.update(event_id=f"{tenant}-{session}-{version}", timestamp=at)
        event["user"].update(user_id=user, role="employee", active=True)
        event["device"].update(device_id=device, managed=True, security_posture="healthy")
        event["auth_context"].update(authentication_result="success", mfa="success")
        event["resource"].update(resource_id="zt-demo-documents", required_role=None)
        signal = SignedSessionSignal(session_id=session, expected_version=version, event=event,
            tenant_id=tenant, source_id=source, key_id="key-1", issued_at=at,
            expires_at=at + timedelta(seconds=120), signature="A" * 86)
        signal.signature = base64.urlsafe_b64encode(keys[source].sign(canonical_signal(signal))).decode().rstrip("=")
        return signal

    def create(session="session-a", **options):
        signal = signed(session, **options)
        return operations.evaluate_signed(signal, principals[signal.tenant_id], now=signal.issued_at)

    def legacy_allow_200(session="session-a"):
        """Explicit legacy fixture, not 200 successful current-policy evaluations.

        Preserve a real, unspent and unexpired grant and every version. Version
        200 ALLOW was writable by the older implementation and must remain readable.
        """
        result = create(session)
        with operations._transaction() as transaction:
            entry = transaction[1][-1]
            for version in range(2, 201):
                state = SessionDecision.model_validate(result.session.model_dump() | {
                    "version": version, "event_id": f"legacy-{session}-{version}",
                })
                operations._append(transaction, {"kind": "decision", "session": state.model_dump(mode="json"),
                                                 "grant_hash": entry["grant_hash"]})
        return result

    def observation(event="risk", *, kind="identity", posture="compromised", at=None, positive=False):
        at = at or now + timedelta(seconds=1)
        claim = ({"kind": "identity", "subject_id": "user-a", "active": True,
                  "authentication_result": "success" if positive else "failure"} if kind == "identity"
                 else {"kind": "device", "subject_id": "device-a", "managed": True,
                       "security_posture": posture})
        signal = SignedContinuousSignal(tenant_id="tenant-a", event_id=event, source_id="observer",
            key_id="key-1", issued_at=at, expires_at=at + timedelta(seconds=90), observed_at=at,
            observation=claim, signature="A" * 86)
        signal.signature = base64.urlsafe_b64encode(keys["observer"].sign(canonical_observation(signal))).decode().rstrip("=")
        return signal

    def inbox(max_attempts=1):
        return SignalInbox(database, max_attempts=max_attempts, lease_seconds=1, retry_seconds=.01)

    def worker(max_attempts=1, service=None):
        return ContinuousSignalService(service or operations, inbox(max_attempts))

    def apply(signal):
        service = worker()
        service.accept(signal, principals["tenant-a"], now=signal.issued_at)
        return service.process_one(now=signal.issued_at)

    def history(session="session-a", tenant="tenant-a", service=None):
        return (service or operations).history(session, principals[tenant])

    def application(service=None, tenant="tenant-a", max_attempts=1):
        service = service or operations
        app = FastAPI()
        app.include_router(zero_trust_router(service, worker(max_attempts, service)))
        install_zero_trust_error_handlers(app)
        app.dependency_overrides[get_principal] = lambda: principals[tenant]
        return app

    def disable(source="idp"):
        next(item for item in registry["sources"] if item["tenant_id"] == "tenant-a"
             and item["source_id"] == source)["keys"][0]["enabled"] = False
        save()

    environment = os.environ | {"APP_ENVIRONMENT": "test", "ANALYZER_MODE": "rule",
        "ZERO_TRUST_DB_PATH": str(database), "TRUSTED_SIGNAL_SOURCES_PATH": str(path),
        "SIGNAL_INBOX_LEASE_SECONDS": "1", "SIGNAL_INBOX_RETRY_SECONDS": "0.01"}
    return SimpleNamespace(now=now, operations=operations, principals=principals, signed=signed,
        create=create, legacy=legacy_allow_200, observation=observation, apply=apply, worker=worker,
        inbox=inbox, history=history, application=application, disable=disable, reopen=reopen,
        registry=registry, save=save, database=database, environment=environment)


def child(lab, code=None, *, module=None, attempts=1, extra=()):
    argv = [sys.executable, "-c", code, *extra] if code else [sys.executable, "-m", module, "--once"]
    return subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, check=False, timeout=20,
        env=lab.environment | {"SIGNAL_INBOX_MAX_ATTEMPTS": str(attempts)})


def http_access(port, session, token):
    import http.client

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("POST", "/zero-trust/protected-access", json.dumps({
            "session_id": session, "resource_id": "zt-demo-documents", "action": "READ", "grant_token": token,
        }), {"Content-Type": "application/json"})
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def assert_fresh_unused_denial(lab, session, original, expected_version, *, service=None):
    assert original.session.grant_expires_at > datetime.now(UTC)
    with running_api(lab.application(service)) as port:
        status, body = http_access(port, session, original.grant_token)
    assert status == 403 and body["reason_code"] == "SESSION_NOT_AUTHORIZED"
    assert body["session_version"] == expected_version and body["content"] is None


def test_real_evaluation_history_reaches_200_hold_and_security_revocation_survives_archive(security_lab):
    lab = security_lab
    previous = None
    for version in range(199):
        previous = lab.create(version=version)
        assert previous.session.version == version + 1 and previous.grant_token
    assert previous.session.version == 199
    capped = lab.create(version=199)
    assert (capped.session.version, capped.session.decision, capped.session.status) == (200, "HOLD", "HELD")
    assert capped.grant_token is None and capped.session.grant_expires_at is None
    assert [item.version for item in lab.history()] == list(range(1, 201))
    with TestClient(lab.application()) as client:
        request = lab.signed(version=200)
        assert client.post("/zero-trust/signals/evaluate", json=request.model_dump(mode="json")).status_code == 409
    assert lab.apply(lab.observation())["result"]["changed_sessions"] == 1
    assert lab.history()[-1].version == 201 and lab.history()[-1].status == "REVOKED"
    before = lab.history()
    assert lab.operations.compact_journal()["compacted"] > 0
    restarted = lab.reopen()
    assert lab.history(service=restarted) == before
    assert_fresh_unused_denial(lab, "session-a", previous, 201, service=restarted)


def test_bounded_tail_all_grades_and_expiry_reason_stop_at_204_without_restore(security_lab):
    lab = security_lab
    original = lab.legacy()
    first = lab.observation("at-risk", kind="device", posture="at_risk")
    lab.apply(first)
    assert (lab.history()[-1].version, lab.history()[-1].decision) == (201, "STEP_UP")
    lab.apply(lab.observation("unknown", kind="device", posture="unknown", at=lab.now + timedelta(seconds=2)))
    assert (lab.history()[-1].version, lab.history()[-1].decision) == (202, "HOLD")
    later = original.session.signal_expires_at + timedelta(seconds=1)
    assert lab.operations.revalidate_sessions(now=later)["held"] == 1
    state = lab.history()[-1]
    assert state.version == 203 and "SIGNAL_PROOF_EXPIRED" in state.reason_codes
    assert lab.operations.revalidate_sessions(now=later)["changed"] == 0
    lab.apply(lab.observation("final-risk", at=later + timedelta(seconds=1)))
    assert (lab.history()[-1].version, lab.history()[-1].status) == (204, "REVOKED")
    for index, options in enumerate(({"positive": True}, {"kind": "device", "posture": "at_risk"},
                                     {"kind": "device", "posture": "unknown"})):
        assert lab.apply(lab.observation(f"weaker-{index}", at=later + timedelta(seconds=index + 2),
                                         **options))["result"]["changed_sessions"] == 0
    repeated = lab.worker().accept(first, lab.principals["tenant-a"], now=later)
    assert repeated["duplicate"] and repeated["state"] == "completed"
    history = lab.history()
    assert [item.version for item in history[-4:]] == [201, 202, 203, 204]
    assert all(item.grant_expires_at is None for item in history[-4:])
    assert lab.operations.revoke("session-a", SessionRevocationRequest(expected_version=204, note="already revoked"),
                                  lab.principals["tenant-a"]).version == 204
    assert lab.history() == history
    with pytest.raises(SessionConflict):
        lab.operations.revoke("session-a", SessionRevocationRequest(expected_version=203, note="stale caller"),
                              lab.principals["tenant-a"])
    lab.operations.compact_journal()
    assert lab.history(service=lab.reopen()) == history


def test_http_intake_and_independent_worker_restrict_capped_and_related_only(security_lab):
    lab = security_lab
    capped = lab.legacy()
    related = lab.create("related-session")
    unrelated = lab.create("unrelated-session", user="user-b", device="device-b", source="independent-idp")
    other = lab.create("foreign-session", tenant="tenant-b")
    request = lab.observation()
    with TestClient(lab.application()) as client:
        assert client.post(BASE, json=request.model_dump(mode="json")).status_code == 202
    assert child(lab, module="scripts.signal_worker").returncode == 0
    receipt = lab.inbox().get("tenant-a", request.event_id)
    assert receipt["state"] == "completed" and receipt["result"]["changed_sessions"] == 2
    assert_fresh_unused_denial(lab, "session-a", capped, 201)
    assert_fresh_unused_denial(lab, "related-session", related, 2)
    with running_api(lab.application()) as port:
        assert http_access(port, "unrelated-session", unrelated.grant_token)[0] == 200
    with running_api(lab.application(tenant="tenant-b")) as port:
        assert http_access(port, "foreign-session", other.grant_token)[0] == 200
    with TestClient(lab.application()) as client:
        assert client.post(BASE, json=request.model_dump(mode="json")).json()["duplicate"]
    assert child(lab, module="scripts.signal_worker").returncode == 0
    assert len(lab.history()) == 201 and len(lab.history("related-session")) == 2


@pytest.mark.parametrize("boundary", ["mid_fanout", "after_policy_commit"])
def test_worker_process_death_does_not_lose_or_double_security_tail(security_lab, boundary):
    lab = security_lab
    original = lab.legacy()
    lab.create("related-session")
    unaffected = lab.create("unrelated-session", user="user-b", device="device-b", source="independent-idp")
    attempts = 2 if boundary == "mid_fanout" else 1
    request = lab.observation()
    lab.worker(attempts).accept(request, lab.principals["tenant-a"], now=request.issued_at)
    code = """
import os,sys
from app.services.signal_inbox import SignalInbox
from app.services.zero_trust import ZeroTrustOperations
from scripts.signal_worker import main
if sys.argv[1]=='mid_fanout':
 append=ZeroTrustOperations._append
 def stop(transaction,entry):
  result=append(transaction,entry)
  if entry.get('kind')=='decision':os._exit(73)
  return result
 ZeroTrustOperations._append=staticmethod(stop)
else:
 SignalInbox.complete=lambda *args,**kwargs:os._exit(73)
raise SystemExit(main(['--once']))
"""
    assert child(lab, code, attempts=attempts, extra=(boundary,)).returncode == 73
    assert lab.history()[-1].version == (200 if boundary == "mid_fanout" else 201)
    if boundary == "after_policy_commit":
        lab.disable("observer")
    with sqlite3.connect(lab.database) as connection:
        expiry = datetime.fromisoformat(connection.execute(
            "SELECT lease_expires_at FROM signal_inbox WHERE event_id=?", (request.event_id,)).fetchone()[0])
    time.sleep(max(0, (expiry - datetime.now(UTC)).total_seconds()) + .05)
    assert child(lab, module="scripts.signal_worker", attempts=attempts).returncode == 0
    receipt = lab.inbox(attempts).get("tenant-a", request.event_id)
    assert receipt["state"] == "completed"
    assert receipt["result"]["duplicate"] == (boundary == "after_policy_commit")
    assert lab.history()[-1].version == 201 and len(lab.history()) == 201
    assert lab.history("related-session")[-1].version == 2
    assert lab.inbox(attempts).compact()["compacted"] == 1
    lab.operations.compact_journal()
    restarted = lab.reopen()
    assert_fresh_unused_denial(lab, "session-a", original, 201, service=restarted)
    assert lab.inbox(attempts).claim(now=datetime.now(UTC), reconcile_exhausted=True) is None
    with running_api(lab.application(restarted)) as port:
        assert http_access(port, "unrelated-session", unaffected.grant_token)[0] == 200


@pytest.mark.parametrize("boundary", ["before_commit", "after_commit"])
def test_watchdog_process_restart_and_key_revocation_do_not_starve_other_sessions(security_lab, boundary):
    lab = security_lab
    original = lab.legacy()
    lab.create("related-session")
    unaffected = lab.create("unrelated-session", user="user-b", device="device-b", source="independent-idp")
    lab.disable()
    code = """
import os,sys
import scripts.session_watchdog as watchdog
from app.services.zero_trust import ZeroTrustOperations
if sys.argv[1]=='before_commit':
 append=ZeroTrustOperations._append
 def stop(transaction,entry):
  result=append(transaction,entry)
  os._exit(73)
 ZeroTrustOperations._append=staticmethod(stop)
else:
 watchdog.print=lambda *args,**kwargs:os._exit(73)
raise SystemExit(watchdog.main(['--once']))
"""
    assert child(lab, code, extra=(boundary,)).returncode == 73
    assert lab.history()[-1].version == (200 if boundary == "before_commit" else 201)
    result = child(lab, module="scripts.session_watchdog")
    assert result.returncode == 0
    assert json.loads(result.stdout)["changed"] == (2 if boundary == "before_commit" else 0)
    assert lab.history()[-1].version == 201 and lab.history("related-session")[-1].version == 2
    assert child(lab, module="scripts.session_watchdog").returncode == 0
    assert len(lab.history()) == 201
    assert_fresh_unused_denial(lab, "session-a", original, 201, service=lab.reopen())
    with running_api(lab.application()) as port:
        assert http_access(port, "unrelated-session", unaffected.grant_token)[0] == 200


def test_current_observation_authority_is_required_even_for_capped_session(security_lab):
    lab = security_lab
    lab.legacy()
    request = lab.observation()
    lab.worker().accept(request, lab.principals["tenant-a"], now=request.issued_at)
    lab.disable("observer")
    assert child(lab, module="scripts.signal_worker").returncode == 1
    receipt = lab.inbox().get("tenant-a", request.event_id)
    assert receipt["state"] == "failed" and receipt["last_error"] == "SIGNAL_REJECTED"
    assert lab.history()[-1].version == 200 and lab.history()[-1].status == "ACTIVE"
    with TestClient(lab.application()) as client:
        assert client.post(BASE, json=request.model_dump(mode="json")).status_code == 401


def test_concurrent_expiry_scan_and_risk_observation_keep_monotone_tail(security_lab):
    lab = security_lab
    first = lab.legacy()
    at = first.session.signal_expires_at + timedelta(seconds=1)
    request = lab.observation(at=at)
    digest = hashlib.sha256(canonical_observation(request)).hexdigest()
    with ThreadPoolExecutor(max_workers=2) as pool:
        scan = pool.submit(lab.reopen().revalidate_sessions, now=at)
        adverse = pool.submit(lab.reopen().apply_observation, request, digest, now=at)
        scan.result()
        assert adverse.result()["changed_sessions"] == 1
    tail = lab.history()[200:]
    assert [entry.decision for entry in tail] in (["DENY"], ["HOLD", "DENY"])
    assert [entry.version for entry in tail] == list(range(201, 201 + len(tail)))
    assert lab.operations.apply_observation(request, digest, now=at)["duplicate"]
    assert lab.operations.revalidate_sessions(now=at)["changed"] == 0


@pytest.mark.parametrize("updates", [
    {"version": 201, "decision": "ALLOW", "status": "ACTIVE"},
    {"version": 202, "decision": "STEP_UP", "status": "STEP_UP_REQUIRED"},
    {"version": 203, "decision": "HOLD", "status": "HELD"},
    {"version": 204, "decision": "HOLD", "status": "HELD"},
    {"version": 205, "decision": "DENY", "status": "REVOKED"},
])
def test_invalid_overflow_state_is_rejected_by_public_model(security_lab, updates):
    first = security_lab.create().session
    with pytest.raises(ValidationError):
        SessionDecision.model_validate(first.model_dump() | {"grant_expires_at": None} | updates)
