"""Archived intake receipts retain HTTP, worker and grant-denial semantics."""

import base64
import hashlib
import http.client
import json
import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from test_continuous_signal_api import (
    BASE,
    OPERATOR,
    isolated_app,
    signed_observation,
    start_session,
)
from test_continuous_signal_api import receiver as receiver  # noqa: PLC0414
from test_observation_collector_process import proxy_to, running_api

from app.security import Principal, Role
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import InboxMissing, SignalInbox
from app.services.trusted_signals import SignalVerifier, canonical_observation
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_models import ProtectedAccessRequest, SessionRevocationRequest

ROOT = Path(__file__).parents[1]


def reopened(receiver, **overrides):
    options = {"max_records": 4, "archive_batch_size": 2,
               "max_archive_records": 200, "max_archive_segments": 100,
               "max_attempts": 1, "lease_seconds": 1}
    options.update(overrides)
    inbox = SignalInbox(receiver.operations.path, **options)
    operations = ZeroTrustOperations(receiver.operations.path,
                                     signal_verifier=SignalVerifier(receiver.registry_path))
    continuous = ContinuousSignalService(operations, inbox)
    return SimpleNamespace(inbox=inbox, operations=operations, continuous=continuous,
                           app=isolated_app(operations, continuous))


def accept_and_complete(lab, request, *, failed=False):
    lab.continuous.accept(request, OPERATOR, now=request.issued_at)
    if failed:
        claim = lab.inbox.claim(now=request.issued_at)
        return lab.inbox.fail(OPERATOR.tenant_id, request.event_id, claim["lease_token"],
                              "SIGNAL_REJECTED", request.issued_at)
    return lab.continuous.process_one(now=request.issued_at)


def http_json(port, method, path, payload):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, json.dumps(payload), {"Content-Type": "application/json"})
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def access_payload(session_id, token):
    return {"session_id": session_id, "resource_id": "zt-demo-documents",
            "action": "READ", "grant_token": token}


def bulk_terminal_rows(receiver, inbox, count):
    """One SQL fixture transaction; each copied row has a real signed envelope.

    A normal intake and worker first produce the validated completed template.
    This avoids ten thousand O(n) claims while retaining all production row checks.
    """
    seed = signed_observation(receiver.key, event_id="bulk-seed", when=datetime.now(UTC) - timedelta(seconds=2),
        observation={"kind": "identity", "subject_id": "unrelated-user", "active": False,
                     "authentication_result": "failure"})
    worker = ContinuousSignalService(receiver.operations, inbox)
    worker.accept(seed, OPERATOR, now=seed.issued_at)
    assert worker.process_one(now=seed.issued_at)["state"] == "completed"
    from app.services import inbox_archive

    with inbox._transaction() as connection:
        template = dict(connection.execute("SELECT * FROM signal_inbox").fetchone())
        columns = list(template)
        rows = []
        for index in range(count - 1):
            request = signed_observation(receiver.key, event_id=f"bulk-{index:05d}",
                when=seed.issued_at, observation=seed.observation.model_dump(mode="json"))
            payload = json.dumps(request.model_dump(mode="json"), sort_keys=True,
                                 ensure_ascii=False, separators=(",", ":"))
            row = template | {"event_id": request.event_id, "payload": payload,
                              "input_digest": hashlib.sha256(canonical_observation(request)).hexdigest(),
                              "payload_digest": hashlib.sha256(payload.encode()).hexdigest()}
            inbox._validate(row)
            rows.append(tuple(row[column] for column in columns))
        connection.executemany(
            f"INSERT INTO signal_inbox ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            rows,
        )
        inbox_archive.refresh(connection, inbox._validate, inbox._archive_limits, added=len(rows))


def test_default_hot_limit_archives_more_than_ten_thousand_receipts_then_applies_policy(receiver):
    inbox = SignalInbox(receiver.operations.path)
    bulk_terminal_rows(receiver, inbox, 10000)
    first = start_session(receiver, "new-after-ten-thousand")
    worker = ContinuousSignalService(receiver.operations, inbox)
    for index in range(2):
        request = signed_observation(receiver.key, event_id=f"new-risk-{index}",
                                     when=datetime.now(UTC) - timedelta(seconds=1))
        with TestClient(isolated_app(receiver.operations, worker)) as client:
            assert client.post(BASE, json=request.model_dump(mode="json")).status_code == 202
        assert worker.process_one()["state"] == "completed"
    storage = inbox.storage_status()
    assert storage["total_records"] == 10002
    assert storage["active_records"] <= 10000 and storage["archived_records"] > 0
    summary = inbox.metrics("tenant-a")
    assert summary["completed"] == summary["total"] == 10002
    assert summary["active_records"] + summary["archived_records"] == 10002
    assert summary["completion_latency_samples"] == 10002
    assert inbox.claim(now=datetime.now(UTC)) is None
    assert len(receiver.operations.history("new-after-ten-thousand", OPERATOR)) == 2
    with running_api(isolated_app(receiver.operations, worker)) as port:
        status, body = http_json(port, "POST", "/zero-trust/protected-access",
                                 access_payload("new-after-ten-thousand", first.grant_token))
    assert status == 403 and body["reason_code"] == "SESSION_NOT_AUTHORIZED"


@pytest.mark.parametrize("failed", [False, True])
def test_archived_terminal_receipt_replays_over_http_and_remains_tenant_scoped(receiver, failed):
    lab = reopened(receiver)
    request = signed_observation(receiver.key, when=datetime.now(UTC) - timedelta(seconds=2))
    before = accept_and_complete(lab, request, failed=failed)
    assert before["state"] == ("failed" if failed else "completed")
    assert lab.inbox.compact()["compacted"] == 1
    restarted = reopened(receiver)
    assert restarted.inbox.get("tenant-a", request.event_id) == before
    assert restarted.inbox.metrics("tenant-a")[before["state"]] == 1
    assert restarted.inbox.metrics("tenant-b")["total"] == 0
    with pytest.raises(InboxMissing):
        restarted.inbox.get("tenant-b", request.event_id)
    with TestClient(restarted.app) as client:
        replay = client.post(BASE, json=request.model_dump(mode="json"))
        assert replay.status_code == 202 and replay.json() == before | {"duplicate": True}
        assert client.get(BASE + "/" + request.event_id).json() == before
    other = Principal("other-operator", "tenant-b", frozenset({Role.ADMIN}), "api_key")
    with TestClient(isolated_app(restarted.operations, restarted.continuous, other)) as client:
        assert client.get(BASE + "/" + request.event_id).status_code == 404
        assert client.get(BASE).json()["total"] == 0
    assert restarted.inbox.claim(now=request.issued_at + timedelta(days=1), reconcile_exhausted=True) is None


def test_archived_exact_expired_envelope_still_requires_current_key_and_scope(receiver):
    lab = reopened(receiver)
    request = signed_observation(receiver.key, when=datetime.now(UTC) - timedelta(seconds=120))
    before = accept_and_complete(lab, request)
    lab.inbox.compact()
    later = request.issued_at + timedelta(seconds=120)
    assert lab.continuous.accept(request, OPERATOR, now=later) == before | {"duplicate": True}
    with TestClient(lab.app) as client:
        replay = client.post(BASE, json=request.model_dump(mode="json"))
        assert replay.status_code == 202 and replay.json()["duplicate"]
    source = receiver.registry["sources"][0]
    source["user_ids"] = ["unrelated-user"]
    receiver.registry_path.write_text(json.dumps(receiver.registry), encoding="utf-8")
    with TestClient(lab.app) as client:
        assert client.post(BASE, json=request.model_dump(mode="json")).status_code == 401
    source["user_ids"] = ["signed-user", "unrelated-user"]
    source["keys"][0]["enabled"] = False
    receiver.registry_path.write_text(json.dumps(receiver.registry), encoding="utf-8")
    with TestClient(lab.app) as client:
        assert client.post(BASE, json=request.model_dump(mode="json")).status_code == 401
    assert lab.inbox.get("tenant-a", request.event_id) == before


def test_compaction_preserves_pending_and_processing_rows_and_fences_old_lease(receiver):
    lab = reopened(receiver)
    at = datetime.now(UTC) - timedelta(seconds=2)
    terminal = signed_observation(receiver.key, event_id="terminal", when=at)
    accept_and_complete(lab, terminal)
    processing = signed_observation(receiver.key, event_id="processing", when=at)
    lab.continuous.accept(processing, OPERATOR, now=at)
    delivery = lab.inbox.claim(now=at)
    pending = signed_observation(receiver.key, event_id="pending", when=at + timedelta(microseconds=1))
    lab.continuous.accept(pending, OPERATOR, now=pending.issued_at)
    with sqlite3.connect(lab.inbox.path) as connection:
        before = connection.execute("SELECT * FROM signal_inbox WHERE state IN ('pending','processing') "
                                    "ORDER BY event_id").fetchall()
    assert lab.inbox.compact()["compacted"] == 1
    with sqlite3.connect(lab.inbox.path) as connection:
        assert connection.execute("SELECT * FROM signal_inbox ORDER BY event_id").fetchall() == before
    restarted = reopened(receiver)
    assert restarted.inbox.get("tenant-a", processing.event_id)["attempts"] == 1
    # The original fence still owns its unexpired lease across archive/restart.
    receipt = restarted.inbox.complete("tenant-a", processing.event_id, delivery["lease_token"],
                                       {"verified": True}, at + timedelta(milliseconds=100))
    assert receipt["state"] == "completed"
    next_delivery = restarted.inbox.claim(now=at + timedelta(milliseconds=200))
    assert next_delivery["event_id"] == pending.event_id and next_delivery["attempts"] == 1


def test_archived_same_event_id_receipts_and_metrics_remain_distinct_between_tenants(receiver):
    lab = reopened(receiver)
    at = datetime.now(UTC) - timedelta(seconds=2)
    first = signed_observation(receiver.key, when=at)
    first_receipt = accept_and_complete(lab, first)
    source = json.loads(json.dumps(receiver.registry["sources"][0]))
    source["tenant_id"] = "tenant-b"
    receiver.registry["sources"].append(source)
    receiver.registry_path.write_text(json.dumps(receiver.registry), encoding="utf-8")
    second = signed_observation(receiver.key, when=at, tenant_id="tenant-b")
    other = Principal("other-operator", "tenant-b", frozenset({Role.ADMIN}), "api_key")
    lab.continuous.accept(second, other, now=at)
    delivery = lab.inbox.claim(now=at)
    second_receipt = lab.inbox.fail("tenant-b", second.event_id, delivery["lease_token"],
                                    "SIGNAL_REJECTED", at)
    assert lab.inbox.compact()["compacted"] == 2
    restarted = reopened(receiver)
    for principal, request, receipt in ((OPERATOR, first, first_receipt),
                                        (other, second, second_receipt)):
        with TestClient(isolated_app(restarted.operations, restarted.continuous, principal)) as client:
            assert client.get(BASE + "/" + request.event_id).json() == receipt
            replay = client.post(BASE, json=request.model_dump(mode="json"))
            assert replay.status_code == 202 and replay.json() == receipt | {"duplicate": True}
            summary = client.get(BASE).json()
            assert summary["total"] == summary[receipt["state"]] == 1
            assert summary["archived_records"] == 1 and summary["active_records"] == 0
    assert restarted.inbox.claim(now=datetime.now(UTC), reconcile_exhausted=True) is None


def test_archived_event_rejects_changed_valid_payload_and_signature(receiver):
    lab = reopened(receiver)
    at = datetime.now(UTC) - timedelta(seconds=2)
    request = signed_observation(receiver.key, when=at)
    before = accept_and_complete(lab, request)
    lab.inbox.compact()
    changed = signed_observation(receiver.key, when=at,
        observation={"kind": "identity", "subject_id": "signed-user", "active": True,
                     "authentication_result": "success"})
    with TestClient(lab.app) as client:
        assert client.post(BASE, json=changed.model_dump(mode="json")).status_code == 409
        broken = request.model_copy(update={"signature": "A" * 86})
        assert client.post(BASE, json=broken.model_dump(mode="json")).status_code == 401
    replacement_key = Ed25519PrivateKey.generate()
    receiver.registry["sources"][0]["keys"][0]["public_key_pem"] = replacement_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    receiver.registry_path.write_text(json.dumps(receiver.registry), encoding="utf-8")
    signature = base64.urlsafe_b64encode(replacement_key.sign(canonical_observation(request))).decode().rstrip("=")
    resigned = request.model_copy(update={"signature": signature})
    with TestClient(lab.app) as client:
        assert client.post(BASE, json=resigned.model_dump(mode="json")).status_code == 409
    assert lab.inbox.get("tenant-a", request.event_id) == before


def test_lost_http_acceptance_ack_replays_archived_receipt_without_second_effect(receiver):
    lab = reopened(receiver)
    first = start_session(receiver, "lost-acceptance-ack")
    request = signed_observation(receiver.key, when=datetime.now(UTC) - timedelta(seconds=1))
    with running_api(lab.app) as port, proxy_to(port) as proxy:
        proxy.mode = "drop_ack"
        with pytest.raises((http.client.RemoteDisconnected, ConnectionResetError)):
            http_json(proxy.server_port, "POST", BASE, request.model_dump(mode="json"))
        assert proxy.committed.is_set()
    assert lab.continuous.process_one()["state"] == "completed"
    assert lab.inbox.compact()["compacted"] == 1
    restarted = reopened(receiver)
    with running_api(restarted.app) as port:
        status, receipt = http_json(port, "POST", BASE, request.model_dump(mode="json"))
        assert status == 202 and receipt["duplicate"] and receipt["state"] == "completed"
        status, body = http_json(port, "POST", "/zero-trust/protected-access",
                                 access_payload("lost-acceptance-ack", first.grant_token))
        assert status == 403 and body["reason_code"] == "SESSION_NOT_AUTHORIZED"
    assert restarted.continuous.process_one() is None
    assert len(restarted.operations.history("lost-acceptance-ack", OPERATOR)) == 2


def test_worker_death_after_final_policy_commit_reconciles_then_archives_after_key_revocation(receiver):
    lab = reopened(receiver)
    first = start_session(receiver, "final-attempt")
    request = signed_observation(receiver.key, when=datetime.now(UTC) - timedelta(seconds=1))
    lab.continuous.accept(request, OPERATOR, now=request.issued_at)
    code = """
import os
from app.services.signal_inbox import SignalInbox
from scripts.signal_worker import main
def die_after_effects(*args,**kwargs):os._exit(73)
SignalInbox.complete=die_after_effects
raise SystemExit(main(['--once']))
"""
    child = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True,
        timeout=15, check=False, env=os.environ | {"APP_ENVIRONMENT": "test", "ANALYZER_MODE": "rule",
            "ZERO_TRUST_DB_PATH": str(lab.inbox.path), "TRUSTED_SIGNAL_SOURCES_PATH": str(receiver.registry_path),
            "SIGNAL_INBOX_MAX_ATTEMPTS": "1", "SIGNAL_INBOX_LEASE_SECONDS": "1"})
    assert child.returncode == 73
    assert receiver.operations.history("final-attempt", OPERATOR)[-1].status == "REVOKED"
    assert lab.inbox.compact()["compacted"] == 0
    with sqlite3.connect(lab.inbox.path) as connection:
        lease_until = connection.execute("SELECT lease_expires_at FROM signal_inbox").fetchone()[0]
    receiver.registry["sources"][0]["keys"][0]["enabled"] = False
    receiver.registry_path.write_text(json.dumps(receiver.registry), encoding="utf-8")
    restarted = reopened(receiver)
    recovered = restarted.continuous.process_one(now=datetime.fromisoformat(lease_until) + timedelta(seconds=1))
    assert recovered["state"] == "completed" and recovered["attempts"] == 1
    assert recovered["result"]["duplicate"] and recovered["result"]["changed_sessions"] == 0
    assert restarted.inbox.compact()["compacted"] == 1
    again = reopened(receiver)
    assert again.inbox.get("tenant-a", request.event_id) == recovered
    assert again.continuous.process_one() is None
    assert len(again.operations.history("final-attempt", OPERATOR)) == 2
    denied = again.operations.access(ProtectedAccessRequest.model_validate(
        access_payload("final-attempt", first.grant_token)), OPERATOR)
    assert not denied.allowed and denied.reason_code == "SESSION_NOT_AUTHORIZED"


@pytest.mark.parametrize("boundary", ["before_commit", "after_commit"])
def test_compact_cli_process_death_retains_receipts_and_http_denial(receiver, boundary):
    lab = reopened(receiver)
    consumed = start_session(receiver, "spent")
    assert receiver.operations.access(ProtectedAccessRequest.model_validate(
        access_payload("spent", consumed.grant_token)), OPERATOR).allowed
    revoked = start_session(receiver, "revoked")
    receiver.operations.revoke("revoked", SessionRevocationRequest(expected_version=1, note="operator stop"),
                               OPERATOR)
    request = signed_observation(receiver.key, when=datetime.now(UTC) - timedelta(seconds=1),
        observation={"kind": "identity", "subject_id": "unrelated-user", "active": False,
                     "authentication_result": "failure"})
    before = accept_and_complete(lab, request)
    code = """
import os,sqlite3,sys
from app.services.signal_inbox import SignalInbox
from scripts.signal_inbox import main
active=False
connect=sqlite3.connect
class FaultConnection(sqlite3.Connection):
 def execute(self,sql,*args,**kwargs):
  result=super().execute(sql,*args,**kwargs)
  if active and BOUNDARY=='before_commit' and sql.lstrip().upper().startswith('DELETE FROM SIGNAL_INBOX '):os._exit(73)
  return result
def fault_connect(*args,**kwargs):
 kwargs['factory']=FaultConnection
 return connect(*args,**kwargs)
sqlite3.connect=fault_connect
compact=SignalInbox.compact
def fault_compact(self,*args,**kwargs):
 global active
 active=True
 result=compact(self,*args,**kwargs)
 if BOUNDARY=='after_commit':os._exit(73)
 return result
SignalInbox.compact=fault_compact
raise SystemExit(main(['compact','--database',sys.argv[1],'--limit','2']))
""".replace("BOUNDARY", repr(boundary))
    child = subprocess.run([sys.executable, "-c", code, str(lab.inbox.path)], cwd=ROOT,
        env=os.environ | {"APP_ENVIRONMENT": "test", "ANALYZER_MODE": "rule"},
        capture_output=True, text=True, timeout=15, check=False)
    assert child.returncode == 73
    restarted = reopened(receiver)
    storage = restarted.inbox.storage_status()
    assert storage["archived_records"] == (0 if boundary == "before_commit" else 1)
    assert restarted.inbox.get("tenant-a", request.event_id) == before
    restarted.inbox.compact()
    with running_api(restarted.app) as port:
        for session, token, reason in (("spent", consumed.grant_token, "GRANT_ALREADY_USED"),
                                       ("revoked", revoked.grant_token, "SESSION_NOT_AUTHORIZED")):
            status, body = http_json(port, "POST", "/zero-trust/protected-access", access_payload(session, token))
            assert status == 403 and body["reason_code"] == reason and body["content"] is None
    assert restarted.inbox.claim(now=datetime.now(UTC), reconcile_exhausted=True) is None
