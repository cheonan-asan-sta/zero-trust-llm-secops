"""Exercise signed GuardDuty imports, durable processing and scoped HTTP access."""

import base64
import hashlib
import http.client
import json
import os
import subprocess
import sys
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from test_observation_collector_process import ROOT, running_api, wait_until

from app.config import Settings
from app.continuous_signal_models import SignedContinuousSignal
from app.scenarios import synthetic_events
from app.security import Principal, Role
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import SignalInbox
from app.services.trusted_signals import SignalVerifier, canonical_observation
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import SessionEvaluationRequest
from scripts.guardduty_eventbridge import GuardDutyMapping, normalize_finding

ACCOUNT = "111122223333"
REGION = "ap-northeast-2"
RESOURCE = "zt-demo-documents"
OTHER_RESOURCE = "zt-demo-vault"
SUBJECT = "guardduty-user"
PRINCIPAL = Principal("guardduty-test", "tenant-a", frozenset({Role.ADMIN}), "api_key")
API_KEY = "synthetic-guardduty-test-key"
INBOX = "/zero-trust/signals/inbox"


@pytest.fixture
def forwarder():
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    mapping = GuardDutyMapping(
        tenant_id=PRINCIPAL.tenant_id, account=ACCOUNT, region=REGION,
        forwarder_public_key_pem=public,
        principals={"AWS-PRINCIPAL:session": {"subject_id": SUBJECT, "resource_id": RESOURCE}},
    )
    return key, mapping


def finding(updated):
    ident = "a" * 32
    return {
        "version": "0", "id": str(uuid4()), "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty", "account": ACCOUNT, "region": REGION, "resources": [],
        "time": updated.isoformat(),
        "detail": {
            "accountId": ACCOUNT, "region": REGION, "id": ident, "severity": 8,
            "arn": f"arn:aws:guardduty:{REGION}:{ACCOUNT}:detector/synthetic-detector/finding/{ident}",
            "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
            "createdAt": (updated - timedelta(minutes=10)).isoformat(),
            "updatedAt": updated.isoformat(),
            "resource": {"resourceType": "AccessKey",
                         "accessKeyDetails": {"principalId": "AWS-PRINCIPAL:session"}},
            "service": {"archived": False},
            "description": "Synthetic test finding",
        },
    }


def signed_input(key, event):
    raw = json.dumps(event).encode()
    return raw, key.sign(raw)


def normalize(forwarder, event, now):
    key, mapping = forwarder
    return normalize_finding(*signed_input(key, event), mapping, tenant_id=PRINCIPAL.tenant_id, now=now)


def test_finding_revision_dedupes_delivery_ids_and_keeps_updates_and_conflicts(forwarder):
    now = datetime.now(UTC)
    event = finding(now - timedelta(minutes=1))
    first = normalize(forwarder, event, now)
    event["id"] = str(uuid4())
    event["time"] = now.isoformat()
    assert normalize(forwarder, event, now) == first
    event["detail"]["description"] = "A different payload at the same revision"
    conflict = normalize(forwarder, event, now)
    assert conflict["event_id"] == first["event_id"]
    assert conflict["observation"]["finding_sha256"] != first["observation"]["finding_sha256"]
    event["detail"]["updatedAt"] = now.isoformat()
    assert normalize(forwarder, event, now)["event_id"] != first["event_id"]


@pytest.mark.parametrize(("path", "value"), [
    (("source",), "other.source"),
    (("detail-type",), "Other Finding"),
    (("account",), "999900001111"),
    (("detail", "accountId"), "999900001111"),
    (("detail", "region"), "us-east-1"),
    (("detail", "arn"), "arn:aws:guardduty:ap-northeast-2:999900001111:detector/x/finding/y"),
    (("detail", "severity"), 6.9),
    (("detail", "service", "archived"), True),
    (("detail", "resource", "resourceType"), "Instance"),
    (("detail", "resource", "accessKeyDetails", "principalId"), "UNMAPPED"),
    (("detail", "updatedAt"), "2026-11-06T00:00:00"),
])
def test_signed_but_out_of_scope_findings_are_rejected(forwarder, path, value):
    now = datetime.now(UTC)
    event = finding(now)
    node = event
    for field in path[:-1]:
        node = node[field]
    node[path[-1]] = value
    with pytest.raises(ValueError):
        normalize(forwarder, event, now)


def test_signature_tenant_and_original_timestamp_are_enforced(forwarder):
    key, mapping = forwarder
    now = datetime.now(UTC)
    event = finding(now)
    raw, signature = signed_input(key, event)
    with pytest.raises(ValueError, match="signature"):
        normalize_finding(raw.replace(b"Synthetic", b"Modified"), signature, mapping,
                          tenant_id=PRINCIPAL.tenant_id, now=now)
    with pytest.raises(ValueError, match="mapping tenant"):
        normalize_finding(raw, signature, mapping, tenant_id="tenant-b", now=now)
    ambiguous = raw.replace(b'"version": "0"', b'"version": "0", "version": "0"')
    with pytest.raises(ValueError, match="duplicate JSON key"):
        normalize_finding(ambiguous, key.sign(ambiguous), mapping, tenant_id=PRINCIPAL.tenant_id, now=now)
    delayed = finding(now - timedelta(seconds=301))
    delayed["time"] = now.isoformat()
    with pytest.raises(ValueError, match="intake window"):
        normalize(forwarder, delayed, now)
    with pytest.raises(ValueError, match="intake window"):
        normalize(forwarder, finding(now + timedelta(seconds=1)), now)


def _cli(directory, env, *args, raw=None):
    return subprocess.run(
        [sys.executable, "-m", "scripts.continuous_signal_collector", *args, "--directory", str(directory)],
        cwd=ROOT, env=env, input=raw, capture_output=True, timeout=20, check=False,
    )


def _http(port, path, payload, key=API_KEY):
    with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=5)) as connection:
        connection.request("POST", path, json.dumps(payload), {
            "X-API-Key": key, "Content-Type": "application/json",
        })
        response = connection.getresponse()
        return response.status, json.load(response)


def _session(operations, session_id, *, user=SUBJECT, resource=RESOURCE, principal=PRINCIPAL):
    now = datetime.now(UTC)
    event = synthetic_events()[0].model_copy(deep=True)
    event.event_id, event.timestamp = f"start-{session_id}", now
    event.user.user_id = user
    event.user.role = "administrator" if resource == OTHER_RESOURCE else "employee"
    event.resource.resource_id = resource
    event.auth_context.authentication_result = event.auth_context.mfa = "success"
    return operations.evaluate(SessionEvaluationRequest(
        session_id=session_id, expected_version=0, event=event,
    ), principal, now=now)


def _signed_observation(private, record, **updates):
    now = datetime.now(UTC)
    fields = {
        **record, "tenant_id": PRINCIPAL.tenant_id, "source_id": "local-guardduty",
        "key_id": "key-1", "issued_at": now, "expires_at": now + timedelta(seconds=90),
        "signature": "A" * 86,
    }
    signal = SignedContinuousSignal.model_validate(fields | updates)
    signal.signature = base64.urlsafe_b64encode(private.sign(canonical_observation(signal))).decode().rstrip("=")
    return signal.model_dump(mode="json")


def test_signed_import_restarts_worker_and_scopes_real_http_access(tmp_path, forwarder, monkeypatch):
    key, mapping = forwarder
    directory = tmp_path / "collector"
    env = os.environ | {"APP_ENVIRONMENT": "test", "AUTH_MODE": "disabled", "ANALYZER_MODE": "rule",
                        "SIGNAL_COLLECTOR_API_KEY": API_KEY}
    init = _cli(directory, env, "init", "--tenant", PRINCIPAL.tenant_id, "--source-id", "local-guardduty",
                "--kind", "guardduty", "--subject", SUBJECT, "--resource", RESOURCE)
    assert init.returncode == 0, init.stderr
    (directory / "guardduty-map.json").write_text(mapping.model_dump_json(), encoding="utf-8")
    registry = directory / "sources.json"
    db = tmp_path / "state.sqlite3"
    operations = ZeroTrustOperations(db, signal_verifier=SignalVerifier(registry))
    inbox = SignalInbox(db)
    service = ContinuousSignalService(operations, inbox)
    app = FastAPI()
    app.include_router(zero_trust_router(operations, service))
    install_zero_trust_error_handlers(app)
    settings = Settings(app_environment="test", auth_mode="api_key", api_key_roles="admin",
                        api_key_sha256=hashlib.sha256(API_KEY.encode()).hexdigest(),
                        api_key_tenant_id=PRINCIPAL.tenant_id, api_key_subject=PRINCIPAL.subject)
    monkeypatch.setattr("app.security.get_settings", lambda: settings)
    worker_env = env | {"ZERO_TRUST_DB_PATH": str(db), "TRUSTED_SIGNAL_SOURCES_PATH": str(registry),
                        "SIGNAL_INBOX_LEASE_SECONDS": "0.1"}
    other_tenant = Principal(PRINCIPAL.subject, "tenant-b", PRINCIPAL.roles, "api_key")
    other = _session(operations, "other-tenant", principal=other_tenant)
    grants = [_session(operations, "related"), _session(operations, "unrelated", user="different-user"),
              _session(operations, "different-resource", resource=OTHER_RESOURCE)]
    assert other.grant_token and all(grant.grant_token for grant in grants)
    unaffected = {grant.session.session_id: operations.history(grant.session.session_id, PRINCIPAL)
                  for grant in grants[1:]}
    now = datetime.now(UTC)
    event = finding(now - timedelta(seconds=70))
    record = normalize(forwarder, event, now)
    sig_path = tmp_path / "finding.sig"
    with running_api(app) as port:
        base = ("--base-url", f"http://127.0.0.1:{port}")

        def import_event(item):
            raw, signature = signed_input(key, item)
            sig_path.write_bytes(signature)
            return _cli(directory, env, "append-guardduty", *base, "--event-signature", str(sig_path), raw=raw)

        assert import_event(event).returncode == 0
        event["id"] = str(uuid4())
        assert import_event(event).returncode == 0
        before = (directory / "input.jsonl").read_bytes()
        raw = json.dumps(event).encode().replace(b"Synthetic", b"Modified")
        tampered_import = _cli(
            directory, env, "append-guardduty", *base, "--event-signature", str(sig_path), raw=raw,
        )
        assert tampered_import.returncode == 1 and (directory / "input.jsonl").read_bytes() == before

        for expected in ("acknowledged", "idle"):
            result = _cli(directory, env, "run", *base, "--once")
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout)["collector"] == expected
        assert inbox.get(PRINCIPAL.tenant_id, record["event_id"])["state"] == "pending"
        assert inbox.metrics(PRINCIPAL.tenant_id)["total"] == 1

        private = serialization.load_pem_private_key((directory / "private.pem").read_bytes(), password=None)
        tampered = _signed_observation(private, record, event_id="tampered-finding")
        tampered["observation"]["finding_sha256"] = "0" * 64
        cross_tenant = _signed_observation(private, record, event_id="cross-tenant", tenant_id="tenant-b")
        wrong_resource = _signed_observation(private, record, event_id="wrong-resource",
                                           observation=record["observation"] | {"resource_id": OTHER_RESOURCE})
        stale_record = record | {"observed_at": now - timedelta(seconds=301)}
        expired = _signed_observation(private, stale_record, event_id="late-first-intake")
        for rejected in (tampered, cross_tenant, wrong_resource, expired):
            assert _http(port, INBOX, rejected)[0] == 401
        assert inbox.metrics(PRINCIPAL.tenant_id)["total"] == 1
        assert inbox.metrics(other_tenant.tenant_id)["total"] == 0

        crash = """
import os
from app.config import get_settings
from scripts.signal_worker import build_service
worker = build_service(get_settings())
def exit_before_ack(*args):
    os._exit(73)
worker.inbox.complete = exit_before_ack
worker.process_one()
"""
        crashed = subprocess.run([sys.executable, "-c", crash], cwd=ROOT, env=worker_env,
                                 capture_output=True, timeout=20, check=False)
        assert crashed.returncode == 73, crashed.stderr
        assert inbox.get(PRINCIPAL.tenant_id, record["event_id"])["state"] == "processing"
        assert operations.history("related", PRINCIPAL)[-1].version == 2
        after_lease = time.monotonic() + 0.11
        wait_until(lambda: time.monotonic() >= after_lease)
        restarted = subprocess.run([sys.executable, "-m", "scripts.signal_worker", "--once"],
                                   cwd=ROOT, env=worker_env, capture_output=True, timeout=20, check=False)
        assert restarted.returncode == 0, restarted.stderr
        receipt = inbox.get(PRINCIPAL.tenant_id, record["event_id"])
        assert receipt["state"] == "completed" and receipt["attempts"] == 2
        assert receipt["result"]["duplicate"] is True and receipt["result"]["changed_sessions"] == 0

        assert all(operations.history(identifier, PRINCIPAL) == history
                   for identifier, history in unaffected.items())
        # Cold CLI processes under emulation can outlive the60s grant. Keep the
        # original controls' histories intact and obtain current authorization
        # for the same unaffected scopes before asserting successful delivery.
        access_grants = [grants[0],
                         _session(operations, "current-unrelated", user="different-user"),
                         _session(operations, "current-other-resource", resource=OTHER_RESOURCE)]
        for grant, expected in zip(access_grants, (403, 200, 200), strict=True):
            decision = grant.session
            status, response = _http(port, "/zero-trust/protected-access", {
                "session_id": decision.session_id, "resource_id": decision.resource_id,
                "grant_token": grant.grant_token, "action": "READ",
            })
            assert status == expected
            assert (response["content"] is not None) == (expected == 200)
            if expected == 403:
                assert response["reason_code"] == "SESSION_NOT_AUTHORIZED"
        assert operations.history("related", PRINCIPAL)[-1].reason_codes[-1] == "CONTINUOUS_GUARDDUTY_DENY"
        assert len(operations.history("related", PRINCIPAL)) == 2
        assert len(operations.history("other-tenant", other_tenant)) == 1
        assert _session(operations, "fresh-related").grant_token is None
        assert _session(operations, "fresh-other-resource", resource=OTHER_RESOURCE).grant_token

        older = finding(now - timedelta(seconds=100))
        older_record = normalize(forwarder, older, datetime.now(UTC))
        assert import_event(older).returncode == 0
        assert _cli(directory, env, "run", *base, "--once").returncode == 0
        # Once accepted, a backlog can cross both the original finding window
        # and the envelope expiry while retaining its restrictive effect.
        result = service.process_one(now=datetime.now(UTC) + timedelta(minutes=6))
        assert result["event_id"] == older_record["event_id"] and result["state"] == "completed"
        assert result["result"]["stale"] is True and result["result"]["changed_sessions"] == 0

        event["detail"]["description"] = "Conflicting revision from the configured forwarder"
        assert import_event(event).returncode == 0
        conflict = _cli(directory, env, "run", *base, "--once")
        assert conflict.returncode == 1
        assert inbox.metrics(PRINCIPAL.tenant_id)["total"] == 2
