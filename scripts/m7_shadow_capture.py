"""Capture fresh lab sessions for M7 shadow triage evaluation."""

import hashlib
import json
import secrets
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.continuous_signal_models import (
    DeviceObservation,
    ObservationApplication,
    SignedContinuousSignal,
)
from app.security import Principal, Role, get_principal
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import SignalInbox
from app.services.trusted_signals import SignalVerifier, canonical_observation
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from scripts.local_oidc_capture import SIGNAL_KEY, SIGNAL_SOURCE, _session_signal
from scripts.test_signal_compose import sign

DOCUMENTS = "zt-demo-documents"
VAULT = "zt-demo-vault"
COLLECTOR = "m7-shadow-collector"
CONTEXTS = (
    (DOCUMENTS, "READ", "employee"),
    (VAULT, "READ", "administrator"),
    (VAULT, "DOWNLOAD", "administrator"),
)
SCOPE = (
    "Controlled local lab. Signed session intake, observation authorization, durable inbox, "
    "policy decisions and protected access are captured from the app. Account approval, "
    "endpoint investigation and corroboration records are scripted lab context."
)

# These references are private and frozen before any app or model capture.
REFERENCES = {
    "approved_account_retirement": (
        "normal", ("low", "low", "low"), ("observation", "approval_record", "enforcement"),
    ),
    "unexplained_account_disable": (
        "unknown", ("medium", "medium", "medium"),
        ("observation", "approval_record", "enforcement"),
    ),
    "confirmed_endpoint_compromise": (
        "threat", ("medium", "high", "high"),
        ("observation", "corroboration", "session_scope", "enforcement"),
    ),
    "approved_endpoint_isolation": (
        "normal", ("low", "low", "low"), ("observation", "approval_record", "enforcement"),
    ),
    "other_resource_alert": (
        "normal", ("low", "low", "low"), ("observation", "session_scope", "enforcement"),
    ),
    "duplicate_endpoint_uncertainty": (
        "unknown", ("medium", "medium", "medium"),
        ("observation", "delivery", "proof_state", "enforcement"),
    ),
    "confirmed_disabled_account_reuse": (
        "threat", ("medium", "high", "high"),
        ("observation", "corroboration", "session_scope", "enforcement"),
    ),
    "untrusted_endpoint_claim": (
        "unknown", ("medium", "medium", "medium"),
        ("source_validation", "corroboration", "enforcement"),
    ),
}

# Scenario inputs independent of scoring, with facts from simulated upstream records.
CONTEXT = {
    "approved_account_retirement": (
        "optional", "verified", "direct",
        "Lab change record approves the account retirement and the final in-flight request.",
        "Lab review matched the request to the registered client shutdown job.",
    ),
    "unexplained_account_disable": (
        "optional", "unconfirmed", "unconfirmed",
        "No change record is available for the observed account disablement.",
        "No independent record ties the follow-up request to an approved shutdown or misuse.",
    ),
    "confirmed_endpoint_compromise": (
        "optional", "conflicting", "unconfirmed",
        "No maintenance or isolation exercise is registered for this endpoint.",
        "Lab endpoint forensics link an unapproved injected process to this session's request.",
    ),
    "approved_endpoint_isolation": (
        "optional", "verified", "delegated",
        "Lab change record approves temporary isolation and delegates this check to the operator.",
        "Lab maintenance ledger links the operator and this request to the isolation check.",
    ),
    "other_resource_alert": (
        "optional", "verified", "direct",
        "The lab access inventory permits this request on the resource in the session.",
        "Lab alert correlation links the finding to a different protected resource.",
    ),
    "duplicate_endpoint_uncertainty": (
        "required", "unconfirmed", "unconfirmed",
        "The lab evaluation policy requires an independent device proof for this workflow.",
        "The lab has no independent device proof or observation resolving the unknown posture.",
    ),
    "confirmed_disabled_account_reuse": (
        "optional", "credential_replay", "unconfirmed",
        "There is no approved retry or delegation for the follow-up request.",
        ("Lab issuer ledger links this request to the repeated redemption of an already-used "
         "single-use identity credential by a second process."),
    ),
    "untrusted_endpoint_claim": (
        "optional", "unconfirmed", "unconfirmed",
        "The lab approval inventory cannot establish who made the follow-up request.",
        "No independent endpoint record corroborates the rejected report.",
    ),
}


def create_plan():
    rows = []
    for family, (label, priorities, required) in REFERENCES.items():
        for (resource, action, role), priority in zip(CONTEXTS, priorities, strict=True):
            rows.append({
                "case_id": "case-" + secrets.token_hex(16),
                "session_id": "sess-" + secrets.token_hex(16),
                "family": family,
                "resource_id": resource,
                "action": action,
                "account_role": role,
                "expected_label": label,
                "expected_priority": priority,
                "required_kinds": list(required),
            })
    return sorted(rows, key=lambda row: row["case_id"])


def _source(case, key, source_id, key_id, now, **fields):
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "tenant_id": case["tenant_id"], "source_id": source_id,
        "user_ids": [case["account_id"]], "device_ids": [case["device_id"]],
        "roles": [case["account_role"]],
        "keys": [{
            "key_id": key_id, "public_key_pem": pem.decode(),
            "not_before": (now - timedelta(days=1)).isoformat(),
            "not_after": (now + timedelta(days=1)).isoformat(),
        }],
        **fields,
    }


def _observation(case):
    family = case["family"]
    if family in {
        "approved_account_retirement", "unexplained_account_disable",
        "confirmed_disabled_account_reuse",
    }:
        return {"kind": "identity", "subject_id": case["account_id"],
                "active": False, "authentication_result": "unknown"}
    if family == "other_resource_alert":
        other = VAULT if case["resource_id"] == DOCUMENTS else DOCUMENTS
        return {"kind": "guardduty", "subject_id": case["account_id"], "resource_id": other,
                "finding_sha256": hashlib.sha256(case["session_id"].encode()).hexdigest()}
    posture = "compromised" if family in {
        "confirmed_endpoint_compromise", "untrusted_endpoint_claim",
    } else "unknown"
    return {"kind": "device", "subject_id": case.get("observation_device_id", case["device_id"]),
            "managed": True,
            "security_posture": posture}


def _journal(path):
    with closing(sqlite3.connect(path)) as connection:
        return [json.loads(row[0]) for row in
                connection.execute("SELECT payload FROM journal ORDER BY seq")]


def _capture(case, directory):
    session_key = Ed25519PrivateKey.generate()
    collector_key = Ed25519PrivateKey.generate()
    start = datetime(2026, 11, 9, 3, tzinfo=UTC)
    current = start

    class LabTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return current.astimezone(tz) if tz is not None else current.replace(tzinfo=None)

    registry = directory / "sources.json"
    observation = _observation(case)
    collector_scope = {"observation_kinds": [observation["kind"]]}
    if observation["kind"] == "guardduty":
        collector_scope["guardduty_resource_ids"] = [DOCUMENTS, VAULT]
    if observation["kind"] == "device":
        collector_scope["device_ids"] = [observation["subject_id"]]
    registry.write_text(json.dumps({"sources": [
        _source(case, session_key, SIGNAL_SOURCE, SIGNAL_KEY, start),
        _source(case, collector_key, COLLECTOR, "lab-key", start, **collector_scope),
    ]}), encoding="utf-8")
    database = directory / "journal.sqlite3"
    operations = ZeroTrustOperations(database, signal_verifier=SignalVerifier(registry))
    service = ContinuousSignalService(operations, SignalInbox(database))
    principal = Principal("lab-operator", case["tenant_id"], frozenset({Role.ADMIN}), "lab")
    app = FastAPI()
    app.include_router(zero_trust_router(operations, service))
    install_zero_trust_error_handlers(app)
    app.dependency_overrides[get_principal] = lambda: principal

    def get_grant(client, version):
        signal = _session_signal(case, session_key, current)
        event = signal.event.model_copy(update={"event_id": f"{case['case_id']}-{version}"})
        signal = sign(signal.model_copy(update={
            "session_id": case["session_id"], "expected_version": version, "event": event,
        }), session_key)
        response = client.post("/zero-trust/signals/evaluate", json=signal.model_dump(mode="json"))
        response.raise_for_status()
        result = response.json()
        session = result["session"]
        if (not result["grant_token"] or session["status"] != "ACTIVE"
                or session["version"] != version + 1 or session["signal_trust"] != "verified_source"):
            raise ValueError("shadow_initial_grant_not_verified")
        return result["grant_token"]

    def access(client, grant):
        response = client.post("/zero-trust/protected-access", json={
            "session_id": case["session_id"], "resource_id": case["resource_id"],
            "action": case["action"], "grant_token": grant,
        })
        body = response.json()
        audit = _journal(database)[-1]
        if (response.status_code not in {200, 403} or audit["kind"] != "access"
                or audit["session_id"] != case["session_id"]
                or any(audit[field] != body[field] for field in (
                    "allowed", "reason_code", "session_version",
                ))
                or (body["content"] is not None) != body["allowed"]):
            raise ValueError("shadow_access_capture_mismatch")
        return {
            "status": response.status_code, "reason_code": body["reason_code"],
            "content_present": body["content"] is not None,
            "session_version": body["session_version"],
        }

    family = case["family"]
    invalid = family == "untrusted_endpoint_claim"
    repeat = family == "duplicate_endpoint_uncertainty"
    with (
        patch("app.services.zero_trust.datetime", LabTime),
        patch("app.services.continuous_signals.datetime", LabTime),
        TestClient(app) as client,
    ):
        grant = get_grant(client, 0)
        earlier = None
        if case["action"] == "DOWNLOAD":
            earlier = access(client, grant)
            if earlier["status"] != 200:
                raise ValueError("shadow_initial_access_failed")
            current += timedelta(seconds=1)
            grant = get_grant(client, 1)
        current += timedelta(seconds=1)
        envelope = SignedContinuousSignal.model_validate({
            "tenant_id": case["tenant_id"], "event_id": case["case_id"] + "-observation",
            "source_id": COLLECTOR, "key_id": "lab-key", "issued_at": current,
            "expires_at": current + timedelta(seconds=60), "observed_at": current,
            "observation": observation, "signature": "A" * 86,
        })
        signer = Ed25519PrivateKey.generate() if invalid else collector_key
        body = sign(envelope, signer).model_dump(mode="json")
        intake = client.post("/zero-trust/signals/inbox", json=body)
        if intake.status_code != (401 if invalid else 202):
            raise ValueError("shadow_inbox_capture_mismatch")
        current += timedelta(seconds=1)
        worker = ContinuousSignalService(
            ZeroTrustOperations(database, signal_verifier=SignalVerifier(registry)),
            SignalInbox(database),
        )
        result = worker.process_one(now=current)
        if invalid and result is not None:
            raise ValueError("shadow_untrusted_signal_enqueued")
        if not invalid and (result is None or result["state"] != "completed"):
            raise ValueError("shadow_worker_capture_incomplete")
        if repeat:
            duplicate = client.post("/zero-trust/signals/inbox", json=body)
            if (duplicate.status_code != 202 or not duplicate.json()["duplicate"]
                    or worker.process_one(now=current) is not None):
                raise ValueError("shadow_duplicate_was_processed_twice")
        final = access(client, grant)
        latest = operations.history(case["session_id"], principal)[-1]

    observations = [row for row in _journal(database) if row["kind"] == "observation"]
    if len(observations) != int(not invalid):
        raise ValueError("shadow_observation_journal_mismatch")
    verified_device_compromise = False
    if not invalid:
        outcome = result["result"]
        marker = ObservationApplication.model_validate(observations[0])
        digest = hashlib.sha256(canonical_observation(envelope)).hexdigest()
        if (marker.tenant_id != envelope.tenant_id or marker.event_id != envelope.event_id
                or marker.observation != envelope.observation
                or marker.input_digest_sha256 != digest
                or marker.matched_sessions != outcome["matched_sessions"]
                or marker.changed_sessions != outcome["changed_sessions"]):
            raise ValueError("shadow_worker_journal_mismatch")
        # Intake and the reopened worker verified this marker's signed envelope.
        # An HTTP denial or a match count alone does not identify the session's device.
        verified_device_compromise = (
            isinstance(marker.observation, DeviceObservation)
            and marker.observation.security_posture == "compromised"
            and marker.tenant_id == latest.tenant_id
            and marker.observation.subject_id == latest.device_id
            and marker.matched_sessions > 0
        )
    return {
        "initial_signal_verified": True,
        "intake_status": intake.status_code,
        "observation": observations[0]["observation"] if observations else None,
        "matched_sessions": observations[0]["matched_sessions"] if observations else 0,
        "changed_sessions": observations[0]["changed_sessions"] if observations else 0,
        "duplicate_delivery": repeat,
        "verified_device_compromise": verified_device_compromise,
        "final_session_status": latest.status,
        "earlier_access": earlier,
        "final_access": final,
        "resource_sensitivity": operations.resources[case["resource_id"]].sensitivity,
    }


def _evidence(case, captured):
    requirement, identity, scope, approval, corroboration = CONTEXT[case["family"]]
    observed = captured["observation"]
    if observed is None:
        statement = "The submitted endpoint report has no trusted observation in the journal."
        trust = "The inbox rejected the endpoint report during source signature validation."
    else:
        if observed["kind"] == "identity":
            statement = "The verified identity feed recorded the account as inactive."
        elif observed["kind"] == "device":
            posture = observed["security_posture"]
            if observed["subject_id"] == case["device_id"]:
                statement = f"The verified endpoint feed recorded {posture} for the session's device."
            else:
                statement = f"The verified endpoint feed recorded {posture} for another device."
                corroboration = "The verified device identifier differs from the session binding."
        else:
            statement = f"The verified alert targets {observed['resource_id']}, a different resource."
        trust = "The inbox verified the collector signature and the worker recorded the observation."
    final = captured["final_access"]
    sensitivity = captured["resource_sensitivity"]
    prior = captured["earlier_access"]
    rule = {
        "proof_requirement": requirement, "proof_state": "absent", "identity_binding": identity,
        "endpoint_scope": scope, "verified_violation": None,
    }
    if captured["verified_device_compromise"]:
        rule["verified_device_compromise"] = True
    facts = {
        "proof_requirement": f"The lab evaluation policy marks independent device proof {requirement}.",
        "proof_state": "No independent device proof was supplied. The initial app assertion was signed.",
        "identity_binding": f"The lab request identity binding record is {identity.replace('_', ' ')}.",
        "endpoint_scope": f"The lab current request scope record is {scope}.",
        "verified_violation": "No independent session proof violation was verified.",
        "session_scope": f"The session requests {case['action']} on {case['resource_id']} ({sensitivity}).",
        "approval_record": approval,
        "corroboration": corroboration,
        "source_validation": trust,
        "observation": statement,
        "delivery": (
            "The inbox acknowledged a duplicate and the worker created no new decision."
            if captured["duplicate_delivery"] else "There was one intake submission for this report."
        ),
        "enforcement": (
            f"The journal shows session {captured['final_session_status']} with "
            f"{captured['changed_sessions']} observation-driven transition. The protected API "
            f"returned HTTP {final['status']} ({final['reason_code']})."
        ),
        "prior_access": (
            f"The earlier request returned HTTP {prior['status']} before the collector report."
            if prior else "No earlier protected request was executed in this lab session."
        ),
    }
    return rule, [
        {"id": "ev-" + hashlib.sha256((case["session_id"] + kind).encode()).hexdigest()[:32],
         "kind": kind, "detail": detail}
        for kind, detail in facts.items()
    ]


def capture_cases(plan, scratch: Path):
    rows = []
    for setup in plan:
        sid = setup["session_id"]
        case = {key: setup[key] for key in (
            "case_id", "session_id", "family", "resource_id", "action", "account_role",
        )} | {"tenant_id": sid + "-t", "account_id": sid + "-u", "device_id": sid + "-d"}
        if setup.get("observation_subject") == "other_device":
            case["observation_device_id"] = sid + "-other-d"
        directory = scratch / sid
        directory.mkdir()
        captured = _capture(case, directory)
        rule, evidence = _evidence(case, captured)
        rows.append({
            "case_id": case["case_id"], "session_id": sid, "family": case["family"],
            "rule_evidence": rule, "evidence": evidence, "capture": captured,
        })
    return rows
