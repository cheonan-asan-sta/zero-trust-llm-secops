"""Bind separate execution telemetry to one capture and compare it with prior authority."""

from datetime import datetime

from app.behavior_execution_models import ExecutionPolicy, SignedExecutionEvidence
from app.services.trusted_signals import SignalRejected


def require_capture_binding(evidence, capture, capture_digest):
    if (evidence.tenant_id != capture.tenant_id
            or evidence.capture_id != capture.capture_id
            or evidence.capture_input_sha256 != capture_digest
            or evidence.scope != capture.scope
            or evidence.session_id != capture.session_id
            or evidence.session_version != capture.session_version
            or evidence.session_input_sha256 != capture.session_input_sha256
            or set(evidence.event_ids) != {event.id for event in capture.activity.events}
            or set(evidence.connection_ids) != set(capture.connection_ids)
            or evidence.observed_at < max(event.timestamp for event in capture.activity.events)
            or evidence.observed_at >= capture.expires_at):
        raise SignalRejected("execution evidence does not bind to the complete capture")


def execution_snapshot(entries, capture, capture_digest, verifier, principal, now):
    records = [entry for entry in entries if entry["kind"] == "execution"
               and entry["tenant_id"] == capture.tenant_id
               and entry["payload"]["evidence"]["capture_id"] == capture.capture_id]
    result = {"status": "missing", "evidence_ids": [], "actor": None, "destinations": None}
    if not records:
        return result
    material = []
    for entry in records:
        evidence = SignedExecutionEvidence.model_validate(entry["payload"]["evidence"])
        result["evidence_ids"].append(evidence.evidence_id)
        try:
            proof = verifier.verify_execution_evidence(evidence, principal, now,
                                                      enforce_freshness=False)
            require_capture_binding(evidence, capture, capture_digest)
        except SignalRejected:
            return result | {"status": "stale"}
        if (evidence.expires_at <= now or evidence.issued_at > now
                or datetime.fromisoformat(entry["created_at"]) > now
                or proof.source_digest != entry["payload"]["source_digest"]
                or proof.input_digest != entry["payload"]["input_digest"]):
            return result | {"status": "stale"}
        if evidence.actor is None or evidence.destinations is None:
            material.append(None)
        else:
            material.append((evidence.actor.model_dump_json(),
                             tuple(sorted(item.model_dump_json() for item in evidence.destinations))))
    if None in material:
        return result | {"status": "incomplete"}
    if len(set(material)) != 1:
        return result | {"status": "conflict"}
    # All accepted reports must cover the same capture and agree; a later favourable
    # report cannot silently supersede an earlier conflicting report.
    return result | {"status": "complete", "actor": evidence.actor,
                     "destinations": evidence.destinations}


def policy_matches(policy, observed):
    policy = ExecutionPolicy.model_validate(policy)
    return (observed["actor"] == policy.actor
            and {item.model_dump_json() for item in observed["destinations"]}
            <= {item.model_dump_json() for item in policy.destinations})
