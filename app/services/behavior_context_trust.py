"""Read verified operational state without granting access or promoting caller claims."""

import hmac
from datetime import datetime

from app.behavior_context_models import SignedBehaviorCapture
from app.continuous_signal_models import ObservationApplication
from app.security import Principal
from app.services.trusted_signals import SignalRejected
from app.services.zero_trust import JournalUnavailable, ZeroTrustOperations
from app.zero_trust_models import SessionDecision


def _same_scope(session, scope):
    return (session.user_id == scope.user_id and session.device_id == scope.device_id
            and session.resource_id == scope.resource_id and session.action == scope.action)


def _evidence(marker, capture, historical):
    if marker.tenant_id != capture.tenant_id or marker.restriction != "DENY":
        return None
    observation = marker.observation
    if observation.kind == "device":
        if (observation.subject_id != capture.scope.device_id
                or observation.security_posture != "compromised"):
            return None
        reason = "trusted_device_compromise"
    elif observation.kind == "guardduty":
        if (observation.subject_id != capture.scope.user_id
                or observation.resource_id != capture.scope.resource_id):
            return None
        reason = "trusted_guardduty_finding"
    elif observation.kind == "session_proof":
        if (marker.matched_sessions < 1
                or observation.session_id != capture.session_id
                or observation.session_version != capture.session_version
                or observation.subject_id != capture.scope.user_id
                or observation.device_id != capture.scope.device_id
                or observation.resource_id != capture.scope.resource_id
                or observation.action != capture.scope.action
                or marker.observed_at < historical.evaluated_at
                or not hmac.compare_digest(
                    observation.session_input_sha256, capture.session_input_sha256,
                )):
            return None
        reason = "trusted_session_proof_violation"
    else:
        # Failed authentication, administrative disabling and isolation can deny
        # access without establishing compromise or an attack attempt.
        return None
    return {
        "event_id": marker.event_id, "kind": observation.kind, "reason": reason,
        "source_id": marker.source_id, "key_id": marker.key_id,
        "input_digest_sha256": marker.input_digest_sha256,
        "observed_at": marker.observed_at.isoformat(),
        "recorded_at": marker.recorded_at.isoformat(),
        "historically_committed": True,
    }


def behavior_snapshot(
    operations: ZeroTrustOperations, capture: SignedBehaviorCapture,
    principal: Principal, now: datetime,
) -> dict:
    """Bind the signed capture to one verified session revision and committed signals.

    Capture signatures and current authority are checked even for internal callers.
    Existing adverse journal evidence remains sticky, matching the policy engine;
    later key expiry does not erase an already committed compromise finding.
    """
    if now.utcoffset() is None:
        raise ValueError("behavior snapshot time requires timezone")
    proof = operations.signal_verifier.verify_behavior_capture(
        capture, principal, now, enforce_freshness=False,
    )
    if capture.tenant_id != principal.tenant_id:
        raise SignalRejected("behavior tenant rejected")
    with operations._transaction() as transaction:
        decisions = [SessionDecision.model_validate(entry["session"])
                     for entry in transaction[1] if entry["kind"] == "decision"
                     and entry["session"]["tenant_id"] == principal.tenant_id
                     and entry["session"]["session_id"] == capture.session_id]
        latest = decisions[-1] if decisions else None
        historical = [session for session in decisions if session.version == capture.session_version]
        result = {
            "binding_valid": False, "binding_reason": "verified_session_binding_missing",
            "normal_session_eligible": False,
            "current_status": latest.status if latest else None,
            "session_version": latest.version if latest else None,
            "evidence": [], "journal_digest_sha256": transaction[2],
            "capture_source_digest": proof.source_digest,
            "capture_input_digest_sha256": proof.input_digest,
        }
        if len(historical) != 1:
            return result
        previous = historical[0]
        if (previous.signal_trust != "verified_source"
                or not _same_scope(previous, capture.scope)
                or not hmac.compare_digest(previous.input_digest_sha256, capture.session_input_sha256)
                or previous.evaluated_at > capture.issued_at
                or any(event.timestamp < previous.evaluated_at for event in capture.activity.events)):
            return result
        result.update(binding_valid=True, binding_reason="verified_session_revision_bound")
        for entry in transaction[1]:
            if entry["kind"] != "observation":
                continue
            marker = ObservationApplication.model_validate(entry)
            if marker.observed_at.utcoffset() is None or marker.recorded_at.utcoffset() is None:
                raise JournalUnavailable("observation timestamp lacks timezone")
            if marker.observed_at > now or marker.recorded_at > now:
                continue
            evidence = _evidence(marker, capture, previous)
            if evidence is not None:
                result["evidence"].append(evidence)
        # The capture can still be historically bound after a later restriction,
        # but normal context cannot reuse an old revision or expired authorization.
        source_digest = operations.signal_verifier.source_digest(
            principal.tenant_id, latest.signal_source_id, latest.signal_key_id, now,
        ) if latest.signal_source_id and latest.signal_key_id else None
        eligible = (
            latest.version == capture.session_version
            and hmac.compare_digest(latest.input_digest_sha256, capture.session_input_sha256)
            and _same_scope(latest, capture.scope)
            and latest.status == "ACTIVE" and latest.decision == "ALLOW"
            and latest.signal_trust == "verified_source"
            and latest.policy_digest_sha256 == operations.policy_digest
            and source_digest is not None and source_digest == latest.signal_source_digest
            and latest.signal_expires_at is not None and latest.signal_expires_at > now
            and latest.grant_expires_at is not None and latest.grant_expires_at > now
            and latest.evaluated_at <= now and capture.expires_at > now
            and not result["evidence"]
        )
        result["normal_session_eligible"] = eligible
        if not eligible:
            result["normal_ineligible_reason"] = "session_context_not_currently_authorized"
        return result
