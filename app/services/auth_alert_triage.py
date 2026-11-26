"""Resolve a shadow authentication alert using current, server-verified session evidence."""

from datetime import UTC, datetime
from typing import Literal

from app.models import SecurityEvent
from app.security import Principal, Role
from app.services.policy_journal import JournalUnavailable
from app.services.session_analysis_evidence import collect_session_evidence
from app.services.trusted_signals import SignalRegistryUnavailable, SignalRejected
from app.services.zero_trust import SessionConflict, SessionMissing, ZeroTrustOperations
from app.zero_trust_models import SignedAuthAttemptReceipt, SignedSessionSignal

AlertDisposition = Literal["confirmed", "cleared", "needs_evidence"]
POLICY_RESTRICTIONS = frozenset(
    {
        "FRESH_MFA_REQUIRED",
        "MANAGED_DEVICE_REQUIRED",
        "RESOURCE_SCOPE_DENIED",
        "SESSION_ALREADY_REVOKED",
        "DEVICE_COMPROMISED",
        "IDENTITY_DENIED",
    }
)


def resolve_auth_alert(
    service: ZeroTrustOperations,
    event: SecurityEvent,
    signal: SignedSessionSignal,
    principal: Principal,
) -> AlertDisposition:
    """Read and recheck. A disposition has no effect on grants or policy decisions."""
    try:
        context = collect_session_evidence(service, signal, principal)
        facts = context.for_event(event)
    except (
        SignalRejected,
        SignalRegistryUnavailable,
        JournalUnavailable,
        SessionConflict,
        SessionMissing,
        OSError,
    ):
        return "needs_evidence"

    session = facts["session"]
    if session["decision"] in {"DENY", "STEP_UP"} and POLICY_RESTRICTIONS.intersection(
        session["reason_codes"]
    ):
        return "confirmed"
    if session["approval_currently_usable"]:
        return "cleared"
    return "needs_evidence"


def resolve_terminal_auth_alert(
    service: ZeroTrustOperations,
    event: SecurityEvent,
    receipt: SignedAuthAttemptReceipt,
    principal: Principal,
    *,
    now: datetime | None = None,
) -> AlertDisposition:
    """Clear only a shadow alert for an authenticated gateway's exact pre-auth terminal event."""
    checked_at = now or datetime.now(UTC)
    caller_expiry = principal.authentication_expires_at
    if (
        principal.auth_method not in {"api_key", "oidc"}
        or Role.ANALYST not in principal.effective_roles
        or (principal.auth_method == "oidc" and caller_expiry is None)
        or (
            caller_expiry is not None
            and (caller_expiry.utcoffset() is None or caller_expiry <= checked_at)
        )
        or not event.user.active
        or event.device.security_posture == "compromised"
        or event.auth_context.authentication_result != "unknown"
        or event.auth_context.mfa not in {"unknown", "not_required"}
        or event.auth_context.failed_attempts != 0
    ):
        return "needs_evidence"
    try:
        receipt = SignedAuthAttemptReceipt.model_validate(receipt.model_dump(mode="json"))
        source_digest = service.signal_verifier.verify_auth_attempt(
            receipt, event, principal, checked_at
        )
        if service.has_session_event(event.event_id, principal):
            return "needs_evidence"
        checked_at = now or datetime.now(UTC)
        if (
            checked_at >= receipt.expires_at
            or (caller_expiry is not None and caller_expiry <= checked_at)
            or source_digest
            != service.signal_verifier.source_digest(
                principal.tenant_id, receipt.source_id, receipt.key_id, checked_at
            )
        ):
            return "needs_evidence"
    except (ValueError, SignalRegistryUnavailable, JournalUnavailable, OSError):
        return "needs_evidence"
    return "cleared"
