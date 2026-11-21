"""Resolve a shadow authentication alert using current, server-verified session evidence."""

from typing import Literal

from app.models import SecurityEvent
from app.security import Principal
from app.services.session_analysis_evidence import collect_session_evidence
from app.services.trusted_signals import SignalRejected
from app.services.zero_trust import SessionConflict, SessionMissing, ZeroTrustOperations
from app.zero_trust_models import SignedSessionSignal

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
    except (SignalRejected, SessionConflict, SessionMissing, OSError):
        return "needs_evidence"

    session = facts["session"]
    if session["decision"] in {"DENY", "STEP_UP"} and POLICY_RESTRICTIONS.intersection(
        session["reason_codes"]
    ):
        return "confirmed"
    if session["approval_currently_usable"]:
        return "cleared"
    return "needs_evidence"
