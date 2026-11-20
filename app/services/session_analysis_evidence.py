"""Read-only, exact-session evidence collection for advisory LLM analysis.

Signature verification proves the registered collector signed its claims. It does
not prove a real human authenticated at an independently contacted enterprise IdP.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from app.models import SecurityEvent
from app.security import Principal, Role
from app.services.settled_io import settled_io
from app.services.trusted_signals import SignalRejected
from app.zero_trust_models import SignedSessionSignal

if TYPE_CHECKING:
    from app.services.zero_trust import ZeroTrustOperations

_TIMESTAMP_TYPE = datetime
_REMOTE_LOGON_RULE_ID = "d1e2f3a4-b5c6-4d7e-8f90-a1b2c3d4e5f6"


def event_digest(event: SecurityEvent) -> str:
    return hashlib.sha256(
        json.dumps(
            event.analysis_payload(), sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode()
    ).hexdigest()


@dataclass(frozen=True)
class VerifiedSessionContext:
    """Internal immutable snapshot; never accepted as a client request field."""

    event_digest_sha256: str
    expires_at: datetime
    facts_json: bytes
    verify_current: Callable[[], None] | None = field(default=None, repr=False, compare=False)

    def for_event(self, event: SecurityEvent, *, now: datetime | None = None) -> dict:
        now = now or datetime.now(UTC)
        if now >= self.expires_at or event_digest(event) != self.event_digest_sha256:
            raise SignalRejected("analysis evidence expired or event binding changed")
        return json.loads(self.facts_json)

    async def revalidate(self, event: SecurityEvent) -> dict:
        """Settle live source I/O, then check binding/expiry at the current time."""
        if self.verify_current is not None:
            await settled_io(self.verify_current)
        return self.for_event(event)


def collect_session_evidence(
    service: ZeroTrustOperations,
    signal: SignedSessionSignal,
    principal: Principal,
    *,
    now: datetime | None = None,
) -> VerifiedSessionContext:
    """Collect current server policy and persisted signed-session state; writes nothing."""
    from app.services.zero_trust import SessionConflict

    now = now or datetime.now(UTC)
    if (
        principal.auth_method not in {"api_key", "oidc"}
        or Role.ANALYST not in principal.effective_roles
    ):
        raise SignalRejected("authenticated analyst authority required")
    caller_expiry = principal.authentication_expires_at
    if principal.auth_method == "oidc" and caller_expiry is None:
        raise SignalRejected("OIDC caller expiration evidence required")
    if caller_expiry is not None and (
        not isinstance(caller_expiry, _TIMESTAMP_TYPE)
        or caller_expiry.utcoffset() is None
        or caller_expiry <= now
    ):
        raise SignalRejected("caller authentication expired or invalid")
    # Revalidate Python model_copy bypasses as strictly as HTTP input.
    signal = SignedSessionSignal.model_validate(signal.model_dump(mode="json"))
    proof = service.signal_verifier.verify(signal, principal, now)
    history, grant_consumed = service.analysis_history(signal.session_id, principal)
    current = history[-1]
    matching = [
        s
        for s in history
        if s.input_digest_sha256 == proof.input_digest
        and s.event_id == signal.event.event_id
        and s.version == signal.expected_version + 1
    ]
    if not matching or (
        current.input_digest_sha256 != proof.input_digest
        or current.observed_at != signal.event.timestamp
        or current.user_id != signal.event.user.user_id
        or current.device_id != signal.event.device.device_id
        or current.resource_id != signal.event.resource.resource_id
        or current.action != signal.event.action
        or current.operator_id != principal.subject
        or current.signal_trust != "verified_source"
        or current.signal_source_id != proof.source_id
        or current.signal_key_id != proof.key_id
        or current.signal_source_digest != proof.source_digest
    ):
        raise SessionConflict("analysis requires the current exact verified session input")
    if (
        current.policy_digest_sha256 != service.policy_digest
        or hashlib.sha256(service.policy.model_dump_json().encode()).hexdigest()
        != service.policy_digest
    ):
        raise SessionConflict("analysis policy changed since session evaluation")
    policy = next(
        (p for p in service.policy.resources if p.resource_id == signal.event.resource.resource_id),
        None,
    )
    max_age = policy.max_signal_age_seconds if policy else 60
    event_age = (now - signal.event.timestamp).total_seconds()
    if not -30 <= event_age < max_age or current.evaluated_at > now:
        raise SignalRejected("analysis event freshness rejected")
    # Recheck authority after reading the journal; never turn withdrawn authority into an approval.
    if (
        service.signal_verifier.source_digest(
            principal.tenant_id, proof.source_id, proof.key_id, now
        )
        != proof.source_digest
    ):
        raise SignalRejected("analysis source authority changed")
    expires = min(proof.expires_at, signal.event.timestamp + timedelta(seconds=max_age))
    if current.signal_expires_at is None or current.signal_expires_at <= now:
        raise SignalRejected("persisted session proof expired")
    expires = min(expires, current.signal_expires_at)
    if caller_expiry is not None:
        expires = min(expires, caller_expiry)
    approval_usable = bool(
        current.decision == "ALLOW"
        and current.status == "ACTIVE"
        and current.grant_expires_at
        and current.grant_expires_at > now
        and current.challenge_id is None
        and not grant_consumed
    )
    # A positive approval assertion must not outlive the grant it describes.
    # This remains a snapshot, never a token that can be redeemed for access.
    if approval_usable:
        expires = min(expires, current.grant_expires_at)
    facts = {
        "scope": "current_local_zero_trust_session_snapshot_not_historical_backfill",
        "collected_at": now.isoformat(),
        "valid_until": expires.isoformat(),
        "tenant_id": principal.tenant_id,
        "caller": {
            "authentication_method": principal.auth_method,
            "session_operator_binding_verified": True,
            "identity_scope": "request_operator_only_not_event_subject",
            "event_subject_mfa_independently_verified": False,
        },
        "policy": {
            "origin": "server_owned_configuration",
            "version": service.policy.version,
            "digest_sha256": service.policy_digest,
            "resource_registered": policy is not None,
            "role_permitted": signal.event.user.role in policy.roles if policy else False,
            "action_permitted": signal.event.action in policy.actions if policy else False,
            "mfa_required": policy.require_mfa if policy else None,
            "managed_device_required": policy.require_managed if policy else None,
        },
        "signal": {
            "signature_verified": True,
            "source_id": proof.source_id,
            "key_id": proof.key_id,
            "source_digest_sha256": proof.source_digest,
            "authentication_observation": signal.event.auth_context.authentication_result,
            "mfa_observation": signal.event.auth_context.mfa,
            "meaning": "Registered collector assertion; external human/IdP not independently verified.",
        },
        "session": {
            "input_digest_sha256": proof.input_digest,
            "version": current.version,
            "decision": current.decision,
            "status": current.status,
            "reason_codes": current.reason_codes,
            "only_generic_remote_logon_rule_matched": current.matched_rule_ids == [_REMOTE_LOGON_RULE_ID],
            "challenge_pending": current.challenge_id is not None,
            "approval_currently_usable": approval_usable,
        },
        "not_an_access_grant": True,
        "external_enterprise_identity_verified": False,
    }
    if caller_expiry is not None:
        facts["caller"]["authentication_valid_until"] = caller_expiry.isoformat()
    return VerifiedSessionContext(
        event_digest(signal.event),
        expires,
        json.dumps(facts, sort_keys=True, ensure_ascii=False).encode(),
    )
