"""Exact-event, scoped Ed25519 business context for local shadow experiments.

These signed records classify business context only. They never grant access,
restore a session, suppress compromised-device evidence or authorize an action.
Authority configuration is trusted operator input, not an event-supplied key.
"""

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, field_validator

from app.models import EventAction, SecurityEvent, StrictModel

DEVIATIONS = frozenset({'authentication_failure', 'new_unmanaged_device', 'role_mismatch',
                        'remote_access', 'resource_fanout', 'bulk_export'})
Identifier = Annotated[str, Field(pattern=r'^[a-zA-Z0-9._-]{1,64}$')]


class ApprovalRejected(ValueError):
    """Bounded local reason code, without keys, signatures or event payloads."""


def require(condition, code):
    if not condition:
        raise ApprovalRejected(code)


def event_digest(event: SecurityEvent):
    # Unsigned exception claims are intentionally excluded from the authoritative
    # binding. Adding them cannot confer authority; actual security inputs remain bound.
    payload = event.analysis_payload()
    payload['behavior'].pop('policy_exception', None)
    payload['behavior'].pop('policy_exception_approved', None)
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


class ApprovalContext(StrictModel):
    schema_version: Literal['zt-business-context-1'] = 'zt-business-context-1'
    approval_id: Annotated[str, Field(pattern=r'^approval-[a-f0-9]{32}$')]
    tenant_id: Identifier
    issuer_id: Identifier
    key_id: Identifier
    event_sha256: Annotated[str, Field(pattern=r'^[a-f0-9]{64}$')]
    user_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=64)
    resource_id: str = Field(min_length=1, max_length=128)
    action: EventAction
    permitted_deviations: list[str] = Field(min_length=1, max_length=6)
    maximum_download_mb: float = Field(ge=0, allow_inf_nan=False)
    issued_at: datetime
    expires_at: datetime

    @field_validator('issued_at', 'expires_at')
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('approval timestamp requires timezone')
        return value

    @field_validator('permitted_deviations')
    @classmethod
    def deviations(cls, value):
        if len(set(value)) != len(value) or not set(value) <= DEVIATIONS:
            raise ValueError('approval deviation scope rejected')
        return value


class SignedApproval(StrictModel):
    context: ApprovalContext
    signature: str = Field(min_length=88, max_length=88)


@dataclass(frozen=True)
class Authority:
    tenant_id: str
    issuer_id: str
    key_id: str
    public_key: Ed25519PublicKey
    allowed_deviations: frozenset[str]
    user_ids: frozenset[str]
    device_ids: frozenset[str]
    resource_ids: frozenset[str]
    actions: frozenset[EventAction]
    key_not_before: datetime
    key_not_after: datetime
    active: bool = True


def canonical(context: ApprovalContext):
    return json.dumps(context.model_dump(mode='json'), ensure_ascii=False, sort_keys=True,
                      separators=(',', ':')).encode()


def sign(context: ApprovalContext, key: Ed25519PrivateKey):
    """Issuer/test utility; private keys never enter a detector event or result."""
    return SignedApproval(context=context, signature=base64.b64encode(key.sign(canonical(context))).decode())


class ApprovalVerifier:
    def __init__(self, authorities: tuple[Authority, ...], *, revoked_approval_ids=frozenset()):
        self.authorities = {}
        self.revoked = frozenset(revoked_approval_ids)
        require(len(self.revoked) <= 10000 and len(authorities) <= 100, 'approval_registry_capacity')
        fingerprints = set()
        for authority in authorities:
            key = authority.tenant_id, authority.issuer_id, authority.key_id
            require(key not in self.authorities and isinstance(authority.public_key, Ed25519PublicKey)
                    and authority.allowed_deviations <= DEVIATIONS, 'approval_registry_identity')
            require(all(0 < len(scope) <= 100 for scope in (authority.user_ids, authority.device_ids,
                    authority.resource_ids, authority.actions)), 'approval_registry_scope_required')
            require(all(isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None
                        for value in (authority.key_not_before, authority.key_not_after))
                    and authority.key_not_before < authority.key_not_after, 'approval_registry_key_window')
            fingerprint = (authority.tenant_id, authority.public_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw))
            require(fingerprint not in fingerprints, 'approval_key_alias')
            fingerprints.add(fingerprint)
            self.authorities[key] = authority

    def verify(self, signed: SignedApproval, event: SecurityEvent, tenant_id: str, *, now=None):
        now = datetime.now(UTC) if now is None else now
        require(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None,
                'approval_clock_requires_timezone')
        context = signed.context
        require(context.tenant_id == tenant_id, 'approval_tenant_mismatch')
        authority = self.authorities.get((tenant_id, context.issuer_id, context.key_id))
        require(authority is not None and authority.active, 'approval_authority_unavailable')
        require(authority.key_not_before <= now < authority.key_not_after
                and authority.key_not_before <= context.issued_at
                and context.expires_at <= authority.key_not_after, 'approval_key_window')
        require(context.approval_id not in self.revoked, 'approval_revoked')
        require(set(context.permitted_deviations) <= authority.allowed_deviations, 'approval_authority_scope')
        require(context.user_id in authority.user_ids and context.device_id in authority.device_ids
                and context.resource_id in authority.resource_ids and context.action in authority.actions,
                'approval_authority_subject_resource_scope')
        require(context.issued_at <= now < context.expires_at and
                timedelta(0) < context.expires_at-context.issued_at <= timedelta(minutes=5),
                'approval_expired_future_or_lifetime')
        require(timedelta(0) <= now-event.timestamp <= timedelta(seconds=60), 'approval_observation_stale')
        require(context.user_id == event.user.user_id and context.device_id == event.device.device_id
                and context.resource_id == event.resource.resource_id and context.action == event.action
                and context.event_sha256 == event_digest(event), 'approval_event_scope')
        require(event.behavior.download_volume_mb <= context.maximum_download_mb, 'approval_volume_scope')
        try:
            signature = base64.b64decode(signed.signature, validate=True)
            require(len(signature) == 64, 'approval_signature_shape')
            authority.public_key.verify(signature, canonical(context))
        except (ValueError, InvalidSignature):
            raise ApprovalRejected('approval_signature_rejected') from None
        return frozenset(context.permitted_deviations)
