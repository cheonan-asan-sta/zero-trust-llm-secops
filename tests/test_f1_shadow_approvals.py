from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.services.detection_benchmark import DetectionBenchmark
from scripts.f1_lab.approvals import (
    ApprovalContext,
    ApprovalRejected,
    ApprovalVerifier,
    Authority,
    event_digest,
    sign,
)


@pytest.fixture
def lab():
    event = DetectionBenchmark().cases[0].event.model_copy(deep=True)
    now = datetime.now(UTC)
    event.timestamp = now
    key = Ed25519PrivateKey.generate()
    context = ApprovalContext(approval_id='approval-' + uuid4().hex, tenant_id='tenant-a',
        issuer_id='business-owner', key_id='key-1', event_sha256=event_digest(event),
        user_id=event.user.user_id, device_id=event.device.device_id,
        resource_id=event.resource.resource_id, action=event.action,
        permitted_deviations=['authentication_failure'], maximum_download_mb=0,
        issued_at=now, expires_at=now+timedelta(minutes=1))
    authority = Authority('tenant-a', 'business-owner', 'key-1', key.public_key(),
                          frozenset({'authentication_failure'}), frozenset({event.user.user_id}),
                          frozenset({event.device.device_id}), frozenset({event.resource.resource_id}),
                          frozenset({event.action}))
    return event, now, key, context, authority


def test_signed_approval_covers_exact_fresh_event_and_has_no_execution_effect(lab):
    event, now, key, context, authority = lab
    verifier = ApprovalVerifier((authority,))
    proof = sign(context, key)
    assert verifier.verify(proof, event, 'tenant-a', now=now) == frozenset({'authentication_failure'})
    # Repeat classification of the same immutable event is idempotent advice, not an access capability.
    assert verifier.verify(proof, event, 'tenant-a', now=now) == verifier.verify(proof, event, 'tenant-a', now=now)


@pytest.mark.parametrize('field', ['user', 'device', 'resource', 'action', 'mfa', 'posture', 'volume', 'event_id'])
def test_approval_cannot_move_to_another_or_modified_event(lab, field):
    event, now, key, context, authority = lab
    proof = sign(context, key)
    changed = event.model_copy(deep=True)
    if field in {'user', 'device', 'resource'}:
        setattr(getattr(changed, field), field + '_id', 'different')
    elif field == 'action':
        changed.action = 'READ'
    elif field == 'mfa':
        changed.auth_context.mfa = 'unknown'
    elif field == 'posture':
        changed.device.security_posture = 'compromised'
    elif field == 'volume':
        changed.behavior.download_volume_mb = 1
    else:
        changed.event_id = 'different'
    with pytest.raises(ApprovalRejected):
        ApprovalVerifier((authority,)).verify(proof, changed, 'tenant-a', now=now)


@pytest.mark.parametrize('seconds', [-1, 60, 61, 600])
def test_strict_future_expiry_and_observation_age(lab, seconds):
    event, now, key, context, authority = lab
    with pytest.raises(ApprovalRejected):
        ApprovalVerifier((authority,)).verify(sign(context, key), event, 'tenant-a', now=now+timedelta(seconds=seconds))


@pytest.mark.parametrize('failure', ['tenant', 'wrong_key', 'revoked', 'inactive', 'scope', 'too_long', 'unsigned_edit'])
def test_trust_authority_and_signature_fail_closed(lab, failure):
    event, now, key, context, authority = lab
    revoked = frozenset()
    tenant = 'tenant-a'
    proof = sign(context, key)
    if failure == 'tenant':
        tenant = 'tenant-b'
    elif failure == 'wrong_key':
        proof = sign(context, Ed25519PrivateKey.generate())
    elif failure == 'revoked':
        revoked = {context.approval_id}
    elif failure == 'inactive':
        authority = replace(authority, active=False)
    elif failure == 'scope':
        changed = context.model_copy(update={'permitted_deviations': ['remote_access']})
        proof = sign(changed, key)
    elif failure == 'too_long':
        proof = sign(context.model_copy(update={'expires_at': now+timedelta(minutes=6)}), key)
    else:
        proof.context.approval_id = 'approval-' + uuid4().hex
    with pytest.raises(ApprovalRejected):
        ApprovalVerifier((authority,), revoked_approval_ids=revoked).verify(proof, event, tenant, now=now)


def test_unsigned_approval_claim_does_not_create_a_proof_and_cannot_expand_signed_scope(lab):
    event, now, key, context, authority = lab
    original = event_digest(event)
    event.behavior.policy_exception_approved = True
    assert event_digest(event) == original
    assert ApprovalVerifier((authority,)).verify(sign(context, key), event, 'tenant-a', now=now) == frozenset({
        'authentication_failure'})


def test_duplicate_or_wrong_registry_and_naive_clock_rejected(lab):
    event, now, key, context, authority = lab
    with pytest.raises(ApprovalRejected):
        ApprovalVerifier((authority, authority))
    with pytest.raises(ApprovalRejected):
        ApprovalVerifier((authority,)).verify(sign(context, key), event, 'tenant-a', now=now.replace(tzinfo=None))


@pytest.mark.parametrize('scope', ['user_ids', 'device_ids', 'resource_ids', 'actions'])
def test_signing_key_cannot_approve_outside_its_registered_authority(lab, scope):
    event, now, key, context, authority = lab
    authority = replace(authority, **{scope: frozenset({'different'})})
    with pytest.raises(ApprovalRejected, match='subject_resource_scope'):
        ApprovalVerifier((authority,)).verify(sign(context, key), event, 'tenant-a', now=now)


def test_same_signing_key_cannot_alias_another_issuer(lab):
    _, _, _, _, authority = lab
    alias = replace(authority, issuer_id='another-issuer', key_id='key-2')
    with pytest.raises(ApprovalRejected, match='key_alias'):
        ApprovalVerifier((authority, alias))
