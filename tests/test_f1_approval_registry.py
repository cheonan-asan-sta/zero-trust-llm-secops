import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.services.detection_benchmark import DetectionBenchmark
from scripts.f1_lab.approvals import ApprovalContext, ApprovalRejected, event_digest, sign
from scripts.f1_lab.detector import ShadowDetector
from scripts.f1_lab.registry import PinnedApprovalVerifier


@pytest.fixture
def lab(tmp_path):
    now = datetime.now(UTC)
    event = DetectionBenchmark().cases[0].event.model_copy(deep=True)
    event.timestamp = now
    key = Ed25519PrivateKey.generate()
    context = ApprovalContext(approval_id='approval-'+uuid4().hex, tenant_id='a', issuer_id='owner', key_id='key',
        event_sha256=event_digest(event), user_id=event.user.user_id, device_id=event.device.device_id,
        resource_id=event.resource.resource_id, action=event.action,
        permitted_deviations=['authentication_failure'], maximum_download_mb=0,
        issued_at=now, expires_at=now+timedelta(seconds=60))
    registry = {'schema_version': 'zt-business-authorities-1', 'version': 1, 'authorities': [{
        'tenant_id': 'a', 'issuer_id': 'owner', 'key_id': 'key',
        'public_key_pem': key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        'allowed_deviations': ['authentication_failure'], 'user_ids': [event.user.user_id],
        'device_ids': [event.device.device_id], 'resource_ids': [event.resource.resource_id],
        'actions': [event.action.value], 'key_not_before': (now-timedelta(hours=1)).isoformat(),
        'key_not_after': (now+timedelta(hours=1)).isoformat()}], 'revoked_approval_ids': []}
    path = tmp_path / 'public.json'

    def publish():
        raw = json.dumps(registry).encode()
        path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    anchor = publish()
    return event, now, sign(context, key), registry, path, publish, anchor


def test_pinned_public_registry_can_validate_context_without_any_private_key_file(lab):
    event, now, proof, _, path, _, anchor = lab
    verifier = PinnedApprovalVerifier(path, anchor, minimum_version=1)
    result = ShadowDetector(approval_verifier=verifier).evaluate(event, 'a', approval=proof, now=now)
    assert result['signed_context_status'] == 'verified' and not result['detected']
    assert b'PRIVATE KEY' not in path.read_bytes()


def test_registry_replacement_requires_new_external_anchor_and_revocation_applies(lab):
    event, now, proof, registry, path, publish, anchor = lab
    old = PinnedApprovalVerifier(path, anchor, minimum_version=1)
    assert old.verify(proof, event, 'a', now=now)
    registry['version'] = 2
    registry['revoked_approval_ids'].append(proof.context.approval_id)
    new_anchor = publish()
    with pytest.raises(ApprovalRejected, match='registry_unavailable'):
        old.verify(proof, event, 'a', now=now)
    with pytest.raises(ApprovalRejected, match='revoked'):
        PinnedApprovalVerifier(path, new_anchor, minimum_version=2).verify(proof, event, 'a', now=now)


@pytest.mark.parametrize('damage', ['key', 'active', 'scope', 'extra', 'duplicate', 'clock', 'version'])
def test_anchor_or_registry_authority_contract_fail_closed(lab, damage):
    event, now, proof, registry, path, publish, _ = lab
    if damage == 'key':
        registry['authorities'][0]['public_key_pem'] = 'PRIVATE KEY IS NOT A PUBLIC KEY'
    elif damage == 'active':
        registry['authorities'][0]['active'] = False
    elif damage == 'scope':
        registry['authorities'][0]['resource_ids'] = ['not-this-resource']
    elif damage == 'extra':
        registry['automatic_trust'] = True
    elif damage == 'duplicate':
        registry['authorities'].append(dict(registry['authorities'][0]))
    elif damage == 'clock':
        registry['authorities'][0]['key_not_before'] = '2026-01-01T00:00:00'
    else:
        registry['version'] = 0
    anchor = publish()
    with pytest.raises(ApprovalRejected):
        PinnedApprovalVerifier(path, anchor, minimum_version=1).verify(proof, event, 'a', now=now)


def test_minimum_registry_version_and_bounded_file_are_enforced(lab):
    event, now, proof, _, path, _, anchor = lab
    with pytest.raises(ApprovalRejected):
        PinnedApprovalVerifier(path, anchor, minimum_version=2).verify(proof, event, 'a', now=now)
    path.write_bytes(b' ' * 256001)
    with pytest.raises(ApprovalRejected):
        PinnedApprovalVerifier(path, anchor, minimum_version=1).verify(proof, event, 'a', now=now)
