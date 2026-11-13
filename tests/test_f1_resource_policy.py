import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from app.services.detection_benchmark import DetectionBenchmark
from scripts.f1_lab.resource_policy import PinnedResourcePolicies, ResourcePolicyUnavailable


@pytest.fixture
def policy(tmp_path):
    now = datetime.now(UTC)
    event = DetectionBenchmark().cases[0].event.model_copy(deep=True)
    event.user.role = 'employee'
    event.action = 'READ'
    body = {'schema_version': 'f1-resource-policies-1', 'version': 2,
        'issued_at': (now-timedelta(minutes=1)).isoformat(), 'expires_at': (now+timedelta(hours=1)).isoformat(),
        'resources': [{'tenant_id': 'tenant-a', 'resource_id': event.resource.resource_id,
            'sensitivity': 'critical', 'permissions': [{'action': 'READ', 'roles': ['employee', 'viewer']}]}]}
    path = tmp_path/'policy.json'

    def publish():
        raw = json.dumps(body).encode()
        path.write_bytes(raw)
        return PinnedResourcePolicies(path, hashlib.sha256(raw).hexdigest(), minimum_version=2)

    return event, now, body, path, publish


def test_exact_policy_allows_multiple_roles_without_trusting_event_required_role(policy):
    event, now, _body, _path, publish = policy
    event.resource.required_role = 'administrator'
    result = publish().resolve(event, 'tenant-a', now=now)
    assert result.role_and_action_allowed and result.effective_sensitivity == 'critical'
    assert result.version == 2


@pytest.mark.parametrize('change', ['role', 'action', 'tenant', 'resource'])
def test_policy_cannot_expand_to_other_identity_role_action_or_resource(policy, change):
    event, now, _body, _path, publish = policy
    verifier = publish()
    tenant = 'tenant-a'
    if change == 'role':
        event.user.role = 'administrator'
    elif change == 'action':
        event.action = 'ADMIN'
    elif change == 'tenant':
        tenant = 'tenant-b'
    else:
        event.resource.resource_id = 'unregistered'
    if change in {'tenant', 'resource'}:
        with pytest.raises(ResourcePolicyUnavailable):
            verifier.resolve(event, tenant, now=now)
    else:
        assert not verifier.resolve(event, tenant, now=now).role_and_action_allowed


@pytest.mark.parametrize('damage', ['expired', 'future', 'naive', 'long_lifetime', 'old_version',
    'duplicate_resource', 'duplicate_action', 'wildcard_role', 'duplicate_role', 'private_key'])
def test_invalid_operator_policy_is_not_an_allowing_default(policy, damage):
    event, now, body, _path, publish = policy
    resource = body['resources'][0]
    if damage == 'expired':
        body['expires_at'] = now.isoformat()
    elif damage == 'future':
        body['issued_at'] = (now+timedelta(seconds=1)).isoformat()
    elif damage == 'naive':
        body['issued_at'] = now.replace(tzinfo=None).isoformat()
    elif damage == 'long_lifetime':
        body['expires_at'] = (now+timedelta(days=2)).isoformat()
    elif damage == 'old_version':
        body['version'] = 1
    elif damage == 'duplicate_resource':
        body['resources'].append(resource)
    elif damage == 'duplicate_action':
        resource['permissions'].append(resource['permissions'][0])
    elif damage == 'wildcard_role':
        resource['permissions'][0]['roles'] = ['*']
    elif damage == 'duplicate_role':
        resource['permissions'][0]['roles'] = ['employee', 'employee']
    else:
        body['private_key'] = 'forbidden'
    with pytest.raises(ResourcePolicyUnavailable):
        publish().resolve(event, 'tenant-a', now=now)


def test_changed_policy_bytes_and_higher_reported_sensitivity_are_not_silent_downgrades(policy):
    event, now, body, path, publish = policy
    body['resources'][0]['sensitivity'] = 'public'
    verifier = publish()
    event.resource.sensitivity = 'critical'
    assert verifier.resolve(event, 'tenant-a', now=now).effective_sensitivity == 'critical'
    path.write_bytes(path.read_bytes()+b'\n')
    with pytest.raises(ResourcePolicyUnavailable):
        verifier.resolve(event, 'tenant-a', now=now)


@pytest.mark.parametrize('anchor,minimum', [('', 1), ('a'*64, True), ('g'*64, 1), ('a'*64, 0)])
def test_policy_pin_and_minimum_version_are_explicit(policy, anchor, minimum):
    _event, _now, _body, path, _publish = policy
    with pytest.raises(ResourcePolicyUnavailable, match='anchor'):
        PinnedResourcePolicies(path, anchor, minimum_version=minimum)


def test_ambiguous_duplicate_json_keys_are_rejected_even_with_a_matching_pin(policy):
    event, now, body, path, _publish = policy
    raw = json.dumps(body).encode().replace(b'"version": 2', b'"version": 1, "version": 2')
    path.write_bytes(raw)
    with pytest.raises(ResourcePolicyUnavailable):
        PinnedResourcePolicies(path, hashlib.sha256(raw).hexdigest(), minimum_version=2).resolve(event, 'tenant-a', now=now)


def test_loaded_batch_snapshot_has_immutable_nested_policy_scopes(policy):
    event, now, _body, _path, publish = policy
    snapshot = publish().snapshot(now=now)
    identity = 'tenant-a', event.resource.resource_id
    with pytest.raises(TypeError):
        snapshot.resources[identity] = ('public', {})
    with pytest.raises(TypeError):
        snapshot.resources[identity][1]['ADMIN'] = frozenset({'employee'})
