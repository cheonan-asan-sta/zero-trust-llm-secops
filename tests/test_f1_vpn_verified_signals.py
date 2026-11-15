import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.security import Principal, Role
from app.services.trusted_signals import canonical_observation, canonical_signal
from scripts.f1_lab.operation_refinement import OperationRefinement
from scripts.f1_lab.vpn_context import PROFILE
from scripts.f1_lab.vpn_risk_retention import RiskRetention
from scripts.f1_lab.vpn_signal_controls import NOW, OPERATOR, VPNControls, arguments, signature
from scripts.f1_lab.vpn_verified_signals import VerifiedVPNRisk, payload_sha


@pytest.fixture
def setup(tmp_path):
    baseline = RiskRetention(OperationRefinement(SimpleNamespace(probability=lambda _: 0.),
        SimpleNamespace(profile=PROFILE, probability=lambda _: .98)))
    controls = VPNControls(tmp_path/'control', baseline)
    return controls, VerifiedVPNRisk(baseline, controls.bridge)


def test_fresh_connection_bound_posture_permission_reduces_only_novelty(setup):
    c, model = setup
    row = c.build()
    before = model.baseline.decide(row['features'], row['case_id'], row['context'])
    result = model.decide(**arguments(row))
    assert before.alert and not result.alert and result.score == 0
    assert result.reason == 'vpn_verified_healthy_authorized_request'
    assert result.evidence_state == 'approved' and len(result.evidence_sha256) == 64
    assert not result.automatic_enforcement_allowed
    assert not list(c.directory.glob('*private*'))


@pytest.mark.parametrize('field', ['nonce', 'evidence'])
def test_missing_proof_or_nonce_keeps_original_detection(setup, field):
    c, model = setup
    row = c.build()
    row[field] = None
    result = model.decide(**arguments(row))
    assert result.alert and result.score == .98


@pytest.mark.parametrize('component', ['binding', 'identity', 'posture', 'approval'])
def test_each_signature_is_independently_required_even_when_gateway_resigns(setup, component):
    c, model = setup
    row = c.build()
    evidence = row['evidence']
    proof = getattr(evidence, component)
    signature_value = 'A'*88 if component == 'approval' else 'A'*86
    evidence = evidence.model_copy(update={component: proof.model_copy(update={'signature': signature_value})})
    if component != 'binding':
        evidence = c.resign_binding(evidence)
    row['evidence'] = evidence
    assert model.decide(**arguments(row)).alert


@pytest.mark.parametrize('changes', [
    {'device': 'compromised'}, {'device': 'at_risk'}, {'device': 'unknown'}, {'managed': False},
    {'active': False}, {'mfa': 'failed'}, {'mfa': 'unknown'}, {'authentication': 'failure'},
    {'authentication': 'unknown'}, {'event_changes': {'network': {'location_anomaly': True}}},
    {'event_changes': {'behavior': {'new_device': True}}},
    {'event_changes': {'behavior': {'unusual_time': True}}},
    {'event_changes': {'behavior': {'request_rate': 'high'}}},
    {'event_changes': {'behavior': {'distinct_resources_10m': 2}}},
])
def test_verified_adverse_device_identity_and_behavior_never_become_normal(setup, changes):
    c, model = setup
    row = c.build(**changes)
    result = model.decide(**arguments(row))
    assert result.alert and result.score == 1 and not result.automatic_enforcement_allowed


def test_permission_policy_denial_is_preserved_with_valid_device_proof(setup):
    c, model = setup
    c.policy['resources'][0]['permissions'][0]['roles'] = ['viewer']
    c.write()
    c.policies.expected_sha256 = hashlib.sha256((c.directory/'policies.json').read_bytes()).hexdigest()
    row = c.build()
    assert model.decide(**arguments(row)).score == 1


@pytest.mark.parametrize('path', ['sources.json', 'approvals.json', 'policies.json'])
def test_unavailable_changed_authority_snapshot_cannot_reduce_alarm(setup, path):
    c, model = setup
    row = c.build()
    (c.directory/path).write_bytes(b'{}')
    assert model.decide(**arguments(row)).alert


@pytest.mark.parametrize('field,value', [
    ('tenant_id', 'other'), ('gateway_id', 'other'), ('session_id', 'other-session'),
    ('session_version', 1), ('user_id', 'other-user'), ('device_id', 'other-device'),
    ('resource_id', 'other-resource'), ('peer_ip', '192.0.2.11'), ('peer_port', 443),
    ('client_certificate_sha256', 'e'*64), ('tls_channel_sha256', 'e'*64),
])
def test_valid_old_bundle_cannot_move_to_other_connection_scope(setup, field, value):
    c, model = setup
    row = c.build()
    request = row['challenge'].request.model_copy(update={field: value})
    if field == 'tenant_id':
        principal = Principal(OPERATOR.subject, 'other', OPERATOR.roles, OPERATOR.auth_method)
    else:
        principal = OPERATOR
    challenge = c.bridge.issue(request, principal, now=NOW)
    row['nonce'] = challenge.nonce
    row['principal'] = principal
    assert model.decide(**arguments(row)).alert


def test_challenge_return_value_cannot_mutate_registered_server_context(setup):
    c, model = setup
    row = c.build()
    row['challenge'].request.device_id = 'mutated'
    # The originally signed proof still matches the server's detached copy.
    assert not model.decide(**arguments(row)).alert


def test_raw_line_and_feature_tampering_keeps_alarm(setup):
    c, model = setup
    row = c.build()
    row['raw_line'] = row['raw_line'].replace('client', 'other')
    assert model.decide(**arguments(row)).alert


@pytest.mark.parametrize('seconds', [30, 31, -1])
def test_expired_and_clock_rollback_evidence_is_not_positive(setup, seconds):
    c, model = setup
    row = c.build()
    row['now'] = NOW+timedelta(seconds=seconds)
    assert model.decide(**arguments(row)).alert


def test_request_nonce_replay_and_process_restart_cannot_reuse_positive_context(setup):
    c, model = setup
    row = c.build()
    assert not model.decide(**arguments(row)).alert
    assert model.decide(**arguments(row)).alert
    c.bridge.pending.clear()  # Restart loses transient challenges; there is no allow cache.
    assert model.decide(**arguments(row)).alert


def test_concurrent_replay_can_reduce_at_most_once(setup):
    c, model = setup
    row = c.build()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: model.decide(**arguments(row)), range(2)))
    assert sum(not r.alert for r in results) == 1


def test_future_posture_rejected_even_with_valid_resigned_envelope(setup):
    c, model = setup
    row = c.build()
    p = row['evidence'].posture.model_copy(update={'observed_at': NOW+timedelta(seconds=1),
        'issued_at': NOW+timedelta(seconds=1)})
    p = p.model_copy(update={'signature': signature(c.keys['device'], canonical_observation(p))})
    row['evidence'] = c.resign_binding(row['evidence'].model_copy(update={'posture': p}))
    assert model.decide(**arguments(row)).alert


def test_expired_revoked_permission_cannot_reduce_alarm(setup):
    c, model = setup
    row = c.build()
    c.approvals['revoked_approval_ids'] = [row['evidence'].approval.context.approval_id]
    c.write()
    c.permissions.expected_sha256 = hashlib.sha256((c.directory/'approvals.json').read_bytes()).hexdigest()
    assert model.decide(**arguments(row)).alert


def test_observation_source_cannot_be_used_as_identity_authority(setup):
    c, model = setup
    row = c.build()
    identity = row['evidence'].identity.model_copy(update={'source_id': 'device'})
    identity = identity.model_copy(update={'signature': signature(c.keys['device'], canonical_signal(identity))})
    row['evidence'] = c.resign_binding(row['evidence'].model_copy(update={'identity': identity}))
    assert model.decide(**arguments(row)).alert


@pytest.mark.parametrize('message', ['AUTH_FAILED', 'TLS Error: handshake failed', '../secret',
    'cmd=x?cmd=whoami', 'sqlmap', '/etc/shadow', 'sudo -l', 'service stopped', 'client denied by server configuration'])
def test_healthy_proofs_cannot_hide_independent_raw_security_flags(setup, message):
    c, model = setup
    row = c.build(raw_message=message)
    assert model.decide(**arguments(row)).alert


def test_prior_risk_remains_despite_new_healthy_approval(setup):
    c, model = setup
    row = c.build()
    row['context'] = replace(row['context'], prior_score=.98, evidence_ordinal=2, age_seconds=1.)
    assert model.decide(**arguments(row)).alert


def test_verified_adverse_is_carried_when_later_proofs_claim_healthy(setup):
    c, model = setup
    bad = c.build(device='compromised')
    assert model.decide(**arguments(bad)).score == 1
    healthy = c.build(now=NOW+timedelta(seconds=1), index=2)
    assert model.decide(**arguments(healthy)).reason == 'vpn_recent_verified_adverse'


@pytest.mark.parametrize('principal', [
    Principal('viewer', 'vpn-lab', frozenset({Role.VIEWER}), 'api_key'),
    Principal('disabled', 'vpn-lab', frozenset({Role.ADMIN}), 'disabled'),
    Principal('other', 'other', frozenset({Role.ADMIN}), 'oidc'),
])
def test_challenge_issuance_requires_authenticated_scoped_operator(setup, principal):
    c, _ = setup
    row = c.build()
    with pytest.raises(ValueError, match='authenticated_operator'):
        c.bridge.issue(row['challenge'].request, principal, now=NOW)


def test_capacity_and_local_environment_are_enforced(setup, monkeypatch):
    c, _ = setup
    row = c.build()
    c.bridge.capacity = 1
    with pytest.raises(ValueError, match='challenge_capacity'):
        c.bridge.issue(row['challenge'].request, OPERATOR, now=NOW)
    monkeypatch.setattr('scripts.f1_lab.vpn_verified_signals.get_settings',
                        lambda: SimpleNamespace(app_environment='production'))
    with pytest.raises(ValueError, match='local_test_only'):
        c.bridge.issue(row['challenge'].request, OPERATOR, now=NOW)


def test_no_proof_path_returns_exact_existing_decision_for_untargeted_or_missing_context(setup):
    _, model = setup
    assert model.decide({}, 'id', None) == model.baseline.decide({}, 'id', None)


def test_gateway_cannot_mix_inner_evidence_from_other_request(setup):
    c, model = setup
    a = c.build()
    b = c.build(now=NOW+timedelta(seconds=1), index=2, session='another-session')
    a['evidence'] = a['evidence'].model_copy(update={'identity': b['evidence'].identity})
    assert payload_sha(a['evidence'].identity) != a['evidence'].binding.session_sha256
    a['now'] = b['now']
    assert model.decide(**arguments(a)).alert


def test_verified_adverse_adds_detection_when_old_model_is_silent(setup):
    c, model = setup
    model.baseline.vpn_model.probability = lambda _: 0.
    row = c.build(device='compromised')
    assert not model.baseline.decide(row['features'], row['case_id'], row['context']).alert
    assert model.decide(**arguments(row)).score == 1


def test_independent_security_flags_add_detection_even_with_valid_healthy_proofs(setup):
    c, model = setup
    model.baseline.vpn_model.probability = lambda _: 0.
    row = c.build(raw_message='AUTH_FAILED')
    assert model.decide(**arguments(row)).reason == 'vpn_independent_security_signal'


def test_existing_non_vpn_baseline_risk_is_never_downranked(setup):
    c, model = setup
    model.web_model.probability = lambda _: .91
    row = c.build()
    assert model.decide(**arguments(row)).score == .98


@pytest.mark.parametrize('mode', ['source', 'key', 'expiry'])
def test_current_source_key_revocation_or_expiry_invalidates_positive_proof(setup, mode):
    c, model = setup
    row = c.build()
    source = c.registry['sources'][1]
    if mode == 'source':
        source['enabled'] = False
    elif mode == 'key':
        source['keys'][0]['enabled'] = False
    else:
        source['keys'][0]['not_after'] = NOW.isoformat()
    c.write()
    c.signals.expected_sha256 = hashlib.sha256((c.directory/'sources.json').read_bytes()).hexdigest()
    assert model.decide(**arguments(row)).alert


def test_permission_signer_cannot_share_gateway_or_identity_key(setup):
    from scripts.f1_lab.approvals import sign
    c, model = setup
    row = c.build()
    c.approvals['authorities'][0]['public_key_pem'] = c.public('identity')
    c.write()
    c.permissions.expected_sha256 = hashlib.sha256((c.directory/'approvals.json').read_bytes()).hexdigest()
    proof = sign(row['evidence'].approval.context, c.keys['identity'])
    row['evidence'] = c.resign_binding(row['evidence'].model_copy(update={'approval': proof}))
    assert model.decide(**arguments(row)).alert


def test_stale_observation_is_not_refreshed_by_recent_issuance(setup):
    c, model = setup
    row = c.build()
    proof = row['evidence'].posture.model_copy(update={'observed_at': NOW-timedelta(seconds=31)})
    proof = proof.model_copy(update={'signature': signature(c.keys['device'], canonical_observation(proof))})
    row['evidence'] = c.resign_binding(row['evidence'].model_copy(update={'posture': proof}))
    assert model.decide(**arguments(row)).alert


def test_signed_security_text_in_identity_cannot_be_overridden_by_healthy_posture(setup):
    c, model = setup
    row = c.build(event_changes={'behavior': {'event_text': 'AUTH_FAILED'}})
    assert model.decide(**arguments(row)).score == 1


def test_just_before_expiry_still_requires_fresh_evidence_and_naive_clock_rejects(setup):
    c, model = setup
    row = c.build()
    row['now'] = NOW+timedelta(seconds=29)
    assert not model.decide(**arguments(row)).alert
    next_row = c.build(now=NOW+timedelta(seconds=30), index=2)
    next_row['now'] = next_row['now'].replace(tzinfo=None)
    assert model.decide(**arguments(next_row)).alert


def test_same_source_cannot_serve_different_authority_roles_under_other_key_ids(setup):
    from scripts.f1_lab.vpn_verified_signals import VPNTrustBridge
    c, _ = setup
    with pytest.raises(ValueError, match='source_separation'):
        VPNTrustBridge(c.signals, c.permissions, c.policies, c.enrollments,
            gateways={('vpn-lab', 'gateway', 'key-1'): {'gateway-local'}},
            identity_sources={('vpn-lab', 'gateway', 'key-2')},
            device_sources={('vpn-lab', 'device', 'key-1')})


@pytest.mark.parametrize("change", ["disabled", "certificate", "device", "expired"])
def test_enrollment_state_is_rechecked_with_all_signatures_valid(setup, change):
    c, model = setup
    row = c.build()
    if change == "disabled":
        c.enrollment_registry["bindings"][0]["enabled"] = False
    elif change == "certificate":
        c.enrollment_registry["bindings"][0]["client_certificate_sha256"] = "e"*64
    elif change == "device":
        c.enrollment_registry["bindings"][0]["device_id"] = "other-device"
    else:
        c.enrollment_registry["expires_at"] = NOW.isoformat()
    c.write()
    c.enrollments.expected_sha256 = hashlib.sha256((c.directory/"enrollments.json").read_bytes()).hexdigest()
    assert model.decide(**arguments(row)).alert
