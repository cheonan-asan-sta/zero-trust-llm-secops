from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.security import Principal, Role
from scripts.f1_lab.operation_refinement import OperationRefinement
from scripts.f1_lab.vpn_context import PROFILE
from scripts.f1_lab.web_context_controls import NOW, OPERATOR, WebControls, arguments, sign
from scripts.f1_lab.web_residual import WebResidualRefinement
from scripts.f1_lab.web_verified_context import (
    PinnedWebRegistry,
    Runtime,
    VerifiedWebRisk,
    WebBundle,
    WebTrustBridge,
    digest_raw,
)


@pytest.fixture
def setup(tmp_path):
    controls = WebControls(tmp_path/'controls')
    base = WebResidualRefinement(OperationRefinement(SimpleNamespace(probability=lambda _: .02),
        SimpleNamespace(profile=PROFILE, probability=lambda _: .98)))
    return controls, VerifiedWebRisk(base, controls.bridge)


@pytest.mark.parametrize('changes', [{'permission':'deny'}, {'authentication':'failure'}, {'mfa':'failure'}])
def test_verified_failure_with_execution_adds_alert_without_access_effects(setup, changes):
    c, model = setup
    row = c.build(**changes)
    old = model.baseline.decide(row['features'], row['case_id'], evidence=row['evidence'])
    new = model.decide(**arguments(row))
    assert not old.alert and old.review
    assert new.alert and new.review and new.score == 1. and new.evidence_state == 'adverse'
    assert not new.automatic_enforcement_allowed and len(new.evidence_sha256) == 64


@pytest.mark.parametrize('changes,state', [({},'consistent'), ({'permission':'deny','executed':False},'review'),
    ({'authentication':'unknown'},'incomplete'), ({'permission':'unknown'},'incomplete'),
    ({'executed':None},'incomplete'), ({'mfa':'unknown'},'review'), ({'mfa':'not_used'},'review')])
def test_allow_unknown_and_contained_denial_never_clear_or_invent_alerts(setup, changes, state):
    c, model = setup
    row = c.build(**changes)
    new = model.decide(**arguments(row))
    assert new.evidence_state == state and not new.alert and new.review and new.score == .02


@pytest.mark.parametrize('score', [.95, .99, 1.])
def test_consistent_server_proofs_cannot_downrank_existing_security_alert(setup, score):
    c, model = setup
    model.baseline.baseline.web_model.probability = lambda _: score
    row = c.build()
    new = model.decide(**arguments(row))
    assert new.alert and new.review and new.score == score and new.evidence_state == 'consistent'


def test_no_nonce_path_returns_exact_existing_decision_without_reading_proof_or_registry(setup):
    c, model = setup
    row = c.build(permission='deny')
    old = model.baseline.decide(row['features'], row['case_id'], evidence=row['evidence'])
    (c.directory/'web-registry.json').unlink()
    row['nonce'] = None
    assert model.decide(**arguments(row)) == old


@pytest.mark.parametrize('kind', ['authentication','authorization','runtime'])
def test_each_role_signature_must_be_valid_independently(setup, kind):
    c, model = setup
    row = c.build(permission='deny')
    proofs = [p.model_copy(update={'signature':'A'*86}) if p.observation.kind == kind else p for p in row['bundle'].proofs]
    row['bundle'] = row['bundle'].model_copy(update={'proofs':proofs})
    new = model.decide(**arguments(row))
    assert not new.alert and new.evidence_state == 'unavailable'


@pytest.mark.parametrize('changes', [
    {'tenant_id':'other'}, {'server_id':'other'}, {'request_id':'other'}, {'subject_id':'other'},
    {'session_id':'other'}, {'session_version':1}, {'resource_id':'other'}, {'body_sha256':'b'*64},
    {'target_sha256':'b'*64}, {'case_id':'b'*64}, {'method':'POST'}, {'raw_line_sha256':'b'*64},
])
def test_valid_proofs_cannot_move_to_new_request_body_session_or_tenant(setup, changes):
    c, model = setup
    row = c.build(permission='deny')
    request = row['challenge'].request.model_copy(update=changes)
    principal = Principal(OPERATOR.subject, request.tenant_id, OPERATOR.roles, OPERATOR.auth_method)
    other = c.bridge.issue(request, principal, now=NOW)
    row.update(nonce=other.nonce, principal=principal)
    new = model.decide(**arguments(row))
    assert not new.alert and new.evidence_state == 'unavailable'


@pytest.mark.parametrize('change', ['disabled','expired','scope','policy','policy_version','key_reused','source_reused','duplicate_resource'])
def test_current_registry_and_pinned_policy_cannot_be_bypassed_with_valid_signatures(setup, change):
    c, model = setup
    row = c.build(permission='deny')
    authority = c.registry['authorities'][0]
    if change == 'disabled': authority['enabled'] = False
    elif change == 'expired': authority['expires_at'] = NOW.isoformat()
    elif change == 'scope': authority['subject_ids'] = ['other']
    elif change == 'policy': c.registry['resources'][0]['authorization_policy_sha256'] = 'b'*64
    elif change == 'policy_version': c.registry['resources'][0]['minimum_policy_version'] = 2
    elif change == 'key_reused': c.registry['authorities'][1]['public_key'] = authority['public_key']
    elif change == 'source_reused': c.registry['authorities'][1]['source_id'] = authority['source_id']
    else: c.registry['resources'].append(c.registry['resources'][0].copy())
    c.repin()
    new = model.decide(**arguments(row))
    assert not new.alert and new.evidence_state == 'unavailable'


def test_registry_hash_change_cannot_silently_repin_and_no_positive_cache(setup):
    c, model = setup
    row = c.build()
    assert model.decide(**arguments(row)).evidence_state == 'consistent'
    next_row = c.build(index=2)
    c.registry['version'] = 2
    c.write()
    assert model.decide(**arguments(next_row)).evidence_state == 'unavailable'


def test_challenge_return_value_is_detached_from_server_pending_state(setup):
    c, model = setup
    row = c.build(permission='deny')
    row['challenge'].request.subject_id = 'tampered'
    assert model.decide(**arguments(row)).evidence_state == 'adverse'


def test_nonce_is_single_use_and_restart_has_no_accepted_evidence_cache(setup):
    c, model = setup
    row = c.build(permission='deny')
    assert model.decide(**arguments(row)).alert
    assert model.decide(**arguments(row)).evidence_state == 'unavailable'
    second = c.build(index=2, permission='deny')
    model.bridge = WebTrustBridge(c.pinned)
    assert model.decide(**arguments(second)).evidence_state == 'unavailable'


def test_two_concurrent_proof_uses_can_escalate_at_most_once(setup):
    c, model = setup
    row = c.build(permission='deny')
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _:model.decide(**arguments(row)),range(2)))
    assert sum(r.alert for r in results) == 1


@pytest.mark.parametrize('seconds', [-1,30,31])
def test_future_rollback_or_expired_challenge_keeps_prior_decision(setup, seconds):
    c, model = setup
    row = c.build(permission='deny')
    row['now'] = NOW+timedelta(seconds=seconds)
    assert model.decide(**arguments(row)).evidence_state == 'unavailable'


@pytest.mark.parametrize('field', ['issued_at','observed_at','expires_at'])
def test_fresh_signature_cannot_hide_future_or_stale_observation(setup, field):
    c, model = setup
    row = c.build(permission='deny')
    value = NOW-timedelta(seconds=1) if field == 'observed_at' else NOW+timedelta(seconds=31)
    c.resign(row, 'runtime', **{field:value})
    assert model.decide(**arguments(row)).evidence_state == 'unavailable'


def test_duplicate_or_mixed_request_proof_cannot_replace_missing_role(setup):
    c, model = setup
    row = c.build(permission='deny')
    other = c.build(index=2)
    # Same log content, different request ID and nonce still give different digests.
    proofs = row['bundle'].proofs
    row['bundle'] = WebBundle(proofs=[proofs[0],proofs[1],other['bundle'].proofs[2]])
    assert model.decide(**arguments(row)).evidence_state == 'unavailable'


def test_wrong_operator_cannot_consume_another_operators_pending_nonce(setup):
    c, model = setup
    row = c.build(permission='deny')
    row['principal'] = Principal('another-analyst', OPERATOR.tenant_id, OPERATOR.roles, 'oidc')
    assert model.decide(**arguments(row)).evidence_state == 'unavailable'
    row['principal'] = OPERATOR
    assert model.decide(**arguments(row)).alert


@pytest.mark.parametrize('principal', [Principal('v','web-lab',frozenset({Role.VIEWER}),'api_key'),
    Principal('x','other',frozenset({Role.ADMIN}),'oidc'),
    Principal('x','web-lab',frozenset({Role.ADMIN}),'disabled')])
def test_issue_requires_authenticated_tenant_scoped_operator(setup, principal):
    c, _ = setup
    row = c.build()
    with pytest.raises(ValueError,match='operator'):
        c.bridge.issue(row['challenge'].request,principal,now=NOW)


def test_raw_and_feature_tampering_cannot_create_new_detection_and_burn_attempt(setup):
    c, model = setup
    row = c.build(permission='deny')
    row['raw_line'] = row['raw_line'].replace('local-test','different')
    assert not model.decide(**arguments(row)).alert
    row['raw_line'] = row['raw_line'].replace('different','local-test')
    assert model.decide(**arguments(row)).evidence_state == 'unavailable'
    row = c.build(index=2,permission='deny')
    row['evidence'] = None
    row['features']['http_method'] = 'POST'
    assert not model.decide(**arguments(row)).alert
    row['features']['http_method'] = 'GET'
    assert model.decide(**arguments(row)).evidence_state == 'unavailable'


def test_production_mode_pending_capacity_and_naive_clock_are_rejected(setup, monkeypatch):
    c, model = setup
    row = c.build()
    c.bridge.capacity = 1
    with pytest.raises(ValueError,match='capacity'):
        c.bridge.issue(row['challenge'].request,OPERATOR,now=NOW)
    row['now'] = NOW.replace(tzinfo=None)
    assert model.decide(**arguments(row)).evidence_state == 'unavailable'
    monkeypatch.setattr('scripts.f1_lab.web_verified_context.get_settings',lambda:SimpleNamespace(app_environment='production'))
    with pytest.raises(ValueError,match='local_test_only'):
        c.bridge.issue(row['challenge'].request,OPERATOR,now=NOW)


@pytest.mark.parametrize('data', [
    {'kind':'runtime','executed':True,'executable_sha256':None,'process_ref_sha256':None},
    {'kind':'runtime','executed':False,'executable_sha256':'a'*64,'process_ref_sha256':'b'*64},
    {'kind':'runtime','executed':'true','executable_sha256':'a'*64,'process_ref_sha256':'b'*64},
])
def test_execution_is_explicit_and_not_invented_from_missing_or_coerced_fields(data):
    with pytest.raises(ValueError): Runtime.model_validate(data)


def test_authorization_signer_cannot_pose_as_runtime_signer(setup):
    c, model = setup
    row = c.build(permission='deny')
    proof = row['bundle'].proofs[2].model_copy(update={'source_id':'authorization'})
    proof = sign(proof,c.keys['authorization'])
    row['bundle'] = WebBundle(proofs=[*row['bundle'].proofs[:2],proof])
    assert model.decide(**arguments(row)).evidence_state == 'unavailable'


def test_registry_version_and_required_fields_are_not_optional(setup):
    c, model = setup
    row = c.build(permission='deny')
    c.pinned.minimum_version = 2
    assert model.decide(**arguments(row)).evidence_state == 'unavailable'
    with pytest.raises(ValueError):
        PinnedWebRegistry(c.directory/'web-registry.json', 'bad', minimum_version=1)
    assert not list(c.directory.glob('*private*'))
    assert digest_raw('') == row['challenge'].request.body_sha256  # Authored explicitly empty body.


def test_complete_control_runner_uses_only_public_registry_and_keeps_scope_explicit(tmp_path, monkeypatch):
    import json

    from scripts import run_web_context_controls as runner
    (tmp_path/'prior.json').write_text('{"completed":true}')
    payload = {'schema':'f1-web-context-controls-1','scope':runner.SCOPE,'score_lowering_allowed':False,
        'automatic_enforcement_allowed':False,'v44_receipt':{'path':'prior.json',
        'sha256':digest_raw((tmp_path/'prior.json').read_text())}}
    path = tmp_path/'plan.json'
    path.write_text(json.dumps(payload))
    monkeypatch.setattr(runner,'ROOT',tmp_path)
    # Real source fingerprints without copying or executing any untrusted source.
    def fingerprint(p):
        return {'path':str(p),'sha256':'a'*64}
    monkeypatch.setattr(runner,'fingerprint',fingerprint)
    result = runner.run(path,digest_raw(path.read_text()),tmp_path/'out')
    assert result['completed'] and result['summary']['expected_outcomes_passed'] == 13
    assert not result['detection_f1_measured'] and result['actual_server_observations_collected'] == 0
    assert not list((tmp_path/'out').rglob('*private*'))
    with pytest.raises(ValueError,match='fresh_output'):
        runner.run(path,digest_raw(path.read_text()),tmp_path/'out')
