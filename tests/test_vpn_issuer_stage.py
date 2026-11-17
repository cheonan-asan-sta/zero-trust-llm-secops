import json
import shutil
from pathlib import Path

import pytest

from scripts import fit_vpn_issuer_review as fitting
from scripts import stage_vpn_issuer_replay as staging
from scripts.f1_lab.transfer_evaluation import sha
from scripts.run_local_vpn_protocol_batch import BOOTSTRAP
from scripts.run_vpn_protocol_review import run
from tests.test_vpn_protocol_stage import fixture


def test_issuer_profile_stages_only_frozen_parameters_not_training_or_client_simulator_logs(tmp_path):
    path, _catalog, _baseline, _dump = fixture(tmp_path)
    out = tmp_path / 'package'
    report = staging.stage(path, sha(path), out)
    assert report['completed'] and report['profile'] == 'vpn-issuer'
    assert report['issuer_model_sha256'] == sha(out / 'inputs/models/issuer.json')
    assert report['frozen_training_parameters_staged'] is True and report['validation_labels_or_aggregates_staged'] is False
    assert not list((out / 'inputs').rglob('*truth*'))
    assert not list((out / 'inputs').rglob('sm.log'))
    assert not list((out / 'inputs').rglob('*training-provenance*'))
    assert all(sha(out / 'inputs' / name) == pin for name, pin in report['input_pins'].items())


@pytest.mark.parametrize('fault', ['authority', 'minimum', 'dependency', 'nontraining', 'source_duplicate', 'provenance_pin', 'phase_pool'])
def test_bundle_with_changed_parameters_training_role_or_provenance_cannot_be_staged(tmp_path, monkeypatch, fault):
    original = Path(staging.ROOT) / 'infra/f1-lab/frozen-vpn-issuer-v125'
    local_root = tmp_path / 'local-root'
    target = local_root / 'infra/f1-lab/frozen-vpn-issuer-v125'
    shutil.copytree(original, target)
    monkeypatch.setattr(staging, 'ROOT', local_root)
    bundle = json.loads((target / 'bundle.json').read_bytes())
    head = json.loads((target / 'head.json').read_bytes())
    provenance = json.loads((target / 'training-provenance.json').read_bytes())
    if fault == 'authority': head['identity_or_authority_verified'] = True
    if fault == 'minimum': head['minimum_support'] = 4
    if fault == 'dependency': head['dependencies']['protocol_model_sha256'] = 'd' * 64
    if fault == 'nontraining': provenance['training'][0]['role'] = 'observed_nontraining_calibration'
    if fault == 'source_duplicate': provenance['training'][1]['source_sha256'] = provenance['training'][0]['source_sha256']
    if fault == 'phase_pool': provenance['support_separate_by_phase'] = False
    (target / 'head.json').write_text(json.dumps(head), encoding='utf8')
    (target / 'training-provenance.json').write_text(json.dumps(provenance), encoding='utf8')
    bundle['head']['sha256'] = sha(target / 'head.json')
    bundle['training_provenance_sha256'] = 'e' * 64 if fault == 'provenance_pin' else sha(target / 'training-provenance.json')
    (target / 'bundle.json').write_text(json.dumps(bundle), encoding='utf8')
    path, _catalog, _baseline, _dump = fixture(tmp_path)
    out = tmp_path / 'package'
    with pytest.raises(ValueError):
        staging.stage(path, sha(path), out)
    assert json.loads((out / 'stage.json').read_bytes())['completed'] is False


@pytest.mark.parametrize('role', ['observed_nontraining_calibration', 'final_reserved'])
def test_training_role_change_rejected_before_any_source_body_or_truth_open(tmp_path, monkeypatch, role):
    plan = {'schema': 'vpn-protocol-training-plan-1', 'goal_qualified': False, 'scope': 'observed_development',
        'minimum_support': 5, 'sources': [{'name': name, 'role': 'training'}
            for name in ('russellmitchell', 'santos', 'shaw', 'wheeler')],
        'not_fitted_observed': ['fox', 'harrison', 'wilson', 'wardbeck']}
    plan['sources'][0]['role'] = role
    path = tmp_path / 'plan.json'
    path.write_text(json.dumps(plan), encoding='utf8')
    monkeypatch.setattr(fitting, 'get_settings', lambda: type('Settings', (), {'app_environment': 'test'})())
    monkeypatch.setattr(fitting, 'legacy', lambda *args: pytest.fail('must reject the role before model/source I/O'))
    with pytest.raises(ValueError, match='declared_training_only'):
        fitting.fit(path, sha(path), tmp_path / 'unused', 'a' * 64, tmp_path / 'unused2', 'b' * 64, tmp_path / 'result')
    assert not (tmp_path / 'result').exists()


@pytest.mark.parametrize('control,attack', [(None, False), ('control.json', False), (None, True)])
def test_issuer_pipeline_cannot_skip_prior_control_model_or_attack_retention(control, attack, tmp_path):
    with pytest.raises(ValueError, match='issuer_model_pair_and_pipeline'):
        run(tmp_path / 'not-opened-plan', 'a' * 64, '', '', '', '', tmp_path / 'not-created',
            with_attack_evidence=attack, control_model=control,
            control_model_pin='b' * 64 if control else None, issuer_model='issuer.json', issuer_model_pin='c' * 64)


def test_issuer_runner_option_is_explicit_with_no_default_activation():
    assert "if PIPELINE=='vpn-issuer':" in BOOTSTRAP
    assert "'--issuer-model','/inputs/models/issuer.json'" in BOOTSTRAP
    assert "if PIPELINE in {'vpn-control','vpn-issuer'}:" in BOOTSTRAP
