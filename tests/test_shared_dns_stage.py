import hashlib
import json

import pytest

from scripts import stage_shared_dns_replay as staging
from scripts.f1_lab.transfer_evaluation import sha
from tests.test_shared_dns_capture_intake import make_lab, run


@pytest.fixture
def staged_inputs(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    manifest_path = lab.raw / 'audit.json'
    manifest = json.loads(manifest_path.read_bytes())
    manifest['pairs'][0]['provenance'].update(simulation_start=1642684600, simulation_end=1642684700)
    manifest_path.write_text(json.dumps(manifest), encoding='utf8')
    prep = json.loads(lab.prep.read_bytes())
    prep['pairs'][0]['rows'] = 1
    prep['source_manifest_sha256'] = sha(manifest_path)
    lab.prep.write_text(json.dumps(prep), encoding='utf8')
    run(lab, tmp_path)
    intake_path = tmp_path / 'result/run.json'
    source_pin = prep['pairs'][0]['raw_sha256']
    baseline = tmp_path / 'before.jsonl'
    baseline.write_text(json.dumps({'case_id': hashlib.sha256((source_pin + ':1').encode()).hexdigest(),
        'source_index': 0, 'before': False, 'after': False, 'before_score': 0.0, 'after_score': 0.0,
        'reason': 'unchanged', 'error': None}) + '\n', encoding='utf8')
    catalog = {'schema': 'vpn-protocol-replay-catalog-1', 'goal_qualified': False, 'scope': 'observed_development',
        'scenarios': [{'name': 'sample', 'preparation': str(lab.prep), 'preparation_sha256': sha(lab.prep),
                       'raw': str(lab.raw), 'baseline': str(baseline), 'baseline_sha256': sha(baseline), 'population': 1}],
        'shared_dns_support': [{'scenario': 'sample', 'source_index': 0,
                                'intake': str(intake_path), 'intake_sha256': sha(intake_path)}]}
    path = tmp_path / 'catalog.json'
    path.write_text(json.dumps(catalog), encoding='utf8')
    return path, catalog, intake_path


def test_stage_only_observations_and_report_reference_not_archives_stats_or_labels(staged_inputs, tmp_path):
    path, _catalog, _intake = staged_inputs
    package = tmp_path / 'package'
    result = staging.stage(path, sha(path), package)
    assert result['completed'] and result['profile'] == 'shared-dns-native'
    assert result['frozen_training_parameters_staged'] is False
    assert result['validation_labels_or_aggregates_staged'] is False
    native = package / 'inputs/native-dns/source-0'
    assert {p.name for p in native.iterdir()} == {'manifest.json', 'shared-dns-observations.jsonl'}
    assert not (package / 'inputs/models/head.json').exists()
    assert not list((package / 'inputs').rglob('*.pcap'))
    assert not list((package / 'inputs').rglob('*truth*'))
    assert sha(package / 'inputs/native-dns-catalog.json') == result['native_catalog_sha256']


@pytest.mark.parametrize('fault', ['not_completed', 'actor', 'receipt', 'not_offline_admitted', 'fresh_final'])
def test_unverified_or_different_scope_input_cannot_mark_package_complete(staged_inputs, tmp_path, fault):
    path, catalog, intake_path = staged_inputs
    value = json.loads(intake_path.read_bytes())
    key, bad = {'not_completed': ('completed', False), 'actor': ('actor_or_authority_proven', True),
                'receipt': ('historical_application_receipt_proven', True),
                'not_offline_admitted': ('admitted_to_offline_native_replay', False),
                'fresh_final': ('role', 'final_reserved')}[fault]
    value[key] = bad
    intake_path.write_text(json.dumps(value), encoding='utf8')
    catalog['shared_dns_support'][0]['intake_sha256'] = sha(intake_path)
    path.write_text(json.dumps(catalog), encoding='utf8')
    with pytest.raises(ValueError):
        staging.stage(path, sha(path), tmp_path / 'package')
    assert json.loads((tmp_path / 'package/stage.json').read_bytes())['completed'] is False


def test_truth_injection_rejected_even_if_file_and_receipt_are_resigned(staged_inputs, tmp_path):
    path, catalog, intake_path = staged_inputs
    observed = intake_path.parent / 'observations.jsonl'
    row = json.loads(observed.read_bytes())
    row['malicious'] = True
    observed.write_text(json.dumps(row) + '\n', encoding='utf8')
    value = json.loads(intake_path.read_bytes())
    value['files']['observations.jsonl'] = sha(observed)
    intake_path.write_text(json.dumps(value), encoding='utf8')
    catalog['shared_dns_support'][0]['intake_sha256'] = sha(intake_path)
    path.write_text(json.dumps(catalog), encoding='utf8')
    with pytest.raises(ValueError, match='observation_fields'):
        staging.stage(path, sha(path), tmp_path / 'package')
    assert json.loads((tmp_path / 'package/stage.json').read_bytes())['completed'] is False


def test_wrong_source_index_and_duplicate_support_rejected(staged_inputs, tmp_path):
    path, catalog, _intake = staged_inputs
    catalog['shared_dns_support'].append(dict(catalog['shared_dns_support'][0]))
    path.write_text(json.dumps(catalog), encoding='utf8')
    with pytest.raises(ValueError, match='support_source'):
        staging.stage(path, sha(path), tmp_path / 'package')


def test_native_runner_dispatch_is_explicit_and_does_not_invoke_a_model():
    from scripts.run_local_vpn_protocol_batch import BOOTSTRAP
    section = BOOTSTRAP.split("elif PIPELINE=='shared-dns-native':", 1)[1].split('elif PIPELINE', 1)[0]
    assert 'scripts.run_shared_dns_native_review' in section and 'DNS_CATALOG' in section
    assert '--model' not in section and '--legacy-models' not in section
