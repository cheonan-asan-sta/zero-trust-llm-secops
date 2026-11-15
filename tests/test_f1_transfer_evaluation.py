import hashlib
import json
import zipfile
from types import SimpleNamespace

import pytest

from scripts import prepare_transfer_source as intake
from scripts import run_frozen_transfer as runner
from scripts.audit_transfer_overlap import audit as overlap_audit
from scripts.f1_lab import transfer_evaluation as module
from scripts.f1_lab.native_jsonl import decode
from scripts.f1_lab.operation_context import canonical
from scripts.prepare_native_stream import prepare as prepare_observations
from tests.test_f1_native_stream import FIXTURE_LIMITS


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value)+b'\n')
    return module.sha(path)


def case(ordinal):
    return hashlib.sha256(str(ordinal).encode()).hexdigest()


def scored_files(tmp_path, predictions, truth):
    paths = tmp_path/'predictions.jsonl', tmp_path/'truth.jsonl'
    for path, rows in zip(paths, (predictions, truth), strict=True):
        path.write_bytes(b''.join(canonical(row)+b'\n' for row in rows))
    return *paths, *(module.sha(path) for path in paths)


def test_inference_errors_remain_in_denominator_and_do_not_erase_valid_baseline(tmp_path):
    outputs = [{'case_id': case(i), 'source_index': 0, 'before': a, 'after': b}
               for i, (a, b) in enumerate([(True, None), (False, None), (False, True), (True, False)])]
    truth = [{'case_id': case(i), 'malicious': expected} for i, expected in enumerate([True, False, True, True])]
    result = module.score(*scored_files(tmp_path, outputs, truth))
    assert result['population'] == 4
    assert result['metrics']['before']['tp'] == 2
    assert result['metrics']['before']['inference_errors'] == 0
    assert result['metrics']['after']['inference_errors'] == 2
    assert result['metrics']['after']['fn'] == 2 and result['metrics']['after']['fp'] == 1
    assert result['changes'] == {'new_tp': 1, 'introduced_fp': 0, 'lost_tp': 1, 'removed_fp': 0}
    assert not result['goal_qualified'] and not result['independent_human_review']


@pytest.mark.parametrize('defect', ['missing', 'extra', 'reordered', 'duplicate', 'nonboolean', 'invalid_id', 'source_bool'])
def test_scoring_rejects_incomplete_or_ambiguous_population(tmp_path, defect):
    outputs = [{'case_id': case(i), 'source_index': 0, 'before': False, 'after': False} for i in range(2)]
    truth = [{'case_id': case(i), 'malicious': False} for i in range(2)]
    if defect == 'missing':
        truth.pop()
    elif defect == 'extra':
        truth.append(truth[-1])
    elif defect == 'reordered':
        truth.reverse()
    elif defect == 'duplicate':
        outputs[1]['case_id'] = truth[1]['case_id'] = case(0)
    elif defect == 'nonboolean':
        truth[0]['malicious'] = 0
    elif defect == 'invalid_id':
        outputs[0]['case_id'] = truth[0]['case_id'] = 'invalid'
    else:
        outputs[0]['source_index'] = True
    with pytest.raises(ValueError):
        module.score(*scored_files(tmp_path, outputs, truth))


def test_score_external_hash_anchor_and_empty_population(tmp_path):
    values = scored_files(tmp_path, [], [])
    with pytest.raises(ValueError, match='transfer_empty_population'):
        module.score(*values)
    with pytest.raises(ValueError, match='transfer_score_hash'):
        module.score(values[0], values[1], '0'*64, values[3])


def small_freeze(root):
    (root/'app').mkdir(parents=True)
    (root/'scripts').mkdir()
    (root/'app/example.py').write_bytes(b'x = 1\r\n')
    models = {}
    for name in ('web', 'heads', 'vpn'):
        path = root/f'models/{name}.json'
        models[name] = {'path': str(path.relative_to(root)).replace('\\', '/'), 'sha256': write(path, {'test': name})}
    write(root/'infra/f1-lab/operation-refinement-protocol.json', {'models': models})
    write(root/'runtime/f1/operation-refinement-v40-20261113/policy.json', {'authored_fixture': True})
    archive = root/'sealed/fixture.zip'
    archive.parent.mkdir()
    return archive


def frozen_fixture(tmp_path):
    root = tmp_path/'root'
    archive = small_freeze(root)
    prefix = 'fixture/gather/host/logs/apache2'
    raw_member, label_member = prefix+'/site-access.log', prefix.replace('/gather/', '/labels/')+'/site-access.log'
    raw = (b'192.0.2.1 - - [04/Feb/2022:00:00:00 +0000] "GET /same HTTP/1.1" 200 10\n'
           b'192.0.2.2 - - [04/Feb/2022:00:00:01 +0000] "GET /other HTTP/1.1" 200 10\n')
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zip:
        zip.writestr(raw_member, raw)
        zip.writestr(label_member, json.dumps({'line': 2, 'labels': ['authored-test']})+'\n')
        zip.writestr('fixture/gather/host/facts.json', canonical({'ansible_facts': {
            'date_time': {'tz': 'UTC', 'tz_offset': '+0000'}}}))
        zip.writestr(prefix+'/unpaired-access.log', b'not inferred normal\n')
    receipt = {'completed': True, 'asset': {'asset_id': 'ait-lds21-harrison-sealed'},
               'publisher_md5_verified': True, 'local_sha256': module.sha(archive)}
    frz = tmp_path/'freeze.json'
    frozen_hash = module.freeze(root, receipt, frz, archive=archive)
    return root, archive, frz, frozen_hash


def test_freeze_blocks_code_model_and_external_anchor_drift(tmp_path):
    root, archive, frz, digest = frozen_fixture(tmp_path)
    module.check_freeze(root, frz, digest)
    (root/'app/example.py').write_bytes(b'x = 1\n')  # checkout line endings do not change code identity
    module.check_freeze(root, frz, digest)
    with pytest.raises(ValueError, match='transfer_freeze_hash'):
        module.check_freeze(root, frz, '0'*64)
    (root/'app/example.py').write_bytes(b'x = 2\n')
    with pytest.raises(ValueError, match='transfer_code_changed'):
        module.check_freeze(root, frz, digest)
    (root/'app/example.py').write_bytes(b'x = 1\n')
    write(root/'models/web.json', {'changed': True})
    with pytest.raises(ValueError, match='transfer_model_changed'):
        module.check_freeze(root, frz, digest)
    intake.access(archive, digest, 'raw')
    receipt = {'completed': True, 'asset': {'asset_id': 'ait-lds21-harrison-sealed'},
               'publisher_md5_verified': True, 'local_sha256': module.sha(archive)}
    with pytest.raises(ValueError, match='transfer_source_not_sealed'):
        module.freeze(root, receipt, tmp_path/'another-freeze.json', archive=archive)


def test_exact_mirror_selection_and_verified_timezone(tmp_path):
    _, archive, frz, _ = frozen_fixture(tmp_path)
    inventory = intake.inspect(archive, decode(frz.read_bytes())['archive_sha256'])
    pairs, excluded = intake.select_pairs(inventory['entries'])
    assert len(pairs) == len(excluded) == 1
    assert pairs[0]['label_member'] == pairs[0]['raw_member'].replace('/gather/', '/labels/')
    assert 'never inferred normal' in excluded[0]['reason']
    assert intake.timezone({'ansible_facts': {'date_time': {'tz': 'UTC', 'tz_offset': '+0000'}}}) == 'UTC'
    for value in ({}, {'date_time': {'tz': 'UTC'}}, {'date_time': {'tz': 'KST', 'tz_offset': '+0900'}}):
        with pytest.raises(ValueError, match='timezone_not_verified_UTC'):
            intake.timezone(value)


def test_raw_preparation_never_opens_labels_and_scoring_waits_for_sealed_predictions(tmp_path, monkeypatch):
    root, archive, frz, digest = frozen_fixture(tmp_path)
    copy = intake.copy_member
    def raw_only(path, archive_sha, member, destination, **kwargs):
        assert '/labels/' not in member
        return copy(path, archive_sha, member, destination, **kwargs)
    monkeypatch.setattr(intake, 'copy_member', raw_only)
    raw = tmp_path/'raw'
    report = intake.prepare(root, archive, frz, digest, raw)
    assert report['completed'] and report['label_bodies_opened'] == 0
    prepared = tmp_path/'prepared'
    result = prepare_observations(raw, module.sha(raw/'audit.json'), prepared,
                                  include_truth=False, limits=FIXTURE_LIMITS)
    assert result['completed'] and not list(raw.glob('*-labels.source'))
    assert not (prepared/'truth.jsonl').exists()
    # Pure fixture model; no empirical performance claim or real model fitting.
    fake_model = SimpleNamespace(web_model=SimpleNamespace(probability=lambda _: .1), vpn_model=None, operation_model=None)
    monkeypatch.setattr(runner, 'load_detector', lambda *args: fake_model)
    monkeypatch.setattr(module, 'prepare_contexts', lambda *args: ({}, {}))
    monkeypatch.setattr(module, 'prepare_retention', lambda *args: {})
    monkeypatch.setattr(module, 'WebResidualRefinement', lambda *args: SimpleNamespace(refine=lambda decision, *args: decision))
    packets = tmp_path/'predictions'
    sealed = runner.prediction_packet(root, frz, digest, raw, prepared, packets)
    assert sealed['population'] == 2 and not sealed['labels_opened']
    monkeypatch.setattr(intake, 'copy_member', lambda *args, **kwargs: pytest.fail('labels opened before seal validation'))
    with pytest.raises(ValueError, match='transfer_prediction_seal_hash'):
        intake.truth_after_seal(root, archive, frz, digest, raw, packets/'prediction-manifest.json', '0'*64, tmp_path/'bad')
    original = (packets/'predictions.jsonl').read_bytes()
    (packets/'predictions.jsonl').write_bytes(original+b'\n')
    with pytest.raises(ValueError, match='transfer_predictions_changed_before_labels'):
        intake.truth_after_seal(root, archive, frz, digest, raw, packets/'prediction-manifest.json',
                                sealed['manifest_sha256'], tmp_path/'bad2')
    (packets/'predictions.jsonl').write_bytes(original)
    monkeypatch.setattr(intake, 'copy_member', copy)
    evaluated = runner.score_packet(root, archive, frz, digest, raw, packets, sealed['manifest_sha256'], tmp_path/'score')
    assert evaluated['population'] == 2 and evaluated['metrics']['after']['fn'] == 1
    assert not evaluated['goal_qualified'] and not evaluated['production_adopted']
    with pytest.raises(ValueError, match='transfer_labels_already_exposed'):
        intake.access(archive, digest, 'raw')
    overlap = overlap_audit(root, frz, digest, packets/'prediction-manifest.json', sealed['manifest_sha256'],
                            prepared, [prepared], tmp_path/'overlap')
    assert overlap['heldout_rows'] == overlap['rows_matching_development_feature_vector'] == 2
    assert len(overlap['exact_raw_source_overlap']) == 1 and overlap['rows_removed_from_evaluation'] == 0
    assert not (tmp_path/'overlap/overlap.sqlite3').exists()


@pytest.mark.parametrize('defect', ['label', 'case', 'population', 'hash'])
def test_observation_iterator_rejects_label_leakage_or_population_drift(tmp_path, defect):
    raw_sha = 'a'*64
    identity = hashlib.sha256((raw_sha+':1').encode()).hexdigest()
    row = {'case_id': identity, 'features': {}, 'observation_error': None}
    if defect == 'label':
        row['malicious'] = True
    elif defect == 'case':
        row['case_id'] = case(0)
    digest = write(tmp_path/'inputs.jsonl', row)
    preparation = {'files': {'inputs.jsonl': {'sha256': digest}},
                   'pairs': [{'raw_sha256': raw_sha, 'rows': 2 if defect == 'population' else 1}]}
    if defect == 'hash':
        preparation['files']['inputs.jsonl']['sha256'] = '0'*64
    with pytest.raises(ValueError):
        list(module.observations(tmp_path, preparation))
