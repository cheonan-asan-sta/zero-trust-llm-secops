"""Prospective selection, artifact freezing, coverage and prediction pairing."""

import copy
import hashlib

import pytest

from scripts.f1_lab.native_jsonl import decode
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.rotation_transfer import (
    POLICY,
    check_freeze,
    freeze,
    pair_predictions,
    select_pairs,
)
from scripts.f1_lab.transfer_evaluation import sha
from scripts.run_rotated_transfer import prediction_packet


def entries():
    rows = []
    for host, suffix in (('web', 'apache2/site-access.log.1'), ('web', 'apache2/site-error.log.1'),
                         ('vpn', 'openvpn/openvpn.log')):
        for area in ('gather', 'labels'):
            rows.append({'archive_name': f'source/{area}/{host}/logs/{suffix}', 'bounded_read_eligible': True})
    rows += [{'archive_name': f'source/gather/{host}/facts.json', 'bounded_read_eligible': True} for host in ('web', 'vpn')]
    return rows


def test_exact_rotations_and_vpn_have_all_declared_kinds():
    selected, excluded = select_pairs(entries())
    assert len(selected) == 3 and not excluded
    assert {p['kind'] for p in selected} == {'access', 'error', 'vpn'}
    assert all(p['raw_member'].replace('/gather/', '/labels/') == p['label_member'] for p in selected)
    assert [p['rotation'] for p in selected if p['kind'] != 'vpn'] == [1, 1]


@pytest.mark.parametrize('suffix', ['openvpn.log', 'site-access.log.1', 'site-error.log.1'])
def test_missing_exact_labels_block_declared_coverage(suffix):
    rows = [r for r in entries() if not ('/labels/' in r['archive_name'] and r['archive_name'].endswith(suffix))]
    with pytest.raises(ValueError, match='declared_coverage_missing'):
        select_pairs(rows)


@pytest.mark.parametrize('replacement', ['site-access.log.01', 'site-access.log.0',
    'site-access.log.10000', 'site-access.log.1.gz', 'site-access.log.backup'])
def test_unknown_rotation_grammar_cannot_silently_supply_coverage(replacement):
    rows = [{**r, 'archive_name': r['archive_name'].replace('site-access.log.1', replacement)} for r in entries()]
    with pytest.raises(ValueError, match='declared_coverage_missing'):
        select_pairs(rows)


def test_unpaired_extra_file_is_reported_without_normal_label_inference():
    rows = entries()+[{'archive_name': 'source/gather/web/logs/apache2/other-access.log', 'bounded_read_eligible': True}]
    selected, excluded = select_pairs(rows)
    assert len(selected) == 3 and len(excluded) == 1 and 'truth unknown' in excluded[0]['reason']


def test_duplicate_or_unbounded_members_fail():
    rows = entries()
    with pytest.raises(ValueError, match='duplicate_member'):
        select_pairs(rows+[rows[0]])
    rows[0]['bounded_read_eligible'] = False
    with pytest.raises(ValueError, match='ineligible_pair'):
        select_pairs(rows)


def freezer_fixture(tmp_path):
    # Synthetic contract fixture, not a downloaded or evaluated public dataset.
    root = tmp_path/'root'
    (root/'app').mkdir(parents=True)
    (root/'scripts').mkdir()
    (root/'app/example.py').write_text('x = 1\n')
    (root/'infra/f1-lab').mkdir(parents=True)
    models = {}
    for name in ('web', 'heads', 'vpn'):
        path = root/f'runtime/models/{name}.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical({'fixture_model': name}))
        models[name] = {'path': path.relative_to(root).as_posix(), 'sha256': sha(path)}
    (root/'infra/f1-lab/operation-refinement-protocol.json').write_bytes(canonical({'models': models}))
    policy = root/'runtime/f1/operation-refinement-v40-20261113/policy.json'
    policy.parent.mkdir(parents=True)
    policy.write_bytes(b'{}')
    archive = tmp_path/'synthetic.source'
    archive.write_bytes(b'synthetic test bytes only')
    acquisition = {'completed': True, 'publisher_md5_verified': True, 'local_sha256': sha(archive), 'asset': {
        'asset_id': POLICY['asset_id'], 'record_id': POLICY['publisher_record'],
        'record_version': POLICY['publisher_version'], 'filename': POLICY['filename'],
        'publisher_md5': POLICY['publisher_md5'], 'license_id': POLICY['license_id'], 'bytes': archive.stat().st_size}}
    return root, archive, acquisition


def test_freeze_and_code_model_or_contract_drift(tmp_path):
    root, archive, acquisition = freezer_fixture(tmp_path)
    path = tmp_path/'freeze.json'
    anchor = freeze(root, acquisition, archive, path)
    value = check_freeze(root, path, anchor)
    assert value['policy']['goal_qualified'] is False and not value['policy']['forward_time_split']
    source = root/'app/example.py'
    source.write_text('x = 2\n')
    with pytest.raises(ValueError, match='code_changed'):
        check_freeze(root, path, anchor)
    source.write_text('x = 1\n')
    (root/'runtime/models/web.json').write_bytes(b'changed')
    with pytest.raises(ValueError, match='model_hash'):
        check_freeze(root, path, anchor)


@pytest.mark.parametrize('field,value', [('maximum_total_rows', 1), ('simulation_start', 1), ('source_id', 'ait-harrison')])
def test_rehashed_duplicate_policy_drift_is_rejected(tmp_path, field, value):
    root, archive, acquisition = freezer_fixture(tmp_path)
    path = tmp_path/'freeze.json'
    freeze(root, acquisition, archive, path)
    data = decode(path.read_bytes())
    data[field] = value
    path.write_bytes(canonical(data))
    with pytest.raises(ValueError, match='duplicate_policy_drift'):
        check_freeze(root, path, sha(path))


def test_changed_fixed_policy_or_operation_path_rejected(tmp_path):
    root, archive, acquisition = freezer_fixture(tmp_path)
    path = tmp_path/'freeze.json'
    freeze(root, acquisition, archive, path)
    original = decode(path.read_bytes())
    changed = copy.deepcopy(original)
    changed['policy']['score_lowering_threshold'] = .9
    path.write_bytes(canonical(changed))
    with pytest.raises(ValueError, match='policy_changed'):
        check_freeze(root, path, sha(path))
    changed = copy.deepcopy(original)
    changed['operation_policy']['path'] = '../other.json'
    path.write_bytes(canonical(changed))
    with pytest.raises(ValueError, match='operation_path'):
        check_freeze(root, path, sha(path))


def test_exposed_source_or_wrong_publisher_cannot_be_frozen(tmp_path):
    root, archive, acquisition = freezer_fixture(tmp_path)
    changed = copy.deepcopy(acquisition)
    changed['asset']['filename'] = 'harrison_no-pcaps.zip'
    with pytest.raises(ValueError, match='publisher_contract'):
        freeze(root, changed, archive, tmp_path/'wrong.json')
    (archive.parent/'evaluation-access.json').write_bytes(b'{}')
    with pytest.raises(ValueError, match='unsealed_source'):
        freeze(root, acquisition, archive, tmp_path/'exposed.json')


def prediction(n, decision, score=.99):
    return {'case_id': hashlib.sha256(str(n).encode()).hexdigest(), 'source_index': 0,
        'after': decision, 'after_score': score if decision is not None else None,
        'reason': 'test', 'error': None if decision is not None else 'inference_error'}


def write_rows(path, rows):
    path.write_bytes(b''.join(canonical(row)+b'\n' for row in rows))


def test_pairing_retains_every_row_and_error_without_truth(tmp_path):
    before, after, output = (tmp_path/name for name in ('before.jsonl', 'after.jsonl', 'paired.jsonl'))
    write_rows(before, [prediction(1, True), prediction(2, False), prediction(3, None)])
    write_rows(after, [prediction(1, False, .01), prediction(2, True), prediction(3, None)])
    result = pair_predictions(before, after, sha(before), sha(after), output)
    assert result['population'] == 3 and result['inference_errors'] == 1
    rows = [decode(row) for row in output.read_bytes().splitlines()]
    assert [r['before'] for r in rows] == [True, False, None]
    assert [r['after'] for r in rows] == [False, True, None]
    assert not result['labels_opened_by_predictor'] and not (tmp_path/'truth.jsonl').exists()


@pytest.mark.parametrize('error', ['duplicate', 'mismatch', 'short', 'extra', 'invalid_prediction'])
def test_pairing_failures_cannot_seal_output(tmp_path, error):
    before, after, output = (tmp_path/name for name in ('before.jsonl', 'after.jsonl', 'paired.jsonl'))
    a, b = [prediction(1, True), prediction(2, False)], [prediction(1, True), prediction(2, False)]
    if error == 'duplicate':
        a[1], b[1] = a[0], b[0]
    elif error == 'mismatch':
        b.reverse()
    elif error == 'short':
        b.pop()
    elif error == 'extra':
        b.append(prediction(3, False))
    else:
        b[1]['after'] = 1
    write_rows(before, a)
    write_rows(after, b)
    with pytest.raises(ValueError):
        pair_predictions(before, after, sha(before), sha(after), output)
    assert not output.exists()


def test_prediction_rejects_truth_sidecar_before_model_loading(tmp_path, monkeypatch):
    from scripts import run_rotated_transfer as driver
    monkeypatch.setattr(driver, 'check_freeze', lambda *_: {})
    raw, prepared = tmp_path/'raw', tmp_path/'prepared'
    raw.mkdir()
    prepared.mkdir()
    preparation = {'schema': 'f1-native-raw-observations-1', 'completed': True, 'labels_loaded': False,
        'truth_sidecar_written': False, 'files': {'inputs.jsonl': {}, 'references.jsonl': {}}}
    (prepared/'preparation.json').write_bytes(canonical(preparation))
    (prepared/'truth.jsonl').write_bytes(b'private label sentinel')
    with pytest.raises(ValueError, match='labels_in_predictor_mount'):
        prediction_packet(tmp_path, tmp_path/'freeze.json', 'a'*64, raw, prepared, tmp_path/'predictions')
