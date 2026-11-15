import hashlib
import json

import pytest

from scripts.fit_native_raw import fit
from scripts.prepare_native_raw import prepare


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def intake(tmp_path, gold_line=2, corrupt_row=False):
    directory = tmp_path/'pairs'
    directory.mkdir()
    raw = directory/'pair-0-raw.source'
    body = b'Jan 21 00:00:00 host session opened\nJan 21 00:00:01 host failed password\n'
    if corrupt_row:
        body += b'\xff\n'
    raw.write_bytes(body)
    label = directory/'pair-0-labels.source'
    label.write_text(json.dumps({'line': gold_line, 'labels': ['attack']})+'\n')
    rows = 3 if corrupt_row else 2
    manifest = {'completed': True, 'scope': 'authored fixture for pipeline verification only',
                'timestamp_basis': 'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
                'pairs': [{'pair_id': 'f'*64, 'raw_rows': rows,
                           'provenance': {'raw_member': 'gather/host/logs/auth.log',
                                          'label_member': 'labels/host/logs/auth.log',
                                          'raw_sha256': digest(raw), 'label_sha256': digest(label),
                                          'simulation_start': 1642723200, 'simulation_end': 1643068800}}]}
    path = directory/'audit.json'
    path.write_text(json.dumps(manifest))
    return directory, path, digest(path)


def test_truth_changes_do_not_change_inference_input(tmp_path):
    pairs, manifest, sha = intake(tmp_path)
    first, second = tmp_path/'one', tmp_path/'two'
    prepare(pairs, sha, first)
    label = pairs/'pair-0-labels.source'
    label.write_text(json.dumps({'line': 1, 'labels': ['different_attack']})+'\n')
    data = json.loads(manifest.read_bytes())
    data['pairs'][0]['provenance']['label_sha256'] = digest(label)
    manifest.write_text(json.dumps(data))
    prepare(pairs, digest(manifest), second)
    assert (first/'inputs.jsonl').read_bytes() == (second/'inputs.jsonl').read_bytes()
    assert (first/'truth.jsonl').read_bytes() != (second/'truth.jsonl').read_bytes()
    assert 'attack_labels' not in (first/'inputs.jsonl').read_text()


@pytest.mark.parametrize('include_tree', [False, True])
def test_corrupt_known_label_row_stays_in_population_and_fit_error_counts(tmp_path, include_tree):
    pairs, _manifest, sha = intake(tmp_path, corrupt_row=True)
    prepared = tmp_path/'prepared'
    report = prepare(pairs, sha, prepared)
    assert report['pairs'][0]['rows'] == 3 and report['pairs'][0]['feature_errors'] == 1
    result = fit(prepared, digest(prepared/'preparation.json'), tmp_path/'fit', include_tree=include_tree)
    assert result['completed'] and not result['independent_evaluation'] and not result['goal_qualified']
    assert result['training']['known_class_counts'] == [2, 1]
    assert result['training']['fitted_class_counts'] == [1, 1]
    assert result['training']['rows_unusable_for_fit'] == 1
    for score in result['metrics'].values():
        assert score['population'] == 3 and score['inference_errors'] == 1 and score['fp'] >= 1


def test_prepared_hash_change_never_produces_successful_fit(tmp_path):
    pairs, _manifest, sha = intake(tmp_path)
    prepared = tmp_path/'prepared'
    prepare(pairs, sha, prepared)
    source = prepared/'inputs.jsonl'
    source.write_bytes(source.read_bytes().replace(b'false', b'true ', 1))
    with pytest.raises(ValueError, match='hash_or_rows'):
        fit(prepared, digest(prepared/'preparation.json'), tmp_path/'fit')
    result = json.loads((tmp_path/'fit/fit.json').read_bytes())
    assert not result['completed'] and not (tmp_path/'fit/model.json').exists()


def test_tree_resource_failure_is_not_silently_treated_as_a_skippable_training_row(tmp_path, monkeypatch):
    from scripts.f1_lab.native_tree import NativeTree
    pairs, _manifest, sha = intake(tmp_path)
    prepared = tmp_path/'prepared'
    prepare(pairs, sha, prepared)
    def fail(*_args):
        raise ValueError('native_source_tree_unique_vector_bound')
    monkeypatch.setattr(NativeTree, 'observe_training', fail)
    with pytest.raises(ValueError, match='tree_unique_vector_bound'):
        fit(prepared, digest(prepared/'preparation.json'), tmp_path/'fit', include_tree=True)
    assert not json.loads((tmp_path/'fit/fit.json').read_bytes())['completed']
