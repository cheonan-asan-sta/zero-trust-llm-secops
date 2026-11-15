import hashlib
import json

import pytest

from scripts.diagnose_native_scores import diagnose, main
from scripts.f1_lab.native_binary_tree import NativeBinaryTree
from scripts.f1_lab.native_heads import NativeHeads
from scripts.f1_lab.raw_context import PROFILE, extra_observations
from scripts.f1_lab.raw_observations import raw_features


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(tmp_path, *, reverse=False, error=False, heads=False):
    tmp_path.mkdir()
    tree = NativeHeads(profile=PROFILE, min_leaf=1, tree_variant='ordered_binary') if heads else NativeBinaryTree(min_leaf=1, class_balanced=False)
    values = [raw_features('session opened'), raw_features('failed password')]
    if heads:
        values = [{**features, **extra_observations(line)} for features, line in zip(
            values, ('session opened', 'failed password'), strict=True)]
    for features, truth in zip(values, (False, True), strict=True):
        tree.observe_training(features, truth)
    path = tmp_path/'model.json'
    path.write_text(json.dumps(tree.fit().export()))
    inputs = [{'case_id': str(i)*64, 'features': None if error and i == 1 else features,
               'observation_error': 'parse' if error and i == 1 else None} for i, features in enumerate(values, 1)]
    gold = [{'case_id': str(i)*64, 'malicious': not truth if reverse else truth, 'attack_labels': []}
            for i, truth in enumerate((False, True), 1)]
    files = {}
    for name, rows in [('inputs.jsonl', inputs), ('truth.jsonl', gold)]:
        target = tmp_path/name
        target.write_text(''.join(json.dumps(row)+'\n' for row in rows))
        files[name] = {'sha256': digest(target), 'bytes': target.stat().st_size}
    preparation = {'schema': 'f1-native-raw-input-1', 'completed': True, 'inputs_contain_truth': False,
                   'scope': 'authored diagnostic unit fixture only', 'pairs': [{'rows': 2, 'raw_member': 'fixture'}],
                   'files': files}
    if heads:
        preparation['feature_profile'] = PROFILE
    (tmp_path/'preparation.json').write_text(json.dumps(preparation))
    return path, digest(path), digest(tmp_path/'preparation.json')


@pytest.mark.parametrize('model_kind', ['ordered_tree', 'heads'])
def test_inverting_truth_cannot_change_probabilities_or_select_a_threshold(tmp_path, monkeypatch, model_kind):
    outputs = []
    for index, reverse in enumerate((False, True)):
        source = tmp_path/f'source-{index}'
        path, model_sha, preparation_sha = fixture(source, reverse=reverse, heads=model_kind == 'heads')
        def forbidden(*_args, **_kwargs):
            raise AssertionError('diagnostic attempted to train')
        with monkeypatch.context() as patch:
            patch.setattr(NativeBinaryTree, 'observe_training', forbidden)
            patch.setattr(NativeBinaryTree, 'fit', forbidden)
            patch.setattr(NativeHeads, 'observe_training', forbidden)
            patch.setattr(NativeHeads, 'fit', forbidden)
            outputs.append(diagnose(source, preparation_sha, path, model_sha, tmp_path/f'out-{index}', model_kind=model_kind))
        assert digest(path) == model_sha
    assert outputs[0]['probability_sequence_sha256'] == outputs[1]['probability_sequence_sha256']
    assert outputs[0]['metrics']['0.5']['f1'] == 1 and outputs[1]['metrics']['0.5']['f1'] == 0
    assert all(result['selected_threshold'] is None and not result['goal_qualified'] and not result['model_refitted'] for result in outputs)


def test_parse_error_stays_in_denominator_and_is_not_a_low_score(tmp_path):
    path, model_sha, preparation_sha = fixture(tmp_path/'source', error=True)
    result = diagnose(path.parent, preparation_sha, path, model_sha, tmp_path/'out')
    assert result['scored_population'] == 2
    assert all(m['population'] == 2 and m['inference_errors'] == 1 and m['fp'] == 1 for m in result['metrics'].values())
    assert any(row['score'] == 'error' for row in result['per_pair'][0]['score_class_mass'])


@pytest.mark.parametrize('thresholds', [(0, .5), (True, .5), (float('nan'), .5), (.5, .5), (.1,), ()])
def test_invalid_threshold_grid_is_rejected_before_creating_output(tmp_path, thresholds):
    output = tmp_path/'out'
    with pytest.raises(ValueError, match='score_diagnostic_thresholds'):
        diagnose(tmp_path/'missing', '0'*64, tmp_path/'none', '0'*64, output, thresholds=thresholds)
    assert not output.exists()


def test_unique_vector_exhaustion_preserves_failure_without_prefix_metrics(tmp_path):
    path, model_sha, preparation_sha = fixture(tmp_path/'source')
    output = tmp_path/'failed'
    with pytest.raises(ValueError, match='unique_vector_bound'):
        diagnose(path.parent, preparation_sha, path, model_sha, output, max_vectors=1)
    report = json.loads((output/'diagnostic.json').read_bytes())
    assert not report['completed'] and 'metrics' not in report and report['failure_type'] == 'ValueError'


def test_prepared_bytes_must_match_external_anchor_even_when_a_row_parses(tmp_path):
    path, model_sha, preparation_sha = fixture(tmp_path/'source')
    source = path.parent/'truth.jsonl'
    source.write_bytes(source.read_bytes().replace(b'false', b'true '))
    with pytest.raises(ValueError, match='prepared_hash_or_rows'):
        diagnose(path.parent, preparation_sha, path, model_sha, tmp_path/'failed')
    report = json.loads((tmp_path/'failed/diagnostic.json').read_bytes())
    assert not report['completed'] and 'metrics' not in report


def test_unsupported_head_is_retained_as_inference_error_instead_of_zero_score(tmp_path):
    path, model_sha, _preparation_sha = fixture(tmp_path/'source', heads=True)
    line = '192.0.2.1 - - [21/Jan/2022:00:00:00 +0000] "GET / HTTP/1.1" 200 10'
    inputs = path.parent/'inputs.jsonl'
    items = [json.loads(body) for body in inputs.read_bytes().splitlines()]
    items[0]['features'] = {**raw_features(line), **extra_observations(line)}
    inputs.write_text(''.join(json.dumps(row)+'\n' for row in items))
    receipt = path.parent/'preparation.json'
    preparation = json.loads(receipt.read_bytes())
    preparation['files']['inputs.jsonl'] = {'sha256': digest(inputs), 'bytes': inputs.stat().st_size}
    receipt.write_text(json.dumps(preparation))
    result = diagnose(path.parent, digest(receipt), path, model_sha, tmp_path/'out', model_kind='heads')
    assert result['metrics']['0.5']['inference_errors'] == 1
    assert result['metrics']['0.5']['fp'] == 1 and result['metrics']['0.5']['population'] == 2
    assert any(row['score'] == 'error' and row['normal'] == 1 for row in result['per_pair'][0]['score_class_mass'])


def test_cli_reproduces_an_explicit_heads_grid_without_selecting_it(tmp_path, monkeypatch, capsys):
    path, model_sha, preparation_sha = fixture(tmp_path/'source', heads=True)
    output = tmp_path/'out'
    monkeypatch.setattr('sys.argv', ['diagnose-native-scores', '--directory', str(path.parent),
        '--expected-preparation-sha256', preparation_sha, '--model', str(path), '--expected-model-sha256', model_sha,
        '--output', str(output), '--model-kind', 'heads', '--thresholds', '.5', '.75', '.9', '.95', '.99'])
    main()
    result = json.loads(capsys.readouterr().out)
    assert set(result['metrics']) == {'0.5', '0.75', '0.9', '0.95', '0.99'}
    stored = json.loads((output/'diagnostic.json').read_bytes())
    assert stored['model_kind'] == 'heads' and stored['selected_threshold'] is None and stored['model_unchanged']
