import hashlib
import json

import pytest

from scripts.evaluate_native_tree import evaluate
from scripts.f1_lab.native_binary_tree import NativeBinaryTree
from scripts.f1_lab.native_tree import NativeTree
from scripts.f1_lab.raw_observations import raw_features


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepared(tmp_path, *, reverse_truth=False, broken_observation=False):
    directory = tmp_path
    directory.mkdir()
    inputs, truth = [], []
    for i, (text, malicious) in enumerate([('session opened', False), ('failed password', True)], 1):
        inputs.append({'case_id': str(i)*64, 'features': None if broken_observation and i == 2 else raw_features(text),
                       'observation_error': 'known_parse_error' if broken_observation and i == 2 else None})
        truth.append({'case_id': str(i)*64, 'malicious': not malicious if reverse_truth else malicious, 'attack_labels': []})
    for name, rows in [('inputs.jsonl', inputs), ('truth.jsonl', truth)]:
        (directory/name).write_text(''.join(json.dumps(row)+'\n' for row in rows))
    receipt = {'schema': 'f1-native-raw-input-1', 'completed': True, 'inputs_contain_truth': False,
               'scope': 'authored functional fixture only; not performance evidence',
               'pairs': [{'rows': 2, 'raw_member': 'fixture'}],
               'files': {name: {'sha256': digest(directory/name), 'bytes': (directory/name).stat().st_size}
                         for name in ('inputs.jsonl', 'truth.jsonl')}}
    (directory/'preparation.json').write_text(json.dumps(receipt))
    return directory, digest(directory/'preparation.json')


def model(tmp_path, model_kind='tree'):
    kind = NativeTree if model_kind == 'tree' else NativeBinaryTree
    tree = kind(min_leaf=1, class_balanced=False)
    for _i in range(5):
        tree.observe_training(raw_features('session opened'), False)
        tree.observe_training(raw_features('failed password'), True)
    tree.fit()
    path = tmp_path/'model.json'
    path.write_text(json.dumps(tree.export()))
    return path, digest(path)


@pytest.mark.parametrize('model_kind', ['tree', 'ordered_tree'])
def test_transfer_never_refits_or_uses_evaluation_truth_for_predictions(tmp_path, monkeypatch, model_kind):
    path, sha = model(tmp_path, model_kind)
    def forbidden(*_args):
        raise AssertionError('evaluation attempted to retrain')
    monkeypatch.setattr(NativeTree, 'observe_training', forbidden)
    monkeypatch.setattr(NativeTree, 'fit', forbidden)
    directory, anchor = prepared(tmp_path/'first')
    first = evaluate(directory, anchor, path, sha, tmp_path/'result1', model_kind=model_kind)
    directory, anchor = prepared(tmp_path/'opposite', reverse_truth=True)
    second = evaluate(directory, anchor, path, sha, tmp_path/'result2', model_kind=model_kind)
    assert first['metrics']['tp'] == first['metrics']['tn'] == 1
    assert second['metrics']['fp'] == second['metrics']['fn'] == 1
    assert first['model_state_before_after_sha256'] == second['model_state_before_after_sha256']
    assert first['model_unchanged'] and not first['refit_performed'] and not first['goal_qualified']
    assert digest(path) == sha


def test_known_label_transfer_parse_error_remains_in_denominator(tmp_path):
    path, sha = model(tmp_path)
    directory, anchor = prepared(tmp_path/'input', broken_observation=True)
    result = evaluate(directory, anchor, path, sha, tmp_path/'result')
    assert result['metrics']['population'] == 2 and result['metrics']['fn'] == 1
    assert result['metrics']['inference_errors'] == 1
