import copy
import hashlib
import json

import pytest

from scripts.f1_lab.native_tree import NativeTree, load_frozen
from scripts.f1_lab.raw_observations import raw_features


def fitted():
    tree = NativeTree(min_leaf=1, class_balanced=False)
    for _ in range(10):
        tree.observe_training(raw_features('session opened'), False)
        tree.observe_training(raw_features('failed password'), True)
    return tree.fit()


def test_roundtrip_preserves_predictions_and_cannot_retrain():
    tree = fitted()
    restored = NativeTree.restore(tree.export())
    assert restored.export() == tree.export()
    for text in ('session opened', 'failed password', 'unknown new observation'):
        assert restored.probability(raw_features(text)) == tree.probability(raw_features(text))
    with pytest.raises(ValueError, match='already_fitted'):
        restored.observe_training(raw_features('new case'), False)


def test_wrong_hash_rejected_before_model_interpretation(tmp_path):
    path = tmp_path/'model.json'
    path.write_text(json.dumps(fitted().export()))
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    assert load_frozen(path, sha).root['counts'] == [10, 10]
    path.write_bytes(path.read_bytes()+b' ')
    with pytest.raises(ValueError, match='artifact_hash'):
        load_frozen(path, sha)


@pytest.mark.parametrize('change,reason', [('probability','probability'), ('counts','conservation'),
                                          ('weights','weights'), ('feature','split'), ('category','categories')])
def test_coherency_checks_even_when_operator_rehashes_artifact(change, reason):
    artifact = copy.deepcopy(fitted().export())
    if change == 'probability': artifact['root']['probability'] = .9
    elif change == 'counts':
        artifact['root']['counts'] = [11, 11]
    elif change == 'weights': artifact['class_weights'] = [0, 1]
    elif change == 'feature': artifact['root']['feature'] = 'ground_truth'
    else:
        key = next(iter(artifact['root']['children']))
        child = artifact['root']['children'].pop(key)
        artifact['root']['children']['"invented-category"'] = child
    with pytest.raises(ValueError, match='artifact_'+reason):
        NativeTree.restore(artifact)


def test_restoration_copies_model_state():
    artifact = fitted().export()
    restored = NativeTree.restore(artifact)
    artifact['root']['counts'][0] = 0
    assert restored.root['counts'] == [10, 10]
