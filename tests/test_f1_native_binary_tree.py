import copy

import pytest

from scripts.f1_lab.native_binary_tree import NativeBinaryTree
from scripts.f1_lab.native_tree import NativeTree
from scripts.f1_lab.raw_observations import raw_features


def features(bucket):
    result = raw_features('same observation')
    result['line_size_bucket'] = bucket
    return result


def train(kind):
    model = kind(min_leaf=5, class_balanced=False)
    for bucket, count, label in [(0, 40, False), (1, 1, False), (4, 40, True), (5, 1, True)]:
        for _ in range(count):
            model.observe_training(features(bucket), label)
    return model.fit()


def test_rare_bucket_does_not_veto_valid_ordered_binary_split():
    old, new = train(NativeTree), train(NativeBinaryTree)
    assert 'feature' not in old.root  # all-category split violates minimum leaf size
    assert new.root['condition'] == {'feature': 'line_size_bucket', 'operator': 'le', 'value': 1}
    assert new.root['gain'] == .5
    assert all(new.probability(features(value)) == label for value, label in [(0, 0), (1, 0), (4, 1), (5, 1)])


def test_binary_model_roundtrip_matches_valid_unseen_bucket_rule():
    original = train(NativeBinaryTree)
    restored = NativeBinaryTree.restore(original.export())
    assert original.export() == restored.export()
    assert restored.probability(features(2)) == original.probability(features(2)) == 1


@pytest.mark.parametrize('change', ['operator', 'feature', 'boolean_threshold', 'child_count'])
def test_binary_artifact_rejects_unsupported_operations_or_incoherent_counts(change):
    artifact = copy.deepcopy(train(NativeBinaryTree).export())
    if change == 'operator': artifact['root']['condition']['operator'] = 'eval'
    elif change == 'feature': artifact['root']['condition']['feature'] = 'ground_truth'
    elif change == 'boolean_threshold': artifact['root']['condition']['value'] = True
    else: artifact['root']['left']['counts'][0] += 1
    with pytest.raises(ValueError):
        NativeBinaryTree.restore(artifact)
