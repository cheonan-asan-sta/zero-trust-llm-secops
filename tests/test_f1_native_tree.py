import pytest

from scripts.f1_lab.native_tree import NativeTree, gini
from scripts.f1_lab.raw_observations import raw_features


def features(failure=False, scanner=False):
    result = raw_features('same size')
    result['auth_failure'], result['scanner_agent'] = failure, scanner
    return result


def test_gini_matches_pairwise_class_disagreement():
    labels = [False, False, True, True, True]
    brute = sum(a != b for a in labels for b in labels)/len(labels)**2
    assert gini(2, 3) == brute and gini(0, 4) == gini(0, 0) == 0


def test_conditional_feature_interaction_and_multiplicity_preserved():
    tree = NativeTree(max_depth=3, min_leaf=1, class_balanced=False)
    for (a, b), normal, attack in [((False, False), 20, 0), ((True, False), 0, 10), ((False, True), 0, 10), ((True, True), 20, 0)]:
        for _ in range(normal): tree.observe_training(features(a, b), False)
        for _ in range(attack): tree.observe_training(features(a, b), True)
    tree.fit()
    # Pure XOR has no first split gain for equal branch distributions. A greedy
    # tree must disclose its limitation rather than fabricate a perfect fit.
    assert tree.root['counts'] == [40, 20] and tree.export()['training_unique_vectors'] == 4
    assert 'feature' not in tree.root


def test_simple_semantic_split_and_duplicate_opposite_labels_are_not_erased():
    tree = NativeTree(min_leaf=1, class_balanced=False)
    for _ in range(10):
        tree.observe_training(features(False), False)
        tree.observe_training(features(True), True)
    tree.observe_training(features(True), False)
    tree.fit()
    assert tree.root['counts'] == [11, 10]
    assert tree.probability(features(True)) == 10/11 and tree.probability(features(False)) == 0


def test_class_balancing_is_declared_and_does_not_change_labels():
    tree = NativeTree(min_leaf=1, class_balanced=True)
    for _ in range(100): tree.observe_training(features(), False)
    for _ in range(10): tree.observe_training(features(), True)
    tree.fit()
    assert tree.root['counts'] == [100, 10] and tree.root['probability'] == .5
    assert tree.export()['class_balanced']


def test_no_post_fit_training_or_one_class_fit():
    tree = NativeTree()
    tree.observe_training(features(), False)
    with pytest.raises(ValueError, match='both_classes'):
        tree.fit()
    tree.observe_training(features(True), True)
    tree.fit()
    with pytest.raises(ValueError, match='already_fitted'):
        tree.observe_training(features(), True)


def test_gold_field_never_learned():
    item = features()
    item['ground_truth'] = True
    with pytest.raises(ValueError, match='feature_population'):
        NativeTree().observe_training(item, True)
