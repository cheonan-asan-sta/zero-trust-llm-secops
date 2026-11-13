import math

import pytest

from scripts.f1_lab.native_bayes import NativeBayes, counts, metrics, record, shape_reference
from scripts.f1_lab.raw_observations import raw_features


def test_training_updates_only_fixed_feature_vocabulary_and_inference_is_label_free():
    normal = raw_features('Jan 21 00:00:00 host CRON: session opened for user root')
    attack = raw_features('Jan 21 00:00:00 host sshd: failed password for alice')
    model = NativeBayes()
    for _ in range(10):
        model.observe_training(normal, False)
        model.observe_training(attack, True)
    assert model.probability(attack) > .95 and model.probability(normal) < .05
    artifact = model.export()
    assert artifact['class_counts'] == [10, 10] and artifact['laplace_alpha'] == 1
    assert 'alice' not in str(artifact) and 'host CRON' not in str(artifact)


@pytest.mark.parametrize('extra', ['ground_truth', 'labels', 'user', 'hostname', 'source_path', 'timestamp'])
def test_hidden_gold_and_identifiers_cannot_enter_model(extra):
    features = raw_features('data')
    features[extra] = 'ignored?'  # Must reject rather than silently learn it.
    with pytest.raises(ValueError, match='feature_population'):
        NativeBayes().observe_training(features, True)


def test_boolean_feature_does_not_coerce_integer():
    features = raw_features('data')
    features['auth_failure'] = 1
    with pytest.raises(ValueError, match='feature_value'):
        NativeBayes().observe_training(features, True)


def test_no_untrained_or_one_class_probability_claim():
    model = NativeBayes()
    with pytest.raises(ValueError, match='both_classes'):
        model.probability(raw_features('data'))
    model.observe_training(raw_features('data'), True)
    with pytest.raises(ValueError, match='both_classes'):
        model.export()


def test_probabilities_are_finite_with_large_counts():
    model = NativeBayes()
    item = raw_features('Jan 21 00:00:00 host failed password')
    for label in (False, True):
        model.observe_training(item, label)
    assert math.isfinite(model.probability(item)) and model.probability(item) == .5


def test_known_label_errors_stay_in_both_class_denominators():
    result = counts()
    for truth, pred in [(True, True), (False, False), (True, None), (False, None)]:
        record(result, truth, pred)
    score = metrics(result)
    assert score['population'] == 4 and score['inference_errors'] == 2
    assert score['precision'] == score['recall'] == score['f1'] == score['false_positive_rate'] == .5


def test_empty_population_is_not_perfect_score():
    score = metrics(counts())
    assert all(score[key] is None for key in ('precision', 'recall', 'f1', 'false_positive_rate', 'accuracy'))


def test_shape_reference_is_native_heuristic_only():
    assert shape_reference(raw_features('failed password'))
    assert not shape_reference(raw_features('session opened'))
