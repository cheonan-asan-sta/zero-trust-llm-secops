import hashlib
import itertools
import json

import pytest

from scripts.audit_cloud_separation import audit
from scripts.f1_lab.cloud_diagnostics import CloudDiagnostics, collision_summary, feature_key
from scripts.f1_lab.cloud_observations import partition


def test_oracle_bound_matches_exhaustive_deterministic_assignments():
    # Meaningful check: exact enumeration proves the diagnostic optimizer on
    # several mixed-label populations, independent of its sorting algorithm.
    for groups in ([[8, 1], [2, 5], [0, 3]], [[0, 1], [4, 2], [2, 1]], [[3, 3], [6, 6], [3, 0]]):
        total = sum(a for n, a in groups)
        scores = []
        for decisions in itertools.product((False, True), repeat=len(groups)):
            tp = sum(a for (n, a), yes in zip(groups, decisions, strict=True) if yes)
            fp = sum(n for (n, a), yes in zip(groups, decisions, strict=True) if yes)
            scores.append(2*tp/(total+tp+fp))
        assert collision_summary(groups)['gold_oracle_best_in_sample_f1'] == pytest.approx(max(scores))


def test_collision_population_counts_both_classes_instead_of_dropping_conflicts():
    result = collision_summary([[8, 1], [2, 5], [0, 3], [4, 0]])
    assert result['known_normal'] == 14 and result['known_attack'] == 9
    assert result['mixed_label_vectors'] == 2 and result['rows_in_mixed_label_vectors'] == 16
    assert result['minimum_in_sample_classification_errors'] == 3
    assert not result['is_model_performance'] and not result['is_independent_evaluation']


def test_training_oracle_without_attack_has_no_f1_score():
    assert collision_summary([[3, 0]])['gold_oracle_best_in_sample_f1'] is None


def test_age_variants_remove_continuous_history_without_using_gold():
    a = {'api_name': 'GetObject', 'historical_session_age_seconds': 101.0}
    b = {**a, 'historical_session_age_seconds': 102.0}
    assert feature_key(a, 'exact') != feature_key(b, 'exact')
    assert feature_key(a, 'bucketed_session_age') == feature_key(b, 'bucketed_session_age')
    assert feature_key(a, 'without_session_age') == feature_key(b, 'without_session_age')


def prepared(tmp_path):
    directory = tmp_path/'input'
    directory.mkdir()
    for index in (0, 1):
        item = {'eventID': 'same-event', 'eventName': 'GetObject', 'eventSource': 's3.amazonaws.com',
                'userIdentity': {'type': 'IAMUser', 'principalId': 'same-principal'},
                'should_sample': bool(index), 'attack_name': 'scenario' if index else ''}
        view, gold = partition(item)
        observation = {'case_id': 'case', 'observation': view, 'error': None}
        (directory/f'asset-{index}-observations.jsonl').write_text(json.dumps(observation)+'\n')
        (directory/f'asset-{index}-truth.jsonl').write_text(json.dumps({'case_id': 'case', **gold})+'\n')
    anchors = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()}
    return directory, anchors


def test_shared_reference_conflicting_labels_preserved_without_reporting_independence(tmp_path):
    directory, anchors = prepared(tmp_path)
    result = audit(directory, anchors, tmp_path/'out')
    assert result['completed'] and result['conflicting_event_reference_labels'] == 1
    assert result['linkage']['principal_reference']['shared_across_training_assets'] == 1
    assert result['profiles']['exact']['minimum_in_sample_classification_errors'] == 1
    assert not result['classifier_fitted'] and not result['final_partition_certified']


@pytest.mark.parametrize('mutation', ['changed_hash', 'case_mismatch', 'missing_truth'])
def test_changed_or_misaligned_sidecars_fail_without_publishing_completed_report(tmp_path, mutation):
    directory, anchors = prepared(tmp_path)
    path = directory/'asset-1-truth.jsonl'
    if mutation == 'missing_truth':
        path.write_bytes(b'')
    elif mutation == 'case_mismatch':
        item = json.loads(path.read_bytes())
        item['case_id'] = 'other'
        path.write_text(json.dumps(item)+'\n')
    else:
        path.write_bytes(path.read_bytes()+b' ')
    with pytest.raises(ValueError):
        audit(directory, anchors, tmp_path/'out')
    assert not (tmp_path/'out/diagnostics.json').exists()


def test_known_labels_with_unusable_observations_not_counted_as_supported_performance():
    diagnostic = CloudDiagnostics()
    diagnostic.add(None, {'truth': True}, asset=0)
    diagnostic.add(None, {'truth': None}, asset=0)
    result = diagnostic.summary()
    assert result['counts']['rows'] == result['counts']['unusable_observations'] == 2
    assert result['counts']['known_label_unusable_observations'] == 1
    assert not result['goal_qualified']
