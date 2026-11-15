import itertools
import math

import pytest

from scripts.f1_lab.score_feasibility import ScoreAudit, point


def audit(rows):
    candidate = ScoreAudit()
    for score, truth in rows:
        candidate.add(score, truth, score >= .95)
    return candidate.report()


def test_exact_target_boundary_and_undefined_denominators():
    assert point(95, 5, 100, 100, 0)['meets_point_targets']
    assert not point(94, 5, 100, 100, 0)['meets_point_targets']
    assert not point(95, 6, 100, 100, 0)['meets_point_targets']
    assert not point(100, 0, 100, 0, 0)['meets_point_targets']
    assert not point(0, 0, 0, 100, 0)['meets_point_targets']


def test_tied_normal_and_threat_scores_cannot_be_separated_by_a_threshold():
    result = audit([(.99, True)]*20+[(.99, False)]*80)
    assert result['distinct_scores'] == 1 and result['boundaries_examined'] == 2
    assert not result['score_only_target_feasible_on_observed_rows']
    assert result['diagnostic_best_f1']['tp'] == 20 and result['diagnostic_best_f1']['fp'] == 80
    assert not result['threshold_adopted'] and not result['original_six_domain_goal_qualified']


def test_diagnostic_success_is_not_adopted_and_cannot_trade_a_prior_true_positive_for_precision():
    result = audit([(1., True)]*100+[(.97, False)]*10+[(.1, False)]*90)
    assert result['safe_point_target_boundaries'] == 1
    assert result['diagnostic_best_f1_without_new_fp_or_lost_tp']['removed_baseline_fp'] == 10
    assert result['current']['fp'] == 10 and not result['current']['meets_point_targets']
    assert not result['threshold_adopted']
    loss = audit([(1., True)]*94+[(.96, True)]*6+[(.97, False)]*100)
    assert not loss['score_only_target_feasible_on_observed_rows']
    assert loss['diagnostic_best_f1']['lost_baseline_tp'] == 6
    assert loss['diagnostic_best_f1_without_new_fp_or_lost_tp']['lost_baseline_tp'] == 0


def test_errors_remain_false_negatives_or_false_positives_at_every_boundary():
    candidate = ScoreAudit()
    candidate.add(.99, True, True)
    candidate.add(None, True, None, failed=True)
    candidate.add(None, False, None, failed=True)
    result = candidate.report()
    for key in ('current', 'diagnostic_best_f1', 'diagnostic_best_f1_without_new_fp_or_lost_tp'):
        assert result[key]['inference_errors'] == 2 and result[key]['fp'] >= 1 and result[key]['fn'] >= 1
        assert result[key]['population'] == 3


@pytest.mark.parametrize('score', [math.nan, math.inf, -math.inf, -.1, 1.1, True, '.95', None])
def test_invalid_score_rejected_without_consuming_population(score):
    candidate = ScoreAudit()
    with pytest.raises(ValueError):
        candidate.add(score, True, True)
    assert candidate.rows == 0 and candidate.current['tp'] == 0


def test_order_independence_and_exhaustive_small_threshold_oracle():
    scores = [.1, .96, .99]
    for labels in itertools.product([False, True], repeat=6):
        rows = list(zip(scores*2, labels, strict=True))
        result = audit(rows)
        assert result == audit(list(reversed(rows)))
        expected = []
        for threshold in [2., *scores]:
            tp = sum(t and s >= threshold for s, t in rows)
            fp = sum(not t and s >= threshold for s, t in rows)
            expected.append(point(tp, fp, sum(labels), 6-sum(labels), 0))
        assert result['point_target_boundaries'] == sum(p['meets_point_targets'] for p in expected)
        assert (result['diagnostic_best_f1']['f1'] or 0) == max(p['f1'] or 0 for p in expected)


def test_frozen_score_decision_inconsistency_and_empty_input_fail_closed():
    candidate = ScoreAudit()
    with pytest.raises(ValueError):
        candidate.add(.99, True, False)
    with pytest.raises(ValueError):
        candidate.report()
    with pytest.raises(ValueError):
        candidate.add(.99, True, True, failed=True)
    assert candidate.rows == 0
