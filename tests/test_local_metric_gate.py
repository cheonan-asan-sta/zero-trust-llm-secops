import copy
import hashlib
import json

import pytest

from scripts.check_local_metric_gate import main
from scripts.f1_lab.local_metric_gate import LOG_KINDS, SECURITY_DOMAINS, evaluate


def rows(names=LOG_KINDS):
    return [{'name': name, 'population': 200, 'tp': 100, 'fp': 0, 'fn': 0,
             'tn': 100, 'inference_errors': 0, 'unknown': 0} for name in names]


def test_large_pooled_success_cannot_hide_one_failed_kind():
    values = rows()
    values[0].update(population=200, tp=0, fn=100)
    values[1].update(population=10_000_000, tp=9_000_000, tn=1_000_000)
    result = evaluate(values, track='observed_log_kinds')
    assert not result['local_metric_gate_passed']
    assert result['rows'][0]['failed_conditions']


def test_high_auth_f1_does_not_hide_missed_recall_target():
    values = rows()
    values[2].update(population=1114, tp=29, fn=3, tn=1082)
    result = evaluate(values, track='observed_log_kinds')
    auth = result['rows'][2]
    assert auth['metrics']['f1'] > .95 and not auth['metric_targets_met']
    assert set(auth['failed_conditions']) == {'recall', 'false_negative_rate'}


def test_rounded_95_is_not_an_exact_95_pass():
    values = rows()
    values[0].update(population=200100, tp=189999, fn=10001, tn=100)
    result = evaluate(values, track='observed_log_kinds')
    assert round(result['rows'][0]['metrics']['recall']*100, 2) == 95
    assert not result['local_metric_gate_passed']


@pytest.mark.parametrize('field', ['unknown', 'inference_errors'])
def test_unclassified_rows_cannot_be_removed_from_metric_denominators(field):
    values = rows()
    values[0].update({field: 1, 'population': 201})
    result = evaluate(values, track='observed_log_kinds')
    assert not result['local_metric_gate_passed']
    assert all(v is None for v in result['rows'][0]['metrics'].values())


@pytest.mark.parametrize('field', ['tp', 'fp', 'fn', 'tn', 'population', 'inference_errors', 'unknown'])
@pytest.mark.parametrize('value', [True, -1, 1.0, '1'])
def test_invalid_counts_are_never_coerced(field, value):
    values = rows()
    values[0][field] = value
    with pytest.raises(ValueError):
        evaluate(values, track='observed_log_kinds')


def test_missing_duplicate_and_cross_track_names_fail():
    for values in [rows()[:-1], [rows()[0], *rows()[1:-1], rows()[0]], rows(SECURITY_DOMAINS)]:
        with pytest.raises(ValueError):
            evaluate(values, track='observed_log_kinds')


def test_absent_negative_support_is_unknown_fpr_even_with_perfect_threats():
    values = rows()
    values[0].update(population=100, tn=0)
    result = evaluate(values, track='observed_log_kinds')
    assert result['rows'][0]['metrics']['false_positive_rate'] is None
    assert not result['local_metric_gate_passed']


def test_successful_aggregate_is_not_independent_qualification_or_ci_permission():
    result = evaluate(rows(SECURITY_DOMAINS), track='original_security_domains')
    assert result['local_metric_gate_passed']
    assert not result['goal_qualified'] and not result['independent_evaluation_verified']
    assert not result['ci_or_merge_started']


def test_counts_must_cover_exact_population():
    values = rows()
    values[0]['population'] += 1
    with pytest.raises(ValueError, match='denominator'):
        evaluate(values, track='observed_log_kinds')


def test_cli_refuses_modified_report_and_reports_unmet_gate(tmp_path, capsys):
    values = rows()
    values[0].update(tp=0, fn=100)
    original = copy.deepcopy(values)
    path = tmp_path/'report.json'
    path.write_text(json.dumps({'schema': 'local-metric-counts-1', 'track': 'observed_log_kinds', 'rows': values}))
    pin = hashlib.sha256(path.read_bytes()).hexdigest()
    args = ['--report', str(path), '--sha256', pin, '--track', 'observed_log_kinds']
    assert main(args) == 1
    assert not json.loads(capsys.readouterr().out)['local_metric_gate_passed']
    path.write_bytes(path.read_bytes()+b' ')
    assert main(args) == 2
    assert not json.loads(capsys.readouterr().out)['completed']
    assert values == original
