import copy

import pytest

from scripts import summarize_transfer_results as driver
from scripts.f1_lab.native_bayes import counts, metrics
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import score, sha
from scripts.f1_lab.transfer_summary import markdown, summarize


def fixture_values(specs):
    pairs, sources, summed = [], [], counts()
    for index, (kind, tp, fp, fn, tn, errors) in enumerate(specs):
        value = {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn, 'inference_errors': errors}
        pairs.append({'raw_rows': tp+fp+fn+tn, 'provenance': {'kind': kind}})
        sources.append({'source_index': index, 'metrics': {name: metrics(value) for name in ('before', 'after')}})
        for key, number in value.items():
            summed[key] += number
    population = sum(p['raw_rows'] for p in pairs)
    return ({'population': population, 'goal_qualified': False, 'per_source': sources,
             'metrics': {name: metrics(summed) for name in ('before', 'after')}},
            {'completed': True, 'pairs': pairs, 'population': population})


def test_large_web_population_cannot_hide_vpn_precision_failure():
    scored, raw = fixture_values([('access', 900000, 0, 0, 10000, 0), ('error', 100, 0, 0, 100, 0),
                                  ('vpn', 28, 168, 0, 10894, 0)])
    result = summarize(scored, raw)
    assert result['overall']['after']['observed_metric_targets_met']
    vpn = result['by_telemetry_kind'][2]['metrics']['after']
    assert vpn['precision'] == 1/7 and vpn['f1'] == .25
    assert not vpn['observed_metric_targets_met'] and not result['all_declared_kind_point_targets_met']
    assert not result['goal_qualified'] and result['all_declared_kinds_have_two_classes']
    assert '25.0000%' in markdown(result)


def test_only_attack_rows_leave_fpr_undefined_and_kind_not_passed():
    scored, raw = fixture_values([('error', 1347, 0, 0, 0, 0)])
    result = summarize(scored, raw)
    value = result['by_telemetry_kind'][1]['metrics']['after']
    assert value['f1'] == 1 and value['false_positive_rate'] is None
    assert not value['observed_metric_targets_met'] and not result['all_declared_kinds_have_two_classes']
    assert result['by_telemetry_kind'][0]['metrics'] is None
    assert '산출 불가' in markdown(result) and '자료 없음' in markdown(result)


def test_no_attacks_and_no_alerts_do_not_become_perfect_precision_recall():
    scored, raw = fixture_values([('vpn', 0, 0, 0, 200, 0)])
    value = summarize(scored, raw)['overall']['after']
    assert value['precision'] is value['recall'] is value['f1'] is value['false_negative_rate'] is None
    assert value['accuracy'] == 1 and not value['observed_metric_targets_met']


def test_exact_target_counts_still_never_certify_original_goal():
    scored, raw = fixture_values([(kind, 95, 5, 5, 95, 0) for kind in ('access', 'error', 'vpn')])
    result = summarize(scored, raw)
    assert result['all_declared_kind_point_targets_met']
    assert not result['goal_qualified'] and not result['original_six_domain_goal_replaced']
    assert set(result['original_domain_coverage'].values()) == {'unverified'}
    assert result['confidence_intervals'] is None and not result['session_metrics_measured']


def test_inference_failures_stay_in_false_positive_false_negative_counts():
    scored, raw = fixture_values([('vpn', 1000, 1, 1, 1000, 2)])
    value = summarize(scored, raw)['overall']['after']
    assert value['false_negative_rate'] == 1/1001 and value['false_positive_rate'] == 1/1001
    assert value['population'] == 2002 and not value['observed_metric_targets_met']


def test_reordered_sources_aggregate_by_explicit_index_without_mutating_inputs():
    scored, raw = fixture_values([('access', 1, 2, 3, 4, 0), ('access', 4, 3, 2, 1, 0), ('vpn', 5, 0, 0, 5, 0)])
    scored['per_source'].reverse()
    previous = copy.deepcopy((scored, raw))
    result = summarize(scored, raw)
    assert result['by_telemetry_kind'][0]['metrics']['after']['tp'] == 5
    assert [row['source_index'] for row in result['per_source']] == [0, 1, 2]
    assert (scored, raw) == previous


@pytest.mark.parametrize('mutation', ['duplicate', 'negative', 'bool_count', 'float_count', 'metrics',
    'global_count', 'source_rows', 'total_rows', 'unknown_kind', 'goal_claim', 'missing_source', 'errors_over_errors'])
def test_inconsistent_or_unscoped_results_are_rejected(mutation):
    scored, raw = fixture_values([('access', 2, 1, 1, 2, 0), ('vpn', 3, 1, 1, 3, 0)])
    first = scored['per_source'][0]['metrics']['after']
    if mutation == 'duplicate':
        scored['per_source'][1]['source_index'] = 0
    elif mutation in {'negative', 'bool_count', 'float_count'}:
        first['tp'] = {'negative': -1, 'bool_count': True, 'float_count': 2.}[mutation]
    elif mutation == 'metrics':
        first['precision'] = 1.
    elif mutation == 'global_count':
        scored['metrics']['after'] = metrics({'tp': 6, 'fp': 1, 'fn': 2, 'tn': 5, 'inference_errors': 0})
    elif mutation == 'source_rows':
        raw['pairs'][0]['raw_rows'] += 1
    elif mutation == 'total_rows':
        scored['population'] += 1
    elif mutation == 'unknown_kind':
        raw['pairs'][0]['provenance']['kind'] = 'device'
    elif mutation == 'goal_claim':
        scored['goal_qualified'] = True
    elif mutation == 'missing_source':
        scored['per_source'].pop()
    else:
        first['inference_errors'] = 3
    with pytest.raises(ValueError, match='transfer_summary'):
        summarize(scored, raw)


def sealed_files(root):
    def write(name, value):
        path = root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical(value)+b'\n')
        return sha(path)
    frozen = write('freeze.json', {'archive_sha256': 'b'*64})
    raw_hash = write('raw/audit.json', {'completed': True, 'population': 2,
        'candidate_freeze_sha256': frozen, 'archive_sha256': 'b'*64,
        'pairs': [{'raw_rows': 2, 'provenance': {'kind': 'vpn'}}]})
    pred = root/'prediction-packet/predictions.jsonl'
    truth = root/'scoring/truth.jsonl'
    pred.parent.mkdir(parents=True)
    truth.parent.mkdir(parents=True)
    pred.write_bytes(b''.join(canonical({'case_id': str(index)*64, 'source_index': 0,
        'before': True, 'after': bool(index)})+b'\n' for index in range(2)))
    truth.write_bytes(b''.join(canonical({'case_id': str(index)*64, 'malicious': bool(index)})+b'\n' for index in range(2)))
    manifest_hash = write('prediction-packet/prediction-manifest.json', {'phase': 'predictions_sealed',
        'candidate_freeze_sha256': frozen, 'raw_manifest_sha256': raw_hash, 'predictions_sha256': sha(pred)})
    scored = score(pred, truth, sha(pred), sha(truth))
    scored.update(completed=True, source_id='synthetic-reporting-control', prediction_manifest_sha256=manifest_hash,
        candidate_freeze_sha256=frozen, truth_manifest={'truth_sha256': sha(truth)})
    return write('scoring/score.json', scored), manifest_hash


def test_reporter_recomputes_sealed_predictions_and_preserves_files(tmp_path):
    score_hash, manifest_hash = sealed_files(tmp_path)
    result = driver.run(tmp_path, score_hash, manifest_hash, tmp_path/'summary')
    assert result['predictions_rescored'] and result['overall']['after']['f1'] == 1
    assert not result['goal_qualified'] and not result['all_declared_kind_point_targets_met']
    assert (tmp_path/'summary/summary.md').is_file()
    assert sha(tmp_path/'scoring/score.json') == score_hash
    with pytest.raises(ValueError, match='fresh_output'):
        driver.run(tmp_path, score_hash, manifest_hash, tmp_path/'summary')


def test_tampered_prediction_is_rejected_before_summary_publication(tmp_path):
    score_hash, manifest_hash = sealed_files(tmp_path)
    path = tmp_path/'prediction-packet/predictions.jsonl'
    path.write_bytes(path.read_bytes().replace(b'"after":false', b'"after":true'))
    with pytest.raises(ValueError, match='transfer_score_hash'):
        driver.run(tmp_path, score_hash, manifest_hash, tmp_path/'summary')
    assert not (tmp_path/'summary').exists()
