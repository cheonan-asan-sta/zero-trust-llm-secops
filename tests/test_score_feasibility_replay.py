import hashlib
import json
from pathlib import Path

import pytest

from scripts import run_score_feasibility as replay
from scripts.f1_lab.native_bayes import metrics
from scripts.f1_lab.operation_context import canonical


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_bytes(canonical(value)+b'\n')


def fixture(tmp_path, mutation=None):
    scenarios, prior_scenarios = [], {}
    for name, role in replay.ROLES.items():
        root = tmp_path/name
        root.mkdir()
        raw_pin = hashlib.sha256(name.encode()).hexdigest()
        other_pin = hashlib.sha256((name+'-auth').encode()).hexdigest()
        predictions, truth = [], []
        for source, ordinal, pin, score, expected in [(0, 1, raw_pin, .99, True),
                (0, 2, raw_pin, .1, False), (1, 1, other_pin, .2, False)]:
            case = hashlib.sha256((pin+':'+str(ordinal)).encode()).hexdigest()
            predictions.append({'case_id': case, 'source_index': source, 'after_score': score,
                                'after': score >= .95, 'error': None})
            truth.append({'case_id': case, 'malicious': expected, 'attack_labels': []})
        if name == 'santos':
            if mutation == 'case_order':
                truth.reverse()
            elif mutation == 'truncated':
                predictions.pop()
            elif mutation == 'bool_source_index':
                predictions[0]['source_index'] = False
            elif mutation == 'score_decision':
                predictions[0]['after'] = False
            elif mutation == 'nonbool_truth':
                truth[0]['malicious'] = 1
            elif mutation == 'extra_truth':
                truth.append(truth[-1])
        for filename, rows in [('prediction.jsonl', predictions), ('truth.jsonl', truth)]:
            (root/filename).write_bytes(b''.join(canonical(row)+b'\n' for row in rows))
        preparation = {'completed': True, 'goal_qualified': False,
            'pairs': [{'rows': 2, 'raw_sha256': raw_pin,
                       'raw_member': 'gather/internal_share/logs/audit/audit.log'},
                      {'rows': 1, 'raw_sha256': other_pin, 'raw_member': 'gather/server/logs/auth.log'}],
            'files': {'truth.jsonl': {'sha256': digest(root/'truth.jsonl')}}}
        write(root/'preparation.json', preparation)
        scenarios.append({'name': name, 'role': role, 'population': 3,
            'preparation': str(root/'preparation.json'), 'preparation_sha256': digest(root/'preparation.json'),
            'truth': str(root/'truth.jsonl'), 'truth_sha256': digest(root/'truth.jsonl'),
            'prediction': str(root/'prediction.jsonl'), 'prediction_sha256': digest(root/'prediction.jsonl')})
        prior_scenarios[name] = {'population': 3,
            'prediction': {'predictions_sha256': digest(root/'prediction.jsonl')},
            'metrics': {'after': metrics({'tp': 1, 'fp': 0, 'fn': 0, 'tn': 2, 'inference_errors': 0})}}
    prior = {'schema': 'apparmor-noop-development-result-1', 'completed': True, 'goal_qualified': False,
        'scope': 'observed_development_only', 'population': 12, 'scenarios': prior_scenarios,
        'kinds_RSF': {'audit-share': {'after': metrics({'tp': 3, 'fp': 0, 'fn': 0, 'tn': 3, 'inference_errors': 0})},
                      'auth': {'after': metrics({'tp': 0, 'fp': 0, 'fn': 0, 'tn': 3, 'inference_errors': 0})}}}
    if mutation == 'matrix':
        prior['kinds_RSF']['audit-share']['after']['tp'] = 4
    write(tmp_path/'prior.json', prior)
    plan = {'schema': 'frozen-score-diagnostic-plan-1', 'scope': 'observed_development_only',
        'goal_qualified': False, 'threshold_changes_allowed': False, 'prior': str(tmp_path/'prior.json'),
        'prior_sha256': digest(tmp_path/'prior.json'), 'scenarios': scenarios}
    if mutation == 'role':
        plan['scenarios'][2]['role'] = 'new_independent_holdout'
    if mutation == 'truth_pin':
        plan['scenarios'][0]['truth_sha256'] = '0'*64
    write(tmp_path/'plan.json', plan)
    return tmp_path/'plan.json', tmp_path/'output'


def test_complete_replay_keeps_all_sources_roles_matrices_and_real_label_access(tmp_path):
    plan, output = fixture(tmp_path)
    before = {p: digest(p) for p in tmp_path.rglob('*') if p.is_file()}
    result = replay.run(plan, digest(plan), output)
    assert result['completed'] and result['population'] == 12
    assert result['labels_reopened_for_diagnostic'] and not result['threshold_adopted']
    assert not result['goal_qualified'] and not result['predictions_changed']
    assert result['per_scenario']['fox']['role'] == 'predeclared_calibration'
    assert result['per_scenario']['harrison_observed']['role'] == 'previously_evaluated_now_observed'
    assert result['kinds_RSF']['audit-share']['population'] == 6
    assert result['kinds_RSF']['auth']['current']['precision'] is None
    assert not result['kinds_RSF']['auth']['score_only_target_feasible_on_observed_rows']
    access = list(replay.rows(output/'diagnostic-access.jsonl'))
    assert len(access) == 8
    assert [entry['phase'] for entry in access[:4]] == ['integrity_verification']*4
    assert [entry['phase'] for entry in access[4:]] == ['semantic_diagnostic']*4
    assert all(digest(p) == pin for p, pin in before.items())


@pytest.mark.parametrize('mutation', ['case_order', 'truncated', 'bool_source_index', 'score_decision',
                                    'nonbool_truth', 'extra_truth', 'matrix', 'role', 'truth_pin'])
def test_unpinned_reordered_incomplete_misreported_or_reclassified_data_cannot_complete(tmp_path, mutation):
    plan, output = fixture(tmp_path, mutation)
    with pytest.raises(ValueError):
        replay.run(plan, digest(plan), output)
    if (output/'run.json').exists():
        assert not json.loads((output/'run.json').read_bytes())['completed']
    if mutation in {'role', 'truth_pin'}:
        assert not output.exists()


def test_input_changed_during_label_assisted_analysis_keeps_incomplete_receipt(tmp_path, monkeypatch):
    plan, output = fixture(tmp_path)
    original = replay.rows
    changed = False

    def rows(path):
        nonlocal changed
        yield from original(path)
        if Path(path).name == 'truth.jsonl' and not changed:
            changed = True
            plan.write_bytes(plan.read_bytes()+b' ')

    monkeypatch.setattr(replay, 'rows', rows)
    with pytest.raises(ValueError):
        replay.run(plan, digest(plan), output)
    assert changed and not json.loads((output/'run.json').read_bytes())['completed']


def test_existing_output_is_never_overwritten(tmp_path):
    plan, output = fixture(tmp_path)
    output.mkdir()
    marker = output/'keep.txt'
    marker.write_text('existing evidence', encoding='utf8')
    with pytest.raises(FileExistsError):
        replay.run(plan, digest(plan), output)
    assert marker.read_text(encoding='utf8') == 'existing evidence'
