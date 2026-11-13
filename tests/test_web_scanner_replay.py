import hashlib
from dataclasses import replace

import pytest

from scripts import run_web_scanner_review as driver
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.native_jsonl import decode
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha
from tests.test_web_scanner_review import observation


def fixture(tmp_path, values):
    raw_hash = 'a'*64
    rows, previous = [], []
    for ordinal, (features, probability, error) in enumerate(values, 1):
        case = hashlib.sha256((raw_hash+':'+str(ordinal)).encode()).hexdigest()
        rows.append({'case_id': case, 'features': features, 'observation_error': None})
        previous.append({'case_id': case, 'source_index': 0, 'before_score': probability,
            'after': None if error else probability >= .95, 'after_score': probability,
            'reason': 'unchanged', 'error': error})
    inputs, old = tmp_path/'inputs.jsonl', tmp_path/'old.jsonl'
    inputs.write_bytes(b''.join(canonical(row)+b'\n' for row in rows))
    old.write_bytes(b''.join(canonical(row)+b'\n' for row in previous))
    prep = {'pairs': [{'raw_sha256': raw_hash, 'rows': len(rows)}],
            'files': {'inputs.jsonl': {'sha256': sha(inputs)}}}
    return prep, old


def test_actual_prediction_keeps_population_and_never_reads_truth(tmp_path):
    prep, old = fixture(tmp_path, [(observation(), .2, None),
        (observation(agent='Mozilla/5.0'), .2, None), (observation(), 1., None), (None, None, 'prior_error')])
    (tmp_path/'truth.jsonl').write_bytes(b'invalid truth; prediction must not read this')
    out = tmp_path/'new.jsonl'
    result = driver.predict(tmp_path, prep, old, sha(old), out)
    rows = [decode(body) for body in out.read_bytes().splitlines()]
    assert [r['before'] for r in rows] == [False, False, True, None]
    assert [r['after'] for r in rows] == [True, False, True, None]
    assert result['population'] == 4 and result['inference_errors'] == 1
    assert not result['labels_opened_by_predictor']


@pytest.mark.parametrize('mode', ['invalid_features', 'decreased_score', 'lost_alarm', 'automatic_enforcement'])
def test_invalid_candidate_remains_an_error_row(tmp_path, monkeypatch, mode):
    features = observation()
    if mode == 'invalid_features':
        features['truth'] = True
    prep, old = fixture(tmp_path, [(features, 1., None)])
    if mode != 'invalid_features':
        fields = {'score': .1} if mode == 'decreased_score' else {'alert': False} if mode == 'lost_alarm' else {'automatic_enforcement_allowed': True}
        monkeypatch.setattr(driver, 'refine', lambda before, _: replace(before, **fields))
    out = tmp_path/'new.jsonl'
    result = driver.predict(tmp_path, prep, old, sha(old), out)
    assert result['population'] == result['inference_errors'] == 1
    assert decode(out.read_bytes())['after'] is None


@pytest.mark.parametrize('mode', ['extra', 'truncated', 'reordered', 'wrong_hash'])
def test_mismatched_baseline_cannot_seal_prediction(tmp_path, mode):
    prep, old = fixture(tmp_path, [(observation(), .2, None), (observation(), .3, None)])
    original = old.read_bytes()
    if mode == 'extra':
        old.write_bytes(original+original)
    elif mode == 'truncated':
        old.write_bytes(original.splitlines(keepends=True)[0])
    elif mode == 'reordered':
        old.write_bytes(b''.join(reversed(original.splitlines(keepends=True))))
    out = tmp_path/'new.jsonl'
    with pytest.raises(ValueError):
        driver.predict(tmp_path, prep, old, 'f'*64 if mode == 'wrong_hash' else sha(old), out)
    assert not out.exists()


def test_existing_evidence_and_wrong_external_contract_are_not_overwritten(tmp_path):
    prep, old = fixture(tmp_path, [(observation(), .2, None)])
    out = tmp_path/'existing.jsonl'
    out.write_bytes(b'keep')
    with pytest.raises(ValueError, match='fresh_prediction'):
        driver.predict(tmp_path, prep, old, sha(old), out)
    assert out.read_bytes() == b'keep'
    with pytest.raises(ValueError, match='external_hash'):
        driver.run(old, 'f'*64, old, sha(old), tmp_path/'run')
    assert not (tmp_path/'run').exists()


def full_fixture(tmp_path):
    plan = {'scope': 'observed_development_only', 'goal_qualified': False, 'candidate': driver.REASON,
        'candidate_sha256': sha(driver.ROOT/'scripts/f1_lab/web_scanner_review.py'), 'scenarios': []}
    prior = {'completed': True, 'scope': 'observed_development_only', 'goal_qualified': False, 'scenarios': {}}
    for name in driver.SCENARIOS:
        folder = tmp_path/name
        folder.mkdir()
        prep, baseline = fixture(folder, [(observation(), .2, None), (observation(agent='Mozilla/5.0'), .2, None)])
        cases = [decode(body)['case_id'] for body in baseline.read_bytes().splitlines()]
        truth = folder/'truth.jsonl'
        truth.write_bytes(b''.join(canonical({'case_id': case, 'malicious': expected})+b'\n'
                                  for case, expected in zip(cases, [True, False], strict=True)))
        prep['files']['truth.jsonl'] = {'sha256': sha(truth)}
        prep_path = folder/'preparation.json'
        prep_path.write_bytes(canonical(prep)+b'\n')
        population = counts()
        record(population, True, False)
        record(population, False, False)
        prior['scenarios'][name] = {'population': 2, 'prediction': {'predictions_sha256': sha(baseline)},
                                   'metrics': {'after': metrics(population)}}
        plan['scenarios'].append({'name': name, 'prepared': str(folder), 'preparation_sha256': sha(prep_path),
                                 'baseline': str(baseline), 'baseline_sha256': sha(baseline)})
    plan_path, prior_path = tmp_path/'plan.json', tmp_path/'prior.json'
    plan_path.write_bytes(canonical(plan)+b'\n')
    prior_path.write_bytes(canonical(prior)+b'\n')
    return plan_path, prior_path


def test_full_run_seals_all_predictions_before_scoring_and_checks_paired_baseline(tmp_path, monkeypatch):
    plan, prior = full_fixture(tmp_path)
    out = tmp_path/'out'
    original_score, calls = driver.score, []

    def checked_score(*args):
        assert (out/'prediction-seal.json').is_file()
        assert all((out/(name+'-predictions.jsonl')).is_file() for name in driver.SCENARIOS)
        calls.append(args[0])
        return original_score(*args)

    monkeypatch.setattr(driver, 'score', checked_score)
    result = driver.run(plan, sha(plan), prior, sha(prior), out)
    assert len(calls) == 4 and result['completed'] and result['candidate_development_gate_passed']
    assert not result['goal_qualified'] and not result['production_adopted']
    assert all(row['changes'] == {'new_tp': 1, 'introduced_fp': 0, 'lost_tp': 0, 'removed_fp': 0}
               for row in result['scenarios'].values())


def test_prior_metric_drift_keeps_failed_run_instead_of_reporting_success(tmp_path):
    plan, prior = full_fixture(tmp_path)
    value = decode(prior.read_bytes())
    value['scenarios']['russellmitchell']['metrics']['after']['fn'] = 0
    prior.write_bytes(canonical(value)+b'\n')
    out = tmp_path/'out'
    with pytest.raises(ValueError, match='previous_score_drift'):
        driver.run(plan, sha(plan), prior, sha(prior), out)
    assert not decode((out/'run.json').read_bytes())['completed']
    assert (out/'prediction-seal.json').is_file()
