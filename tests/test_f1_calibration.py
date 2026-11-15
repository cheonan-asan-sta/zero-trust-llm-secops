import hashlib
from pathlib import Path

import pytest

from app.services.detection_benchmark import DetectionBenchmark, metrics
from scripts import calibrate_f1_shadow as runner
from scripts.f1_lab import calibration as lab

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT/'infra/f1-lab/calibration.json'


@pytest.fixture
def contract():
    return lab.validate_contract(CONTRACT.read_bytes())


@pytest.fixture
def development():
    return [case for case in DetectionBenchmark().cases if case.split == 'development']


def test_declared_candidates_are_small_one_factor_trials_not_a_hidden_search(contract):
    base = contract['candidates'][0]
    assert len(contract['candidates']) == 7
    for candidate in contract['candidates'][1:]:
        assert sum(candidate[k] != base[k] for k in ('credential_failures', 'resource_fanout', 'bulk_download_mb')) == 1


@pytest.mark.parametrize('field,value', [('outer_folds', True), ('new_independent_evaluation', True),
    ('input_role', 'holdout'), ('selection', 'best observed holdout F1'), ('promotion', 'write app config')])
def test_contract_cannot_silently_change_population_or_promotion(contract, field, value):
    contract[field] = value
    with pytest.raises(ValueError):
        lab.validate_contract(lab.canonical(contract))


def test_duplicate_thresholds_do_not_get_extra_selection_opportunities(contract):
    contract['candidates'][1] = {**contract['candidates'][0], 'id': 'duplicate'}
    with pytest.raises(ValueError, match='duplicate_parameters'):
        lab.validate_contract(lab.canonical(contract))


def test_connected_groups_keep_every_declared_overlap_inside_one_fold(development):
    folds, audit = lab.connected_folds(development, 3)
    assert sorted(i for fold in folds for i in fold) == list(range(360))
    tokens = [{t for i in fold for t in lab.group_tokens(development[i])} for fold in folds]
    assert all(not tokens[i] & tokens[j] for i in range(3) for j in range(i))
    assert audit['cross_fold_family_subject_device_session_projection_overlap'] == 0
    assert sum(audit['fold_positive_counts']) == 180


def test_reordering_cases_cannot_change_fold_membership(development):
    first, _audit = lab.connected_folds(development, 3)
    other = list(reversed(development))
    second, _audit = lab.connected_folds(other, 3)
    assert [{development[i].case_id for i in fold} for fold in first] == [
        {other[i].case_id for i in fold} for fold in second]


def test_subject_reuse_connects_otherwise_different_families(development):
    first, second = development[0], development[100].model_copy(deep=True)
    second.event.user.user_id = first.event.user.user_id
    with pytest.raises(ValueError, match='insufficient_indivisible_groups'):
        lab.connected_folds([first, second], 2)


def test_historical_holdout_is_rejected_before_inference(contract, monkeypatch):
    cases = [case for case in DetectionBenchmark().cases if case.split == 'holdout']
    monkeypatch.setattr(lab, 'infer', lambda *_: pytest.fail('must reject before inference'))
    with pytest.raises(ValueError, match='development_unique_cases_only'):
        lab.calibrate(cases, contract)


def test_outer_fold_labels_do_not_select_the_candidate_evaluated_on_that_fold(development, contract):
    original = lab.calibrate(development, contract)
    fold = set(original['outer_folds'][0]['evaluation_case_ids'])
    changed = [case.model_copy(update={'threat': not case.threat}) if case.case_id in fold else case
               for case in development]
    counterfactual = lab.calibrate(changed, contract)
    assert original['outer_folds'][0]['selected_candidate'] == counterfactual['outer_folds'][0]['selected_candidate']
    assert original['outer_folds'][0]['training_scores'] == counterfactual['outer_folds'][0]['training_scores']
    assert original['outer_folds'][0]['evaluation'] != counterfactual['outer_folds'][0]['evaluation']


def test_selection_requires_valid_predictions_and_checks_all_four_margins():
    boundary = {'metrics': metrics({'tp': 95, 'fp': 5, 'fn': 5, 'tn': 95}), 'evaluation_errors': 0}
    high_recall_high_fpr = {'metrics': metrics({'tp': 100, 'fp': 20, 'fn': 0, 'tn': 80}), 'evaluation_errors': 0}
    assert lab.choose([high_recall_high_fpr, boundary]) == 1
    assert lab.choose([boundary, boundary]) == 0
    with pytest.raises(ValueError, match='no_valid_candidate'):
        lab.choose([{**boundary, 'evaluation_errors': 1}])


def test_executable_keeps_populations_and_never_promotes_selected_thresholds(tmp_path):
    anchor = hashlib.sha256(CONTRACT.read_bytes()).hexdigest()
    result = runner.run(CONTRACT, anchor, tmp_path/'result')
    assert result['out_of_fold_score']['case_count'] == 360
    assert result['previously_observed_holdout_diagnostic']['case_count'] == 360
    assert result['no_app_configuration_changes'] and not result['new_independent_evaluation']
    assert result['goal_qualified'] is False
    assert result['effects'] == {'cloud_calls': 0, 'paid_api_calls': 0, 'app_configuration_writes': 0}
    with pytest.raises(ValueError, match='fresh_directory'):
        runner.run(CONTRACT, anchor, tmp_path/'result')


def test_wrong_external_anchor_does_not_publish_output(tmp_path):
    with pytest.raises(ValueError, match='external_contract_anchor'):
        runner.run(CONTRACT, '0'*64, tmp_path/'result')
    assert not (tmp_path/'result').exists()


def test_changed_contract_during_execution_does_not_publish_success(tmp_path, monkeypatch):
    path = tmp_path/'contract.json'
    path.write_bytes(CONTRACT.read_bytes())
    anchor = hashlib.sha256(path.read_bytes()).hexdigest()
    original = runner.calibrate

    def changed(*args):
        result = original(*args)
        path.write_bytes(path.read_bytes()+b'\n')
        return result

    monkeypatch.setattr(runner, 'calibrate', changed)
    with pytest.raises(ValueError, match='source_or_contract_changed'):
        runner.run(path, anchor, tmp_path/'result')
    assert not (tmp_path/'result').exists()
