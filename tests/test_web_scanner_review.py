from dataclasses import replace

import pytest

from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.raw_context import extra_observations
from scripts.f1_lab.raw_observations import raw_features
from scripts.f1_lab.raw_semantics import semantic_observations
from scripts.f1_lab.web_scanner_review import REASON, refine


def observation(agent='Mozilla/5.0 (compatible; Nmap Scripting Engine)', method='GET', status=200):
    line = f'192.0.2.1 - - [21/Jan/2022:00:00:00 +0000] "{method} / HTTP/1.1" {status} 10 "-" "{agent}"'
    return {**raw_features(line), **extra_observations(line), **semantic_observations(line),
            'http_window_available': True}


def prior():
    return OperationDecision(.2, .2, False, False, 'unchanged')


@pytest.mark.parametrize('method', ['GET', 'HEAD'])
@pytest.mark.parametrize('status', [200, 301, 404, 500])
def test_explicit_scanner_read_is_advisory_and_does_not_prove_authorization(method, status):
    result = refine(prior(), observation(method=method, status=status))
    assert result.alert and result.review and result.score == .95 and result.baseline_score == .2
    assert result.reason == REASON and not result.automatic_enforcement_allowed


@pytest.mark.parametrize('changed', [
    {'scanner_agent': False}, {'http_user_agent_kind': 'browser'}, {'http_method': 'POST'},
    {'http_method': 'none'}, {'http_status_class': 0}, {'http_status_class': 1},
    {'http_semantic_available': False}, {'http_window_available': False},
    {'http_semantic_parse_error': True}, {'http_encoding_replacement': True},
])
def test_ambiguous_missing_or_inconsistent_observation_is_unchanged(changed):
    old = prior()
    assert refine(old, {**observation(), **changed}) is old


def test_ordinary_browser_and_existing_alert_keep_exact_decisions():
    old = prior()
    assert refine(old, observation(agent='Mozilla/5.0')) is old
    alert = replace(old, score=1., alert=True, review=True, reason='prior_security_intent')
    assert refine(alert, observation()) is alert


@pytest.mark.parametrize('score', [True, None, -.1, 1.1, float('nan'), float('inf')])
def test_invalid_prior_score_is_not_silently_repaired(score):
    with pytest.raises(ValueError, match='scanner_previous_values'):
        refine(replace(prior(), score=score), observation())


def test_truth_or_authority_inputs_are_rejected():
    with pytest.raises(ValueError, match='native_feature_population'):
        refine(prior(), {**observation(), 'malicious': True})
    with pytest.raises(ValueError, match='scanner_previous'):
        refine(replace(prior(), automatic_enforcement_allowed=True), observation())
