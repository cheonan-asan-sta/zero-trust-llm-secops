"""Successful POST is a model eligibility rule, never identity or authority."""

import hashlib
from dataclasses import replace

import pytest

from scripts.f1_lab.native_heads import NativeHeads
from scripts.f1_lab.native_jsonl import decode
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.raw_context import extra_observations
from scripts.f1_lab.raw_observations import raw_features
from scripts.f1_lab.raw_semantics import PROFILE, semantic_observations
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.web_post_refinement import REASON, SuccessfulPostRefinement
from scripts.f1_lab.web_refinement import RETENTION_FLAGS, WebRefinement, fit_http_tree
from scripts.run_web_post_refinement import predict


def features(path='/form.php', volume=3):
    line = ('192.0.2.1 - - [21/Jan/2022:00:00:00 +0000] '
            f'"POST {path} HTTP/1.1" 200 10 "-" "Mozilla/5.0"')
    return {**raw_features(line), **extra_observations(line), **semantic_observations(line),
            'http_window_available': True, 'http_requests_60s': volume}


@pytest.fixture
def model():
    base = NativeHeads(profile=PROFILE, tree_variant='ordered_binary')
    for _ in range(10):
        base.observe_training(features(volume=0), False)
        base.observe_training(features(), True)
    base.fit()
    training = [(features(volume=v), False) for v in (0, 3) for _ in range(10)]
    training += [(features('/form.php?q=union+select+password+from+users', volume=v), True)
                 for v in (0, 3) for _ in range(10)]
    tree, _ = fit_http_tree(training)
    baseline_sha = hashlib.sha256(canonical(base.export())+b'\n').hexdigest()
    return SuccessfulPostRefinement(WebRefinement(base, baseline_sha, tree, 'a'*64))


def prior():
    return OperationDecision(1., 1., True, True, 'unchanged')


def test_successful_post_low_evidence_reduces_alert_without_grant(model):
    before = canonical(model.web_model.export())
    result = model.refine(prior(), features())
    assert result.score == 0 and not result.alert and not result.review
    assert result.reason == REASON and result.baseline_score == 1
    assert not result.automatic_enforcement_allowed
    assert canonical(model.web_model.export()) == before


@pytest.mark.parametrize('flag', RETENTION_FLAGS)
def test_explicit_attack_flags_keep_alarm(model, flag):
    old = prior()
    assert model.refine(old, {**features(), flag: True}) is old


@pytest.mark.parametrize('changed', [
    {'http_method': 'GET'}, {'http_method': 'OPTIONS'}, {'http_status_class': 3},
    {'http_status_class': 4}, {'http_status_class': 5}, {'http_window_available': False},
    {'http_semantic_available': False}, {'http_semantic_parse_error': True},
    {'http_encoding_replacement': True}, {'http_requests_1s': 6},
    {'http_requests_60s': 6}, {'http_user_agent_kind': 'scanner'},
])
def test_other_methods_errors_unknown_and_extreme_rate_keep_alarm(model, changed):
    old = prior()
    assert model.refine(old, {**features(), **changed}) is old


@pytest.mark.parametrize('reason', [
    'encoded_credential_file_read_intent', 'encoded_command_after_credential_read_intent',
    'same_client_distinct_missing_script_burst', 'uploaded_script_encoded_argv',
    'vpn_history_risk_review', 'missing_context', 'unknown_upstream',
])
def test_upstream_security_or_review_reasons_cannot_be_suppressed(model, reason):
    old = replace(prior(), reason=reason)
    assert model.refine(old, features()) is old


def test_low_evidence_boundary_and_ambiguity(model, monkeypatch):
    monkeypatch.setattr(model.tree, 'probability', lambda _: .05)
    assert model.refine(prior(), features()).score == .05
    monkeypatch.setattr(model.tree, 'probability', lambda _: .050001)
    old = prior()
    assert model.refine(old, features()) is old


@pytest.mark.parametrize('probability', [float('nan'), float('inf'), -.1, 1.1, True, None])
def test_invalid_model_probability_is_not_a_normal_prediction(model, monkeypatch, probability):
    monkeypatch.setattr(model.tree, 'probability', lambda _: probability)
    with pytest.raises(ValueError, match='evidence_probability'):
        model.refine(prior(), features())


def test_mismatched_baseline_cannot_erase_upstream_score(model):
    with pytest.raises(ValueError, match='baseline_score_binding'):
        model.refine(replace(prior(), score=.99), features())


def test_truth_fields_invalid_features_or_automatic_enforcement_rejected(model):
    with pytest.raises(ValueError):
        model.refine(prior(), {**features(), 'ground_truth': False})
    with pytest.raises(ValueError):
        model.refine(prior(), None)
    with pytest.raises(ValueError, match='post_previous'):
        model.refine(replace(prior(), automatic_enforcement_allowed=True), features())


def test_existing_negative_decision_cannot_become_new_alarm(model):
    old = OperationDecision(.1, .1, False, False, 'unchanged')
    assert model.refine(old, features()) is old


def replay_fixture(tmp_path, rows):
    source = 'b' * 64
    inputs, previous = [], []
    for ordinal, (values, probability, error) in enumerate(rows, 1):
        case_id = hashlib.sha256((source + ':' + str(ordinal)).encode()).hexdigest()
        inputs.append({'case_id': case_id, 'features': values, 'observation_error': None})
        previous.append({'case_id': case_id, 'source_index': 0, 'after': None if error else probability >= .95,
            'before_score': probability, 'after_score': probability, 'reason': 'unchanged', 'error': error})
    path = tmp_path/'inputs.jsonl'
    path.write_bytes(b''.join(canonical(row)+b'\n' for row in inputs))
    old = tmp_path/'old.jsonl'
    old.write_bytes(b''.join(canonical(row)+b'\n' for row in previous))
    prep = {'pairs': [{'raw_sha256': source, 'rows': len(rows)}],
            'files': {'inputs.jsonl': {'sha256': sha(path)}}}
    return prep, old


def test_replay_without_truth_preserves_errors_and_attack_guards(model, tmp_path):
    prep, old = replay_fixture(tmp_path, [(features(), 1., None),
        ({**features(), 'http_requests_1s': 6}, 1., None), (None, None, 'old_error')])
    output = tmp_path/'new.jsonl'
    result = predict(tmp_path, prep, old, sha(old), model, output)
    rows = [decode(row) for row in output.read_bytes().splitlines()]
    assert [row['after'] for row in rows] == [False, True, None]
    assert result['population'] == 3 and result['inference_errors'] == 1
    assert not result['labels_opened_by_predictor'] and not (tmp_path/'truth.jsonl').exists()
    assert not output.with_suffix('.jsonl.part').exists()


def test_inference_failure_stays_in_population(model, tmp_path):
    prep, old = replay_fixture(tmp_path, [(features(), .99, None)])
    output = tmp_path/'new.jsonl'
    result = predict(tmp_path, prep, old, sha(old), model, output)
    row = decode(output.read_bytes())
    assert result['population'] == 1 and result['inference_errors'] == 1
    assert row['before'] is True and row['after'] is None


def test_population_failure_cannot_seal_partial_output(model, tmp_path):
    prep, old = replay_fixture(tmp_path, [(features(), 1., None)])
    old.write_bytes(old.read_bytes()*2)
    output = tmp_path/'new.jsonl'
    with pytest.raises(ValueError, match='extra_baseline'):
        predict(tmp_path, prep, old, sha(old), model, output)
    assert not output.exists() and output.with_suffix('.jsonl.part').exists()


def test_changed_baseline_and_existing_output_fail(model, tmp_path):
    prep, old = replay_fixture(tmp_path, [(features(), 1., None)])
    output = tmp_path/'new.jsonl'
    with pytest.raises(ValueError, match='baseline_hash'):
        predict(tmp_path, prep, old, 'f'*64, model, output)
    output.write_bytes(b'previous evidence')
    with pytest.raises(ValueError, match='fresh_output'):
        predict(tmp_path, prep, old, sha(old), model, output)
    assert output.read_bytes() == b'previous evidence'
