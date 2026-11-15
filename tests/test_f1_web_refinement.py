import hashlib

import pytest

from scripts.f1_lab.native_heads import NativeHeads
from scripts.f1_lab.raw_context import extra_observations
from scripts.f1_lab.raw_observations import raw_features
from scripts.f1_lab.raw_semantics import PROFILE, semantic_observations
from scripts.f1_lab.web_refinement import (
    EXCLUDED,
    RETENTION_FLAGS,
    WebRefinement,
    canonical,
    fit_http_tree,
    load_web_refinement,
)


def observed(line):
    return {**raw_features(line), **extra_observations(line), **semantic_observations(line)}


def http(target='/asset.js', *, volume=3):
    line = f'192.0.2.1 - - [21/Jan/2022:00:00:00 +0000] "GET {target} HTTP/1.1" 200 10 "-" "Mozilla/5.0"'
    return {**observed(line), 'http_window_available': True, 'http_requests_60s': volume}


@pytest.fixture
def models():
    baseline = NativeHeads(profile=PROFILE, tree_variant='ordered_binary')
    auth_normal = observed('Jan 21 00:00:00 host sshd[1]: Accepted password for alice from 192.0.2.1 port 22 ssh2')
    auth_attack = observed('Jan 21 00:00:00 host sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2')
    for _ in range(10):
        # Deliberately reproduce the old volume shortcut in the functional fixture.
        for f, truth in ((http(volume=0), False), (http(), True), (auth_normal, False), (auth_attack, True)):
            baseline.observe_training(f, truth)
    baseline.fit()
    training = [(http(volume=v), False) for v in (0, 3) for _ in range(10)]
    training += [(http('/?q=union+select+password+from+users', volume=v), True) for v in (0, 3) for _ in range(10)]
    tree, report = fit_http_tree(iter(training))
    sha = hashlib.sha256(canonical(baseline.export())+b'\n').hexdigest()
    model = WebRefinement(baseline, sha, tree, '1'*64)
    return baseline, model, sha, auth_normal, auth_attack, report


def test_benign_browser_burst_lowers_alert_without_creating_a_new_alert(models):
    baseline, model, *_ = models
    assert baseline.probability(http()) == 1
    result = model.score(http())
    assert result.score == 0 and result.reason == 'low_evidence_score'
    assert model.probability(http(volume=0)) == baseline.probability(http(volume=0)) == 0


@pytest.mark.parametrize('flag', RETENTION_FLAGS)
def test_spoofed_browser_with_attack_indicators_keeps_baseline_alarm(models, flag):
    baseline, model, *_ = models
    features = {**http(), flag: True}
    result = model.score(features)
    assert result.score == baseline.probability(features) == 1
    assert result.reason == 'retain_security_or_extreme_rate'


@pytest.mark.parametrize('changes', [
    {'http_requests_1s': 6}, {'http_requests_60s': 6}, {'http_user_agent_kind': 'scanner'},
    {'http_method': 'POST'}, {'http_status_class': 3}, {'http_status_class': 4}, {'http_status_class': 5},
    {'http_window_available': False}, {'http_semantic_available': False},
    {'http_semantic_parse_error': True}, {'http_encoding_replacement': True},
])
def test_extreme_rates_and_ineligible_or_unknown_requests_cannot_be_suppressed(models, changes):
    baseline, model, *_ = models
    features = {**http(), **changes}
    assert model.probability(features) == baseline.probability(features) == 1


def test_non_http_scores_and_models_are_unchanged(models):
    baseline, model, _, normal, attack, _ = models
    before = canonical(baseline.export())
    for features in (normal, attack):
        result = model.score(features)
        assert result.score == baseline.probability(features)
        assert result.reason == 'non_http_unchanged'
    assert canonical(baseline.export()) == before


def test_excluded_volume_features_do_not_change_fitted_evidence_tree(models):
    _, model, *rest = models
    tree = model._tree
    first = tree.probability(http(volume=0))
    for value in range(7):
        features = {**http(), **{name: value for name in EXCLUDED}}
        assert tree.probability(features) == first
    assert rest[-1]['http_classes'] == [20, 20]


def test_ambiguous_or_unavailable_refinement_retains_original_score(models, monkeypatch):
    baseline, model, *_ = models
    monkeypatch.setattr(model._tree, 'probability', lambda _: .1)
    assert model.score(http()).reason == 'retain_ambiguous_score'
    assert model.probability(http()) == baseline.probability(http())
    def fail(_):
        raise ValueError('injected_refiner_failure')
    monkeypatch.setattr(model._tree, 'probability', fail)
    assert model.score(http()).reason == 'refinement_unavailable'
    assert model.probability(http()) == baseline.probability(http())


def test_model_artifact_roundtrip_pins_baseline_and_does_not_train(models, tmp_path, monkeypatch):
    baseline, model, sha, *_ = models
    baseline_path, path = tmp_path/'baseline.json', tmp_path/'model.json'
    baseline_path.write_bytes(canonical(baseline.export())+b'\n')
    path.write_bytes(canonical(model.export())+b'\n')
    def forbidden(*_args, **_kwargs):
        raise AssertionError('inference attempted to train')
    monkeypatch.setattr(NativeHeads, 'fit', forbidden)
    restored = load_web_refinement(path, hashlib.sha256(path.read_bytes()).hexdigest(), baseline_path, sha)
    assert restored.probability(http()) == model.probability(http())
    exported = restored.export()
    exported['tree']['root']['probability'] = .99
    assert restored.export() == model.export()
    baseline_path.write_bytes(baseline_path.read_bytes()+b' ')
    with pytest.raises(ValueError, match='artifact_hash'):
        load_web_refinement(path, hashlib.sha256(path.read_bytes()).hexdigest(), baseline_path, sha)


@pytest.mark.parametrize('change', ['cutoff', 'excluded', 'methods', 'baseline', 'forbidden_split'])
def test_rehashed_policy_relaxations_or_volume_splits_are_rejected(models, tmp_path, change):
    baseline, model, sha, *_ = models
    data = model.export()
    if change == 'cutoff': data['benign_score_max'] = .9
    elif change == 'excluded': data['excluded_features'] = []
    elif change == 'methods': data['eligible_methods'].append('POST')
    elif change == 'baseline': data['baseline_model_sha256'] = 'f'*64
    else: data['tree'] = baseline.models['http'].export()
    path, base = tmp_path/'model.json', tmp_path/'baseline.json'
    path.write_bytes(canonical(data))
    base.write_bytes(canonical(baseline.export())+b'\n')
    with pytest.raises(ValueError, match='web_artifact_contract|web_excluded_split'):
        load_web_refinement(path, hashlib.sha256(path.read_bytes()).hexdigest(), base, sha)


def test_truth_and_extra_fields_are_rejected_in_inference(models):
    _, model, *_ = models
    with pytest.raises(ValueError):
        model.probability({**http(), 'ground_truth': False})
    with pytest.raises(ValueError):
        model.probability(None)


def test_training_keeps_invalid_observations_counted_and_cannot_fit_one_class():
    samples = [(None, False), *[(http(), False)]*10]
    with pytest.raises(ValueError, match='both_classes_required'):
        fit_http_tree(iter(samples))
