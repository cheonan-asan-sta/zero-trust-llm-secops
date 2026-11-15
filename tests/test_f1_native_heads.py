import hashlib
import json

import pytest

from scripts.f1_lab.native_heads import NativeHeads, gate, load_frozen_heads
from scripts.f1_lab.raw_context import extra_observations
from scripts.f1_lab.raw_observations import raw_features


def example(kind, attack=False):
    if kind == 'cpu':
        value = {'@timestamp': '2022-01-21T00:00:00Z', 'system': {'cpu': {
            name: {'norm': {'pct': number}} for name, number in [('total', 1 if attack else .1),
                    ('user', .1), ('nice', .9 if attack else 0), ('system', 0)]}}}
        line = json.dumps(value)
    else:
        line = 'Jan 21 00:00:00 dnsmasq: query[A] '+('a'*100 if attack else 'www.example.org')+' from 192.0.2.1'
    return {**raw_features(line), **extra_observations(line)}


def fitted(dns_count=5, tree_variant='categorical'):
    model = NativeHeads(min_leaf=1, tree_variant=tree_variant)
    for attack in (False, True):
        for _ in range(5): model.observe_training(example('cpu', attack), attack)
        for _ in range(dns_count): model.observe_training(example('dns', attack), attack)
    return model.fit()


def test_dns_volume_does_not_change_cpu_model_or_prediction():
    small, large = fitted(5), fitted(1000)
    assert gate(example('cpu')) == 'cpu' and gate(example('dns')) == 'dns'
    assert small.models['cpu'].export() == large.models['cpu'].export()
    assert small.probability(example('cpu', True)) == large.probability(example('cpu', True)) == 1
    assert small.probability(example('cpu', False)) == 0


def test_no_training_support_abstains_instead_of_assuming_safe():
    model = fitted()
    line = '2022-01-21 00:00:00 TLS: Initial packet'
    features = {**raw_features(line), **extra_observations(line)}
    assert gate(features) == 'vpn'
    with pytest.raises(ValueError, match='insufficient_class_support'):
        model.probability(features)


def test_pinned_artifact_restores_without_learning(tmp_path):
    original = fitted()
    path = tmp_path/'model.json'
    path.write_text(json.dumps(original.export()))
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    restored = load_frozen_heads(path, sha)
    assert restored.export() == original.export()
    assert restored.probability(example('cpu', True)) == 1
    with pytest.raises(ValueError, match='already_fitted'):
        restored.observe_training(example('cpu'), False)
    path.write_bytes(path.read_bytes()+b' ')
    with pytest.raises(ValueError, match='artifact_hash'):
        load_frozen_heads(path, sha)


def test_head_counts_cannot_be_forged_after_rehashing():
    artifact = fitted().export()
    artifact['class_counts']['cpu'][0] += 1
    with pytest.raises(ValueError, match='model_binding'):
        NativeHeads.restore(artifact)


def test_ordered_heads_artifact_roundtrip_and_variant_binding():
    model = fitted(tree_variant='ordered_binary')
    artifact = model.export()
    restored = NativeHeads.restore(artifact)
    assert restored.export() == artifact and restored.probability(example('cpu', True)) == 1
    artifact['tree_variant'] = 'categorical'
    with pytest.raises(ValueError, match='artifact_schema'):
        NativeHeads.restore(artifact)
