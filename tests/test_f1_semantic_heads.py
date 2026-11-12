import copy

import pytest

from scripts.f1_lab.native_heads import NativeHeads, gate
from scripts.f1_lab.raw_context import PROFILE as OLD_PROFILE
from scripts.f1_lab.raw_context import extra_observations
from scripts.f1_lab.raw_observations import raw_features
from scripts.f1_lab.raw_semantics import PROFILE, semantic_observations


def features(line):
    return {**raw_features(line), **extra_observations(line), **semantic_observations(line)}


def test_extended_observation_gate_is_profile_specific_and_old_gate_preserved():
    text = 'Jan 21 00:00:00 server systemd-logind[12]: New session c1 of user alice.'
    observed = features(text)
    previous = {**raw_features(text), **extra_observations(text)}
    assert gate(previous, profile=OLD_PROFILE) == 'other'
    assert gate(observed, profile=PROFILE) == 'auth'
    assert gate(features('type=LOGIN uid=1000 auid=1000 ses=12 '), profile=PROFILE) == 'audit'


def test_semantic_heads_roundtrip_and_gate_version_cannot_be_forged():
    observed = features('Jan 21 00:00:00 server su[12]: Successful su for alice by daemon')
    model = NativeHeads(profile=PROFILE, tree_variant='ordered_binary')
    for truth in (False, True):
        model.observe_training(observed, truth)
    model.fit()
    payload = model.export()
    assert payload['gate_version'] == 'observed-format-2-semantic'
    restored = NativeHeads.restore(payload)
    assert restored.probability(observed) == model.probability(observed) == .5
    forged = copy.deepcopy(payload)
    forged['gate_version'] = 'observed-format-1'
    with pytest.raises(ValueError, match='gate_binding'):
        NativeHeads.restore(forged)


def test_unsupported_semantic_head_abstains_instead_of_claiming_safety():
    model = NativeHeads(profile=PROFILE)
    model.observe_training(features('type=LOGIN uid=0 auid=0 ses=1 '), False)
    model.fit()
    with pytest.raises(ValueError, match='insufficient_class_support'):
        model.probability(features('type=LOGIN uid=1000 auid=1000 ses=2 '))
