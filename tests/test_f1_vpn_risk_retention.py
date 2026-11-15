import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest

from scripts.f1_lab.operation_context import core_features
from scripts.f1_lab.operation_refinement import OperationRefinement
from scripts.f1_lab.raw_semantics import semantic_observations
from scripts.f1_lab.vpn_context import PROFILE
from scripts.f1_lab.vpn_risk_retention import RiskRetention, evidence_case, retained_contexts

SOURCE = 'a'*64


def line(named=False, port=12345, ip='192.0.2.1'):
    return f'2022-01-21 00:00:01 {"alice/" if named else ""}{ip}:{port} VERIFY OK\n'


def model():
    vpn = SimpleNamespace(profile=PROFILE, probability=lambda f: .94 if f['vpn_peer_named_now'] else .97)
    return RiskRetention(OperationRefinement(SimpleNamespace(probability=lambda _: 0.), vpn))


def get(contexts, ordinal):
    return next(c for c in contexts.values() if c.base.ordinal == ordinal)


def decide(candidate, context, raw):
    return candidate.decide({**core_features(raw), **semantic_observations(raw)}, context.base.case_id, context)


def test_named_authentication_does_not_clear_strictly_earlier_connection_risk():
    candidate = model()
    contexts = retained_contexts([(1, 1, line()), (2, 2, line(True))], SOURCE, candidate.vpn_model)
    second = get(contexts, 2)
    result = decide(candidate, second, line(True))
    assert second.age_seconds == 1 and second.prior_score == .97 and result.alert
    assert result.score == .97 and not result.automatic_enforcement_allowed
    assert evidence_case(second) == hashlib.sha256((SOURCE+':1').encode()).hexdigest()


def test_equal_time_is_withheld_and_future_cannot_change_past_decisions():
    candidate = model()
    tied = retained_contexts([(1, 2, line()), (2, 2, line(True))], SOURCE, candidate.vpn_model)
    assert not decide(candidate, get(tied, 2), line(True)).alert
    past = [(2, 1, line(True)), (1, 2, line())]
    a = retained_contexts(past, SOURCE, candidate.vpn_model)
    b = retained_contexts(past+[(3, 3, line())], SOURCE, candidate.vpn_model)
    assert get(a, 2) == get(b, 2) and get(a, 2).prior_score == 0


def test_exact_endpoint_source_scope_and_missing_time_have_no_risk_carry():
    candidate = model()
    records = [(1, 1, line()), (2, 2, line(True, port=54321)),
               (3, 2, line(True, ip='192.0.2.2')), (4, None, line(True))]
    contexts = retained_contexts(records, SOURCE, candidate.vpn_model)
    for ordinal, _, raw in records[1:]:
        assert not decide(candidate, get(contexts, ordinal), raw).alert
    fresh = retained_contexts([(1, 2, line(True))], 'b'*64, candidate.vpn_model)
    assert not decide(candidate, get(fresh, 1), line(True)).alert


def test_expiry_is_inclusive_and_held_risk_never_refreshes_expiry():
    candidate = model()
    contexts = retained_contexts([(1, 0, line()), (2, 59, line(True)),
                                 (3, 60, line(True)), (4, 60.001, line(True))], SOURCE, candidate.vpn_model)
    assert decide(candidate, get(contexts, 2), line(True)).alert
    assert decide(candidate, get(contexts, 3), line(True)).alert
    assert not decide(candidate, get(contexts, 4), line(True)).alert


@pytest.mark.parametrize('changes', [
    {'prior_score': float('nan')}, {'prior_score': 1.1}, {'prior_score': .9},
    {'evidence_ordinal': 2}, {'evidence_ordinal': 0}, {'age_seconds': 0.},
    {'age_seconds': 60.001}, {'age_seconds': float('inf')}, {'evidence_ordinal': None},
])
def test_invalid_evidence_fails_explicitly(changes):
    candidate = model()
    contexts = retained_contexts([(1, 1, line()), (2, 2, line(True))], SOURCE, candidate.vpn_model)
    with pytest.raises(ValueError, match='retention_'):
        decide(candidate, replace(get(contexts, 2), **changes), line(True))


def test_mutated_feature_binding_fails_before_risk_can_be_used():
    candidate = model()
    contexts = retained_contexts([(1, 1, line()), (2, 2, line(True))], SOURCE, candidate.vpn_model)
    current = get(contexts, 2)
    with pytest.raises(ValueError, match='feature_binding'):
        candidate.decide({**core_features(line(True)), **semantic_observations(line(True)),
                          'http_target_size': 1}, current.base.case_id, current)
    assert candidate.decide(core_features(line()), 'unknown').score == 0


def test_intrinsic_bad_model_score_fails_explicitly():
    candidate = model()
    candidate.vpn_model.probability = lambda _: float('nan')
    with pytest.raises(ValueError, match='intrinsic_score'):
        retained_contexts([(1, 1, line())], SOURCE, candidate.vpn_model)
