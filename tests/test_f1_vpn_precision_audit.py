import hashlib
from types import SimpleNamespace

import pytest

from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.vpn_precision_audit import (
    collision_bound,
    informational_declaration,
    metadata_candidate,
    paired_review,
    signature,
)
from scripts.f1_lab.vpn_risk_retention import retained_contexts

SOURCE = 'a'*64


def case(n, truth, before, after, key='b'*64):
    return {'case_id': hashlib.sha256(str(n).encode()).hexdigest(), 'malicious': truth,
            'before': before, 'after': after, 'signature': key}


def test_fp_gain_cannot_hide_one_lost_attack_even_if_net_fn_is_unchanged():
    rows = [case(1, True, True, False), case(2, True, False, True, 'c'*64),
            case(3, False, True, False)]
    result = paired_review(rows)
    assert result['before']['fn'] == result['after']['fn'] == 1
    assert result['changes']['lost_true_positives'] == 1
    assert not result['acceptable_without_recall_regression']


def test_true_dominance_requires_less_fp_and_retains_every_existing_tp():
    result = paired_review([case(1, True, True, True), case(2, False, True, False)])
    assert result['acceptable_without_recall_regression']
    assert not paired_review([case(1, True, True, True)])['acceptable_without_recall_regression']


def test_none_is_counted_in_denominator_and_rejected():
    result = paired_review([case(1, True, True, None), case(2, False, True, False)])
    assert result['after']['population'] == 2 and result['after']['fn'] == 1
    assert result['after']['inference_errors'] == 1 and not result['acceptable_without_recall_regression']


def test_collision_bound_is_label_assisted_and_cannot_be_used_as_inference():
    rows = [case(1, True, True, True), case(2, False, True, False),
            case(3, False, True, False, 'c'*64), case(4, False, False, False, 'd'*64)]
    result = collision_bound(rows)
    assert result['label_assisted_diagnostic_only']
    assert result['mandatory_fp_if_all_baseline_tp_retained'] == 1
    assert result['fp_in_unmixed_signatures'] == 1 and result['mixed_signature_count'] == 1
    assert result['witnesses'][0]['attack_case'] == rows[0]['case_id']


def test_signature_that_omits_baseline_determining_observations_is_rejected():
    with pytest.raises(ValueError, match='signature_incomplete'):
        collision_bound([case(1, True, True, True), case(2, False, False, False)])


@pytest.mark.parametrize('change', [
    {'case_id': 'bad'}, {'signature': 'bad'}, {'malicious': 1}, {'before': 1}, {'after': 'false'},
    {'new_label_feature': True},
])
def test_invalid_scored_rows_are_never_silently_dropped(change):
    row = {**case(1, True, True, True), **change}
    with pytest.raises(ValueError):
        paired_review([row])


def test_duplicate_cases_and_empty_populations_fail():
    with pytest.raises(ValueError, match='duplicate_case'):
        paired_review([case(1, True, True, True)]*2)
    with pytest.raises(ValueError, match='row_bound'):
        paired_review([])


def line(message, *, named=True, port=12345):
    return f'2022-01-21 00:00:01 {"alice/" if named else ""}192.0.2.1:{port} {message}\n'


CIPHER = "Outgoing Data Channel: Cipher 'AES-256-CBC' initialized with 256 bit key"


@pytest.mark.parametrize('message', [
    CIPHER, "Incoming Data Channel: Using 160 bit message hash 'SHA1' for HMAC authentication",
    "Incoming Data Channel: Cipher 'CHACHA20-POLY1305' initialized with 256 bit key",
])
def test_candidate_grammar_does_not_whitelist_one_product_algorithm_or_name(message):
    assert informational_declaration(line(message))


@pytest.mark.parametrize('message', [CIPHER+'; exec(x)', CIPHER+' AUTH_FAILED',
    "Outgoing Data Channel: Cipher 'x;id' initialized with 256 bit key", 'VERIFY OK', 'global event'])
def test_unknown_or_suspicious_messages_are_not_information_exceptions(message):
    assert not informational_declaration(line(message))


def candidate(records, score=.98, baseline=0.):
    model = SimpleNamespace(probability=lambda _: score)
    contexts = retained_contexts(records, SOURCE, model)
    scores = {key: baseline for key in contexts}
    return metadata_candidate(records, SOURCE, model, scores), contexts, model, scores


def test_same_time_metadata_is_a_real_counterexample_not_an_accepted_improvement():
    records = [(1, 1, line('TLS: Initial packet', named=False)), (2, 1, line(CIPHER))]
    values, contexts, _, _ = candidate(records)
    current = next(c for c in contexts.values() if c.base.ordinal == 2)
    rows = [case(1, True, True, values[current.base.case_id] >= .95),
            case(2, False, True, False)]
    assert values[current.base.case_id] == 0
    assert not paired_review(rows)['acceptable_without_recall_regression']


def test_earlier_risk_is_preserved_but_other_connections_and_future_are_not_used():
    records = [(1, 1, line('TLS: Initial packet', named=False)), (2, 2, line(CIPHER)),
               (3, 2, line(CIPHER, port=54321)), (4, 3, line('TLS: Initial packet', named=False))]
    values, contexts, _, _ = candidate(records)
    by_n = {c.base.ordinal: c.base.case_id for c in contexts.values()}
    assert values[by_n[2]] == .98 and values[by_n[3]] == 0
    earlier, _, _, _ = candidate(records[:-1])
    assert all(earlier[k] == values[k] for k in earlier)


def test_missing_time_peer_and_existing_base_alarm_never_get_suppressed():
    records = [(1, None, line(CIPHER)), (2, 2, 'daemon observation\n')]
    values, _, _, _ = candidate(records, baseline=1.)
    assert set(values.values()) == {1.}
    values, _, model, scores = candidate([(1, 1, line(CIPHER))])
    with pytest.raises(ValueError, match='baseline_population'):
        metadata_candidate([(1, 1, line(CIPHER))], SOURCE, model, {})
    scores[next(iter(scores))] = float('nan')
    with pytest.raises(ValueError, match='baseline_score'):
        metadata_candidate([(1, 1, line(CIPHER))], SOURCE, model, scores)


def test_signature_binds_only_observations_and_held_risk():
    _, contexts, _, _ = candidate([(1, 1, line(CIPHER))])
    current = next(iter(contexts.values()))
    a = signature(current.base.vpn_features, current, True)
    assert a == signature(dict(current.base.vpn_features), current, True)
    assert a != signature(current.base.vpn_features, current, False)


def test_raw_reader_rejects_rehashed_wrong_source_or_oversized_inputs(tmp_path, monkeypatch):
    from scripts.audit_vpn_precision import raw_records
    body = b'2022-01-21 00:00:01 daemon event\n'
    (tmp_path/'pair-0-raw.source').write_bytes(body)
    sha = hashlib.sha256(body).hexdigest()
    provenance = {'raw_member': 'host/openvpn.log', 'raw_sha256': sha,
                  'simulation_start': 1642723200, 'simulation_end': 1642809600}
    pair = {'provenance': provenance, 'raw_rows': 1}
    prepared = {'raw_member': provenance['raw_member'], 'raw_sha256': sha, 'rows': 1}
    records, errors = raw_records(tmp_path, 0, pair, prepared)
    assert len(records) == 1 and errors == 0
    with pytest.raises(ValueError, match='source_alignment'):
        raw_records(tmp_path, 0, pair, {**prepared, 'raw_sha256': 'f'*64})
    monkeypatch.setattr('scripts.audit_vpn_precision.MAX_EVENTS', 0)
    with pytest.raises(ValueError, match='raw_bound'):
        raw_records(tmp_path, 0, pair, prepared)


def test_comparator_evaluates_all_rows_after_prediction_and_reproduces_baseline(tmp_path, monkeypatch):
    import scripts.audit_vpn_precision as runner
    from scripts.f1_lab.operation_refinement import OperationRefinement
    from scripts.f1_lab.vpn_context import PROFILE
    from scripts.f1_lab.vpn_risk_retention import RiskRetention
    records = [(1, 1, line('TLS: Initial packet', named=False)), (2, 1, line(CIPHER))]
    vpn = SimpleNamespace(profile=PROFILE, probability=lambda _: .98)
    base = SimpleNamespace(probability=lambda _: 0.)
    model = RiskRetention(OperationRefinement(base, vpn))
    c = counts()
    record(c, True, True)
    record(c, False, True)
    monkeypatch.setattr(runner, 'annotations', lambda *_: ({1: ['attack']}, {}))
    result = runner.compare_source(records, SOURCE, model, tmp_path/'labels', 'b'*64, metrics(c))
    assert result['population'] == 2
    assert result['policies']['metadata_only']['after']['fp'] == 0
    assert result['collision']['mandatory_fp_if_all_baseline_tp_retained'] == 0
