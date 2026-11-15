import pytest

from scripts.f1_lab.native_bayes import NativeBayes, feature_domains, validate
from scripts.f1_lab.raw_context import PROFILE as PREVIOUS_PROFILE
from scripts.f1_lab.raw_context import extra_observations
from scripts.f1_lab.raw_observations import raw_features
from scripts.f1_lab.vpn_context import PROFILE, empty, ordered_vpn_context


def line(peer='192.0.2.1:1194', *, name=None, message='VERIFY OK'):
    return '2022-01-21 00:00:00 '+(name+'/' if name else '')+peer+' '+message


def test_strict_past_excludes_all_equal_timestamp_rows_and_future():
    records = [(1, 10, line(message='TLS: Initial packet')), (2, 10, line(name='alice')), (3, 11, line())]
    result = ordered_vpn_context(records)
    for ordinal in (1, 2):
        assert not result[ordinal]['vpn_peer_seen_before']
        assert not result[ordinal]['vpn_connection_initial_before']
    assert result[3]['vpn_peer_seen_before'] and result[3]['vpn_peer_named_before']
    assert result[3]['vpn_connection_initial_before']
    extended = ordered_vpn_context([*records, (4, 12, line(peer='203.0.113.2:443', name='other'))])
    assert all(result[key] == extended[key] for key in result)
    reversed_ties = ordered_vpn_context([records[1], records[0], records[2]])
    assert reversed_ties == result


def test_endpoint_names_and_addresses_are_link_keys_never_memorized_features():
    a = ordered_vpn_context([(1, 1, line(name='alice')), (2, 2, line(name='alice'))])
    b = ordered_vpn_context([(1, 1, line('203.0.113.9:443', name='bob')),
                             (2, 2, line('203.0.113.9:443', name='bob'))])
    assert a == b
    assert all(type(value) in (bool, int) for row in a.values() for value in row.values())
    assert not any(name in str(a) for name in ('alice', '192.0.2', 'healthy', 'authorized', 'malicious'))


def test_peer_and_connection_state_do_not_merge_other_endpoints():
    result = ordered_vpn_context([(1, 1, line(name='alice')),
                                  (2, 2, line('203.0.113.2:1194', name='alice')),
                                  (3, 3, line('192.0.2.1:2222'))])
    assert not result[2]['vpn_peer_seen_before']
    assert result[3]['vpn_peer_seen_before'] and not result[3]['vpn_connection_seen_before']
    # Same logged name is not a proof of the same human/device.
    assert not result[2]['vpn_peer_named_before']


def test_duplicate_source_rows_count_once_without_dropping_scored_rows():
    initial = [(1, 1, line()), (2, 1, line())]
    result = ordered_vpn_context([*initial, (3, 2, line(name='alice'))])
    single = ordered_vpn_context([initial[0], (3, 2, line(name='alice'))])
    assert len(result) == 3 and result[3] == single[3]
    assert result[3]['vpn_connection_prior_rows'] == 1


def test_24_hour_expiration_and_new_source_isolation():
    result = ordered_vpn_context([(1, 1, line(name='alice')), (2, 86402, line())])
    assert not result[2]['vpn_peer_seen_before'] and not result[2]['vpn_peer_named_before']
    assert not ordered_vpn_context([(1, 2, line())])[1]['vpn_peer_seen_before']


@pytest.mark.parametrize('text,moment', [(line('999.0.0.1:1194'), 1), (line('192.0.2.1:0'), 1),
                                        (line('192.0.2.1:65536'), 1), ('VERIFY OK', 1),
                                        (line(), None)])
def test_missing_or_invalid_endpoint_and_time_remain_unavailable(text, moment):
    assert ordered_vpn_context([(1, moment, text)])[1] == empty()


@pytest.mark.parametrize('records', [[(1, float('nan'), line())], [(1, True, line())],
                                    [(1, 1, line()), (1, 2, line())]])
def test_invalid_time_and_duplicate_ordinal_rejected(records):
    with pytest.raises(ValueError):
        ordered_vpn_context(records)


def test_bounds_are_enforced_before_context_is_published(monkeypatch):
    import scripts.f1_lab.vpn_context as module
    monkeypatch.setattr(module, 'MAX_BYTES', 20)
    with pytest.raises(ValueError, match='vpn_input_bytes'):
        ordered_vpn_context([(1, 1, line())])
    monkeypatch.setattr(module, 'MAX_EVENTS', 0)
    with pytest.raises(ValueError, match='vpn_record_bound'):
        ordered_vpn_context([(1, 1, line())])


def test_new_feature_contract_preserves_old_profile_and_rejects_implicit_upgrade():
    before = {**raw_features(line()), **extra_observations(line())}
    validate(before, profile=PREVIOUS_PROFILE)
    after = {**before, **ordered_vpn_context([(1, 1, line())])[1]}
    assert feature_domains(PREVIOUS_PROFILE).keys() == before.keys()
    validate(after, profile=PROFILE)
    with pytest.raises(ValueError, match='feature_population'):
        validate(after, profile=PREVIOUS_PROFILE)
    model = NativeBayes(profile=PROFILE)
    for truth in (False, True):
        model.observe_training(after, truth)
    assert model.probability(after) == .5
