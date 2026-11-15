import json

import pytest

from scripts.f1_lab.dns_context import DNS_DOMAINS, PROFILE, DNSWindow, empty, observe_syntax
from scripts.f1_lab.native_bayes import feature_domains, validate
from scripts.f1_lab.native_binary_tree import NativeBinaryTree


def line(message, *, host='resolver', pid=123):
    return f'Jan 24 12:00:00 {host} dnsmasq[{pid}]: {message}\n'


@pytest.mark.parametrize('kind', ['A', 'AAAA', 'PTR', 'TXT', 'MX', 'NS', 'SOA', 'CNAME', 'SRV', 'ANY'])
def test_exact_query_kind_and_transient_keys_only(kind):
    facts, keys = observe_syntax(line(f'query[{kind}] Private.Example. from 192.0.2.1'))
    assert facts['dns_record_type'] == kind and facts['dns_query_peer_available']
    assert set(facts) == set(DNS_DOMAINS) and all(isinstance(key, bytes) and len(key) == 32 for key in keys)
    assert '192.0.2.1' not in json.dumps(facts) and 'private' not in json.dumps(facts).lower()
    assert keys == observe_syntax(line(f'query[{kind}] private.example from 192.0.2.1'))[1]


@pytest.mark.parametrize('message', ['query[A] bad..example from 192.0.2.1',
    'query[A] '+('x'*64)+'.example from 192.0.2.1',
    'untrusted: query[A] private.example from 192.0.2.1',
    'query[A] private.example from 192.0.2.1 extra', 'query[A] private.example from invalid'])
def test_invalid_or_embedded_query_does_not_enter_peer_history(message):
    facts, keys = observe_syntax(line(message))
    assert keys is None and not facts['dns_query_peer_available']
    assert not DNSWindow().observe(line(message), 1)['dns_query_window_available']


@pytest.mark.parametrize('body,kind,local', [('reply a.example is NXDOMAIN', 'negative', False),
    ('cached a.example is NODATA', 'negative', False), ('reply a.example is <CNAME>', 'alias', False),
    ('reply a.example is 2001:db8::1', 'address', False), ('/etc/hosts a.example is 192.0.2.1', 'address', True)])
def test_answers_never_invent_requester_or_query_type(body, kind, local):
    facts, keys = observe_syntax(line(body))
    assert facts['dns_semantic_available'] and facts['dns_response_kind'] == kind
    assert facts['dns_local_answer'] is local and keys is None and facts['dns_record_type'] == 'unknown'
    assert not facts['dns_query_peer_available'] and not facts['dns_query_window_available']


def test_equal_time_queries_do_not_see_each_other_or_future_queries():
    window = DNSWindow()
    for index in range(10):
        facts = window.observe(line(f'query[A] n{index}.example from 192.0.2.1'), 100)
        assert facts['dns_peer_queries_1s'] == facts['dns_peer_queries_60s'] == 0
    facts = window.observe(line('query[A] next.example from 192.0.2.1'), 101)
    assert facts['dns_peer_queries_1s'] == 3 and facts['dns_peer_queries_60s'] == 1
    assert facts['dns_peer_names_60s'] == 2


def test_other_client_and_answers_do_not_borrow_query_history():
    window = DNSWindow()
    for _ in range(10):
        window.observe(line('query[A] private.example from 192.0.2.1'), 100)
    other = window.observe(line('query[A] private.example from 192.0.2.2'), 101)
    answer = window.observe(line('reply private.example is 192.0.2.3'), 102)
    assert other['dns_peer_queries_60s'] == 0 and not answer['dns_query_window_available']


@pytest.mark.parametrize('mode', ['regression', 'different_process', 'different_host', 'expiry'])
def test_expired_regressed_or_different_scope_cannot_carry_history(mode):
    window = DNSWindow()
    for _ in range(10):
        window.observe(line('query[A] private.example from 192.0.2.1'), 100)
    window.observe(line('query[A] private.example from 192.0.2.1'), 101)
    kwargs = {'pid': 456} if mode == 'different_process' else {'host': 'other'} if mode == 'different_host' else {}
    stamp = 99 if mode == 'regression' else 162 if mode == 'expiry' else 102
    value = window.observe(line('query[A] private.example from 192.0.2.1', **kwargs), stamp)
    assert value['dns_peer_queries_60s'] == 0


def test_ipv6_peer_and_reverse_query_are_observations_not_authority():
    window = DNSWindow()
    raw = line('query[PTR] 1.2.0.192.in-addr.arpa from 2001:db8::1')
    assert window.observe(raw, 1)['dns_reverse_name']
    assert window.observe(raw, None)['dns_query_peer_available']
    assert not window.observe(raw, None)['dns_query_window_available']
    assert not any('trust' in key or 'identity' in key for key in empty())


@pytest.mark.parametrize('message', ['reply a.example is NXDOMAIN',
    'forwarded a.example to 192.0.2.53', 'started, version 2.90 cachesize 150',
    'query[A] bad..example from 192.0.2.1'])
@pytest.mark.parametrize('moment', [None, 100, 102])
@pytest.mark.parametrize('boundary', [{'pid': 456}, {'host': 'other'}])
def test_non_query_process_boundary_clears_committed_and_pending_history(message, moment, boundary):
    window = DNSWindow()
    query = line('query[A] private.example from 192.0.2.1')
    for _ in range(10):
        window.observe(query, 100)
    assert window.observe(query, 101)['dns_peer_queries_60s'] == 1
    window.observe(line(message, **boundary), moment)
    # Returning to the original PID must not resurrect its earlier counters.
    assert not window.groups and not window.pending
    assert window.observe(query, 103)['dns_peer_queries_60s'] == 0


def test_same_process_non_query_does_not_clear_usable_history():
    window = DNSWindow()
    query = line('query[A] private.example from 192.0.2.1')
    for _ in range(10):
        window.observe(query, 100)
    window.observe(line('reply private.example is NXDOMAIN'), None)
    assert window.observe(query, 101)['dns_peer_queries_60s'] == 1


@pytest.mark.parametrize('moment', [True, '1', float('nan'), float('inf')])
def test_invalid_time_rejected(moment):
    with pytest.raises(ValueError, match='dns_time'):
        DNSWindow().observe(line('query[A] a.example from 192.0.2.1'), moment)


def test_bound_rejects_oversize_and_non_string_inputs():
    for value in (b'query[A]', 'x'*(2*1024**2+1)):
        with pytest.raises(ValueError, match='dns_line_bound'):
            observe_syntax(value)


def test_new_profile_restores_tree_without_changing_old_profile_domains():
    old = {name: feature_domains(name).copy() for name in ('base', 'raw-http-auth-semantics-4')}
    normal = {name: domain[0] for name, domain in feature_domains(PROFILE).items()}
    attack = {**normal, 'dns_record_type': 'TXT'}
    tree = NativeBinaryTree(profile=PROFILE, min_leaf=2, class_balanced=False)
    for _ in range(5):
        tree.observe_training(normal, False)
        tree.observe_training(attack, True)
    tree.fit()
    restored = NativeBinaryTree.restore(tree.export())
    assert restored.probability(normal) == 0 and restored.probability(attack) == 1
    assert old == {name: feature_domains(name) for name in old}
    with pytest.raises(ValueError, match='feature_population'):
        validate({**normal, 'raw_peer': '192.0.2.1'}, profile=PROFILE)
