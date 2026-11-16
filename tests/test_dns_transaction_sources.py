import copy
import hashlib
import io
import json
from dataclasses import asdict

import pytest

from scripts.f1_lab.dns_transaction_fence import DnsTransactionFence
from scripts.f1_lab.dns_transaction_projection import name_shape, project
from scripts.f1_lab.transfer_evaluation import sha


def counters():
    return [{'ordinal': 1, 'timestamp_us': 99000000, 'dns_udp_transactions': 0, 'kernel_packets': 0,
             'kernel_drops': 0, 'decoder_packets': 0, 'uptime': 1, 'row_sha256': 'a' * 64},
            {'ordinal': 5, 'timestamp_us': 102000000, 'dns_udp_transactions': 3, 'kernel_packets': 4,
             'kernel_drops': 0, 'decoder_packets': 4, 'uptime': 4, 'row_sha256': 'b' * 64}]


def events():
    def stats(stamp, tx, packets, uptime):
        return {'event_type': 'stats', 'timestamp': f'1970-01-01T00:01:{stamp}+00:00',
                'stats': {'app_layer': {'tx': {'dns_udp': tx}}, 'capture': {'kernel_packets': packets,
                    'kernel_drops': 0}, 'decoder': {'pkts': packets}, 'uptime': uptime}}
    label = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+'
    base = {'event_type': 'dns', 'timestamp': '1970-01-01T00:01:40+00:00', 'flow_id': 42, 'proto': 'UDP',
            'src_ip': '192.0.2.1', 'src_port': 12345, 'dest_ip': '198.51.100.1', 'dest_port': 53}
    query = {**base, 'dns': {'type': 'query', 'id': 123, 'tx_id': 0, 'rrtype': 'A',
                           'rrname': '.'.join([label] * 3 + ['example'])}}
    answer = {**base, 'timestamp': '1970-01-01T00:01:40.1+00:00',
              'dns': {'type': 'answer', 'id': 123, 'version': 2}}
    second = copy.deepcopy(query)
    second['timestamp'], second['dns']['tx_id'] = '1970-01-01T00:01:41+00:00', 2
    return [stats('39', 0, 0, 1), query, answer, second, stats('42', 3, 4, 4)]


def project_rows(tmp_path, rows):
    body = b''.join((json.dumps(row) + '\n').encode() for row in rows)
    return project(io.BytesIO(body), len(body), tmp_path / 'projected',
                   {'reported_packet_count': 4, 'runtime_started_us': 90000000,
                    'runtime_stopped_second_us': 110000000})


def test_prefix_accounts_for_both_requests_and_responses(tmp_path):
    result = project_rows(tmp_path, events())
    assert result['dns_udp_transactions'] == 3 and result['queries'] == 2 and result['answers'] == 1
    rows = list(map(json.loads, (tmp_path / 'projected/observations.jsonl').read_bytes().splitlines()))
    assert [row['transaction_ordinal'] for row in rows] == [1, 3]
    assert all(row['encoded_shape'] for row in rows)
    assert all('packet_ordinal' not in row and 'frame_sha256' not in row for row in rows)
    assert rows[1]['source_transaction_bound']['seen_no_later_than_us'] == 102000000
    assert all(sha(tmp_path / 'projected' / name) == pin for name, pin in result['files'].items())


def test_bound_is_first_sufficient_sample_not_later_counter_refresh():
    rows = counters()
    rows.append({**rows[-1], 'ordinal': 6, 'timestamp_us': 109000000, 'uptime': 11})
    bound = DnsTransactionFence(rows, 3, 4).bound(3, 101000000)
    assert asdict(bound)['seen_no_later_than_us'] == 102000000
    assert bound.application_receipt_time_proven is False and bound.actor_or_authority_proven is False
    assert DnsTransactionFence(rows, 3, 4).bound(3, 103000000) is None


@pytest.mark.parametrize('key', sorted(counters()[0]))
def test_all_counter_fields_mandatory(key):
    rows = counters()
    del rows[0][key]
    with pytest.raises(ValueError, match='stats_fields'):
        DnsTransactionFence(rows, 3, 4)


@pytest.mark.parametrize('value', [True, 3.0, '3', None, -1, 4])
def test_counter_is_bounded_integer_not_bool_float_string_or_missing(value):
    rows = counters()
    rows[-1]['dns_udp_transactions'] = value
    with pytest.raises(ValueError):
        DnsTransactionFence(rows, 3, 4)


@pytest.mark.parametrize('field', ['timestamp_us', 'dns_udp_transactions', 'kernel_packets', 'decoder_packets', 'uptime'])
def test_each_clock_or_counter_regression_rejected(field):
    rows = counters()
    middle = {**rows[-1], 'ordinal': 3}
    middle[field] += 1
    with pytest.raises(ValueError):
        DnsTransactionFence([rows[0], middle, rows[-1]], 3, 4)


@pytest.mark.parametrize('fault', ['loss', 'duplicate_order', 'terminal_transaction', 'terminal_kernel', 'terminal_decoder'])
def test_incomplete_or_lossy_counters_rejected(fault):
    rows = counters()
    if fault == 'loss': rows[0]['kernel_drops'] = 1
    if fault == 'duplicate_order': rows[-1]['ordinal'] = 1
    if fault == 'terminal_transaction': rows[-1]['dns_udp_transactions'] = 2
    if fault == 'terminal_kernel': rows[-1]['kernel_packets'] = 3
    if fault == 'terminal_decoder': rows[-1]['decoder_packets'] = 3
    with pytest.raises(ValueError):
        DnsTransactionFence(rows, 3, 4)


@pytest.mark.parametrize('fault', ['v1', 'multi_question', 'query_gap', 'query_only_count', 'missing_answer',
    'reversed_flow', 'flow_collision', 'event_time_regression', 'future_bound', 'missing_stats',
    'truth', 'dns_truth', 'tcp', 'float_txid', 'boolean_flow_id'])
def test_ambiguous_incomplete_or_leaking_native_sources_rejected(tmp_path, fault):
    rows = events()
    if fault == 'v1': rows[2]['dns'].pop('version')
    if fault == 'multi_question': rows.insert(2, copy.deepcopy(rows[1])); rows[-1]['stats']['app_layer']['tx']['dns_udp'] = 4
    if fault == 'query_gap': rows[3]['dns']['tx_id'] = 3
    if fault == 'query_only_count': rows[-1]['stats']['app_layer']['tx']['dns_udp'] = 2
    if fault == 'missing_answer': rows.pop(2)
    if fault == 'reversed_flow': rows[2]['src_port'], rows[2]['dest_port'] = 53, 12345
    if fault == 'flow_collision': rows[2]['src_ip'] = '192.0.2.200'
    if fault == 'event_time_regression': rows[3]['timestamp'] = '1970-01-01T00:01:39+00:00'
    if fault == 'future_bound': rows[-1]['timestamp'] = '1970-01-01T00:01:40+00:00'
    if fault == 'missing_stats': del rows[0]['stats']['capture']['kernel_drops']
    if fault == 'truth': rows[1]['label'] = 'normal'
    if fault == 'dns_truth': rows[1]['dns']['expected_alert'] = True
    if fault == 'tcp': rows[1]['proto'] = 'TCP'
    if fault == 'float_txid': rows[1]['dns']['tx_id'] = 0.0
    if fault == 'boolean_flow_id': rows[1]['flow_id'] = True
    with pytest.raises((ValueError, KeyError)):
        project_rows(tmp_path, rows)


@pytest.mark.parametrize('name', ['binary\\xff.example', '한글.example', 'a..b', 'x' * 64 + '.example', '.'])
def test_unrecoverable_native_name_shape_stays_unsupported(name):
    result = name_shape(name)
    assert result['query_shape_supported'] is False and result['encoded_shape'] is False
    assert result['qname_sha256'] == hashlib.sha256(name.encode()).hexdigest()


def test_unsupported_name_still_counts_toward_native_population(tmp_path):
    rows = events()
    rows[1]['dns']['rrname'] = 'binary\\xff.example'
    result = project_rows(tmp_path, rows)
    assert result['dns_udp_transactions'] == 3 and result['queries'] == 2
    assert result['unsupported_query_shapes'] == 1
