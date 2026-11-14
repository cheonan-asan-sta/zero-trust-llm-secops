"""Bounded one-process probes preserve failure visibility and secret redaction."""

import copy
import json
import subprocess
from http.client import HTTPException
from types import SimpleNamespace

import pytest

from scripts import monitoring_diagnostics as diag


def response():
    return {'status': 200, 'body': {'status': 'success', 'data': {'resultType': 'vector', 'result': [
        {'metric': {'job': 'zt-signals', 'alertname': 'C01ExporterDown', 'alertstate': 'firing',
                    'credential': 'secret-sentinel'}, 'value': [123, '1']}],
        'groups': [{'rules': [{'name': 'C01ExporterDown', 'state': 'firing', 'health': 'ok',
            'lastError': '', 'evaluationTime': .1, 'token': 'secret-sentinel'}]}]}}}


def test_four_fixed_read_only_queries_share_one_batch_and_redact(monkeypatch):
    monkeypatch.setenv('APP_ENVIRONMENT', 'test')
    calls = []
    def probe(value):
        calls.append(value)
        assert value['profile'] == 'prometheus' and set(value) <= {'profile', 'query', 'path'}
        return response()
    batch = diag.collect_probes(probe)
    assert len(calls) == 4
    assert {v['query'] for v in calls if 'query' in v} == set(diag.QUERIES.values())
    assert [v['path'] for v in calls if 'path' in v] == ['/api/v1/rules?type=alert']
    assert all(value['available'] for value in batch['prometheus'].values())
    assert 'secret-sentinel' not in json.dumps(batch)
    assert diag.public_batch(batch) == batch['prometheus']


@pytest.mark.parametrize('error', [OSError('secret-sentinel'), HTTPException('secret-sentinel'), ValueError('secret-sentinel')])
def test_one_failed_query_does_not_hide_other_actual_samples(monkeypatch, error):
    monkeypatch.setenv('APP_ENVIRONMENT', 'test')
    def probe(value):
        if value.get('query') == diag.QUERIES['up']:
            raise error
        return response()
    output = diag.collect_probes(probe)['prometheus']
    assert output['up'] == {'available': False}
    assert all(output[key]['available'] for key in ('alerts', 'alert_sample_timestamps', 'rules'))
    assert 'secret-sentinel' not in json.dumps(output)


def test_non_successful_http_response_is_unavailable_without_raw_body(monkeypatch):
    monkeypatch.setenv('APP_ENVIRONMENT', 'test')
    batch = diag.collect_probes(lambda _: {'status': 500, 'body': 'secret-sentinel'})
    assert all(value == {'available': False} for value in batch['prometheus'].values())
    assert 'secret-sentinel' not in json.dumps(batch)


@pytest.mark.parametrize('value', [None, [], {}, {'schema': 'wrong'},
    {'schema': 'public-c01-probe-batch-1', 'prometheus': []}])
def test_invalid_child_output_is_not_reported_as_success(value):
    assert all(row == {'available': False} for row in diag.public_batch(value).values())


def test_parent_revalidates_labels_numbers_rules_and_bounds():
    batch = {'schema': 'public-c01-probe-batch-1', 'prometheus': {
        'up': {'available': True, 'samples': [{'labels': {'job': 'zt-signals', 'token': 'secret-sentinel'},
                    'timestamp': 123, 'value': 0, 'secret': 'secret-sentinel'}]*100},
        'alerts': {'available': True, 'samples': [{'labels': {}, 'timestamp': 123, 'value': 'NaN'}]},
        'rules': {'available': True, 'rules': [{'name': 'C01ExporterDown', 'state': 'firing',
            'health': 'ok', 'evaluation_error': False, 'evaluation_seconds': .1, 'query': 'secret-sentinel'}]*100},
        'foreign': 'secret-sentinel'}}
    result = diag.public_batch(batch)
    assert len(result['up']['samples']) == len(result['rules']['rules']) == 32
    assert result['up']['truncated'] and result['rules']['truncated']
    assert result['alerts']['samples'] == []
    assert 'secret-sentinel' not in json.dumps(result)


def test_production_batch_denied_before_network(monkeypatch):
    monkeypatch.setenv('APP_ENVIRONMENT', 'production')
    calls = []
    with pytest.raises(ValueError, match='local_test_only'):
        diag.collect_probes(lambda value: calls.append(value))
    assert not calls


def test_single_exec_uses_remaining_budget_without_per_query_fallback(monkeypatch):
    clock, calls = [0.], []
    ident = 'a'*64
    monkeypatch.setattr(diag.time, 'monotonic', lambda: clock[0])
    def command(argv, **kwargs):
        calls.append(argv)
        assert kwargs['timeout'] <= 20-clock[0]
        if argv[1] == 'ps':
            clock[0] += 2
            return ident
        if argv[1] == 'inspect':
            clock[0] += 2
            return json.dumps({'id': ident, 'service': 'operator', 'running': True})
        assert argv[-2:] == ['scripts.monitoring_diagnostics', '--batch']
        assert kwargs['timeout'] == 14
        clock[0] += 14
        raise subprocess.TimeoutExpired('secret-sentinel', 14)
    monkeypatch.setattr(diag, 'command', command)
    result = diag.collect(SimpleNamespace(state={'project': 'kmtls-012345abcdef'}, services=('operator',)), 'failure')
    assert len(calls) == 3 and result['probe_launches'] == 1 and result['batch_probe_unavailable']
    assert result['services'][0]['running'] is True
    assert all(v == {'available': False} for v in result['prometheus'].values())
    assert clock[0] == 18 and not result['budget_exhausted']
    assert 'secret-sentinel' not in json.dumps(result)


def test_invalid_public_rules_do_not_passthrough_arbitrary_payload():
    value = {'schema': 'public-c01-probe-batch-1', 'prometheus': {
        'rules': {'available': True, 'rules': ['secret-sentinel', {'name': 'foreign'}]},
        'up': {'available': True, 'samples': 'secret-sentinel'}}}
    frozen = copy.deepcopy(value)
    result = diag.public_batch(value)
    assert result['rules']['rules'] == [] and not result['up']['available']
    assert value == frozen and 'secret-sentinel' not in json.dumps(result)
