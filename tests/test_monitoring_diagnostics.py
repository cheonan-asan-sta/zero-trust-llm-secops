import json
import subprocess
from types import SimpleNamespace

import pytest

from scripts import monitoring_diagnostics as diag
from scripts.continuous_mtls_runtime import RuntimeFailure
from scripts.test_continuous_mtls_runtime import Checks
from scripts.test_monitored_mtls_runtime import MonitoredChecks


@pytest.mark.parametrize('value', [None, True, [], {}, 'NaN', 'Inf', '-Inf', '1e1000', 1e13])
def test_nonfinite_or_unbounded_sample_is_discarded(value):
    assert diag.number(value) is None


def test_vector_redacts_untrusted_labels_and_limits_samples():
    sample = {'metric': {'job': 'zt-signals', 'instance': 'exporter:9101',
        'alertname': 'C01ExporterDown', 'alertstate': 'firing', 'token': 'secret-sentinel',
        'url': 'secret-sentinel'}, 'value': [123, '0']}
    result = diag.vector({'status': 'success', 'data': {'resultType': 'vector', 'result': [sample] * 50}})
    assert result['available'] and result['truncated'] and len(result['samples']) == 32
    assert 'secret-sentinel' not in json.dumps(result)
    assert result['samples'][0]['value'] == 0


@pytest.mark.parametrize('body', [None, [], {'status': 'success', 'data': []},
    {'status': 'success', 'data': {'resultType': 'matrix', 'result': []}}, {'error': 'secret-sentinel'}])
def test_invalid_vectors_return_only_availability(body):
    assert diag.vector(body) == {'available': False}


def test_rule_errors_are_boolean_and_unknown_labels_are_omitted():
    result = diag.rules({'status': 'success', 'data': {'groups': [{'rules': [
        {'name': 'C01ExporterDown', 'state': [], 'health': {}, 'lastError': 'secret-sentinel',
         'evaluationTime': 'NaN', 'query': 'secret-sentinel'}, {'name': 'foreign-rule'}]}]}})
    assert result['rules'] == [{'name': 'C01ExporterDown', 'state': 'unknown', 'health': 'unknown',
                              'evaluation_error': True, 'evaluation_seconds': None}]
    assert 'secret-sentinel' not in json.dumps(result)


def test_invalid_project_never_executes_docker(monkeypatch):
    def reject(*args, **kwargs):
        raise AssertionError('out-of-scope Docker call')
    monkeypatch.setattr(diag, 'command', reject)
    result = diag.collect(SimpleNamespace(state={'project': 'foreign'}, services=('operator',)), 'secret/sentinel')
    assert result['reason'] == 'monitoring_failure' and result['services'] == []
    assert not result['prometheus']['up']['available']


def test_timeout_does_not_replace_failure_or_disclose_command(monkeypatch):
    def timeout(*args, **kwargs):
        assert 0 < kwargs['timeout'] <= 3
        raise subprocess.TimeoutExpired('secret-sentinel', 3)
    monkeypatch.setattr(diag, 'command', timeout)
    result = diag.collect(SimpleNamespace(state={'project': 'kmtls-012345abcdef'}, services=('operator',)), 'query_failed')
    assert result['service_probe_unavailable']
    assert 'secret-sentinel' not in json.dumps(result)


def test_scoped_inspection_and_queries_do_not_export_docker_or_api_secrets(monkeypatch):
    calls = []
    ident = 'a' * 64
    def command(argv, **kwargs):
        calls.append(argv)
        assert kwargs['timeout'] <= 4
        if argv[1] == 'ps':
            assert argv[-1] == 'label=secops.runtime=kmtls-012345abcdef'
            return ident
        if argv[1] == 'inspect':
            return json.dumps({'id': ident, 'service': 'operator', 'running': True, 'restarting': False,
                               'oom': False, 'exit_code': 0, 'restarts': 2, 'raw': 'secret-sentinel'})
        assert argv[:4] == ['docker', 'exec', '-i', ident]
        assert json.loads(kwargs['payload'])['profile'] == 'prometheus'
        return json.dumps({'status': 200, 'body': {'status': 'success',
            'data': {'resultType': 'vector', 'result': [], 'groups': []}, 'token': 'secret-sentinel'}})
    monkeypatch.setattr(diag, 'command', command)
    result = diag.collect(SimpleNamespace(state={'project': 'kmtls-012345abcdef'}, services=('operator',)), 'query_failed')
    assert len(calls) == 5 and result['prometheus']['up']['available']
    assert 'secret-sentinel' not in json.dumps(result) and ident not in json.dumps(result)


def test_wait_keeps_original_failure_if_diagnostics_time_out(tmp_path, monkeypatch):
    from scripts import continuous_mtls_runtime as base
    monkeypatch.setattr(base, 'ROOT', tmp_path)
    checks = MonitoredChecks(tmp_path / 'runtime/c02/validation')
    def fail(*args, **kwargs):
        raise RuntimeFailure('original_failure')
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired('secret-sentinel', 1)
    monkeypatch.setattr(Checks, 'wait', fail)
    monkeypatch.setattr(diag, 'collect', timeout)
    with pytest.raises(RuntimeFailure, match='^original_failure$'):
        checks.wait(lambda: False, 'original_failure')
    assert checks.report['monitoring_failure_diagnostics'] == {'available': False}
