import copy
from datetime import UTC, datetime, timedelta

import pytest

from scripts.monitoring_readiness import inactive_rule
from scripts.test_monitored_mtls_runtime import MonitoredChecks

NOW = datetime(2026, 11, 6, 12, tzinfo=UTC)
NAME = 'C01ExporterDown'


def body():
    return {'status': 'success', 'data': {'groups': [{'name': 'c01-zero-trust-operations', 'rules': [{
        'name': NAME, 'state': 'inactive', 'health': 'ok', 'lastError': '', 'alerts': [],
        'lastEvaluation': NOW.isoformat()}]}]}}


@pytest.mark.parametrize('fault', ['pending', 'firing', 'health', 'error', 'active_alert', 'old', 'future',
    'before_barrier', 'no_timezone', 'bad_date', 'missing', 'duplicate', 'foreign_group', 'absent_alerts'])
def test_inactive_baseline_never_accepts_missing_stale_or_unhealthy_current_rule(fault):
    value = body()
    group = value['data']['groups'][0]
    rule = group['rules'][0]
    floor = NOW - timedelta(seconds=2)
    if fault in {'pending', 'firing'}:
        rule['state'] = fault
    elif fault == 'health':
        rule['health'] = 'err'
    elif fault == 'error':
        rule['lastError'] = 'private-error-sentinel'
    elif fault == 'active_alert':
        rule['alerts'] = [{'state': 'firing'}]
    elif fault == 'old':
        rule['lastEvaluation'] = (NOW - timedelta(seconds=30)).isoformat()
        floor = NOW - timedelta(minutes=1)
    elif fault == 'future':
        rule['lastEvaluation'] = (NOW + timedelta(seconds=1)).isoformat()
    elif fault == 'before_barrier':
        floor = NOW + timedelta(seconds=1)
    elif fault == 'no_timezone':
        rule['lastEvaluation'] = '2026-11-06T12:00:00'
    elif fault == 'bad_date':
        rule['lastEvaluation'] = 'invalid'
    elif fault == 'missing':
        group['rules'] = []
    elif fault == 'duplicate':
        group['rules'].append(copy.deepcopy(rule))
    elif fault == 'foreign_group':
        group['name'] = 'foreign'
    else:
        rule.pop('alerts')
    assert inactive_rule(value, NAME, floor, now=NOW) is None


@pytest.mark.parametrize('value', [None, [], {}, {'status': 'error'}, {'status': 'success', 'data': []}])
def test_malformed_rule_responses_fail_closed(value):
    assert inactive_rule(value, NAME, NOW, now=NOW) is None


def test_live_inactive_evaluation_returns_only_fixed_public_fields():
    value = body()
    value['data']['groups'][0]['rules'][0]['query'] = 'private-sentinel'
    assert inactive_rule(value, NAME, NOW, now=NOW) == {
        'alertname': NAME, 'state': 'inactive', 'health': 'ok', 'last_evaluation': NOW.isoformat()}


@pytest.mark.parametrize('fresh_scrape', [False, True])
def test_old_firing_tsdb_sample_does_not_replace_current_rule_or_fresh_scrape_gate(monkeypatch, fresh_scrape):
    checks = object.__new__(MonitoredChecks)
    checks.report = {}
    value = body()
    monkeypatch.setattr('scripts.test_monitored_mtls_runtime.inactive_rule', lambda *a: {
        'alertname': NAME, 'state': 'inactive', 'health': 'ok', 'last_evaluation': NOW.isoformat()})
    monkeypatch.setattr(checks, 'monitor', lambda *a: {'status': 200, 'body': value})

    def query(expression):
        # Simulates the prior incident: historical firing series still exists.
        if expression.startswith('ALERTS'):
            return [{'metric': {'alertname': NAME}, 'value': [0, '1']}]
        assert 'timestamp(up{' in expression
        return [{'metric': {'job': 'zt-signals', 'instance': 'exporter:9101'}, 'value': [0, '1']}] if fresh_scrape else []

    monkeypatch.setattr(checks, 'query', query)
    monkeypatch.setattr(checks, 'wait', lambda predicate, label: pytest.fail(label) if not predicate() else None)
    monkeypatch.setattr(checks, 'add', lambda *a: None)
    if fresh_scrape:
        checks.clear_baseline(NAME)
        assert checks.report['monitoring_baselines'][0]['alertname'] == NAME
    else:
        with pytest.raises(pytest.fail.Exception, match='fresh_inactive_rule'):
            checks.clear_baseline(NAME)
