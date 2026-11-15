"""Bounded public evidence for local C01 failures; no raw payloads or secrets."""

import json
import math
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from http.client import HTTPException

from scripts.continuous_mtls_runtime import RuntimeFailure, command

ALERTS = {'C01SignalQueueBacklog', 'C01SignalCollectionUnavailable', 'C01ExporterDown', 'C01SignalProcessingFailed'}
QUERIES = {'up': 'up{job="zt-signals"}', 'alerts': 'ALERTS{alertname=~"C01.*"}',
           'alert_sample_timestamps': 'timestamp(ALERTS{alertname=~"C01.*"})'}


def number(value):
    if isinstance(value, bool):
        return None
    try:
        value = float(value)
    except (ValueError, TypeError, OverflowError):
        return None
    return value if math.isfinite(value) and abs(value) <= 1e12 else None


def vector(body):
    if not isinstance(body, dict) or body.get('status') != 'success':
        return {'available': False}
    data = body.get('data')
    if not isinstance(data, dict) or data.get('resultType') != 'vector' or not isinstance(data.get('result'), list):
        return {'available': False}
    rows = []
    for item in data['result'][:32]:
        if not isinstance(item, dict) or not isinstance(item.get('metric'), dict):
            continue
        sample = item.get('value')
        if not isinstance(sample, list) or len(sample) != 2:
            continue
        stamp, value = [number(v) for v in sample]
        if stamp is None or value is None:
            continue
        labels = {key: value for key, value in item['metric'].items()
                  if isinstance(value, str) and ((key == 'job' and value == 'zt-signals')
                      or (key == 'instance' and value == 'exporter:9101')
                      or (key == 'alertname' and value in ALERTS)
                      or (key == 'alertstate' and value in {'pending', 'firing'}))}
        rows.append({'labels': labels, 'timestamp': stamp, 'value': value})
    return {'available': True, 'samples': rows, 'truncated': len(data['result']) > 32}


def rules(body):
    if not isinstance(body, dict) or body.get('status') != 'success':
        return {'available': False}
    data = body.get('data')
    if not isinstance(data, dict) or not isinstance(data.get('groups'), list):
        return {'available': False}
    result = []
    for group in data['groups'][:8]:
        if not isinstance(group, dict) or not isinstance(group.get('rules'), list):
            continue
        for item in group['rules'][:32]:
            if not isinstance(item, dict) or not isinstance(item.get('name'), str) or item['name'] not in ALERTS:
                continue
            result.append({'name': item['name'],
                'state': item.get('state') if item.get('state') in ('inactive', 'pending', 'firing') else 'unknown',
                'health': item.get('health') if item.get('health') in ('ok', 'err', 'unknown') else 'unknown',
                'evaluation_error': bool(item.get('lastError')), 'evaluation_seconds': number(item.get('evaluationTime'))})
    return {'available': True, 'rules': result[:32], 'truncated': len(result) > 32}


def collect_probes(probe=None):
    """One operator process, four fixed read-only mTLS queries, public output only."""
    if os.environ.get('APP_ENVIRONMENT', 'local') not in {'local', 'test'}:
        raise ValueError('monitoring_diagnostics_local_test_only')
    if probe is None:
        from scripts.monitoring_runtime_control import probe
    requests = {key: {'query': expression} for key, expression in QUERIES.items()}
    requests['rules'] = {'path': '/api/v1/rules?type=alert'}

    def observe(item):
        key, request = item
        body = None
        try:
            response = probe({'profile': 'prometheus', **request})
            if isinstance(response, dict) and response.get('status') == 200:
                body = response.get('body')
        except (RuntimeFailure, OSError, HTTPException, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            pass
        return key, rules(body) if key == 'rules' else vector(body)

    # Each tls.request uses a fresh pinned context and bounded socket timeout.
    # The parent exec still has the original overall wall-time deadline.
    with ThreadPoolExecutor(max_workers=4) as pool:
        result = dict(pool.map(observe, requests.items()))
    return {'schema': 'public-c01-probe-batch-1', 'prometheus': result}


def public_batch(value):
    """Revalidate child output; never pass through arbitrary labels or errors."""
    result = {key: {'available': False} for key in (*QUERIES, 'rules')}
    if (not isinstance(value, dict) or value.get('schema') != 'public-c01-probe-batch-1'
            or not isinstance(value.get('prometheus'), dict)):
        return result
    for key in (*QUERIES, 'rules'):
        item = value['prometheus'].get(key)
        if not isinstance(item, dict) or item.get('available') is not True:
            continue
        if key != 'rules':
            samples = item.get('samples')
            if not isinstance(samples, list):
                continue
            rows = [{'metric': row.get('labels'), 'value': [row.get('timestamp'), row.get('value')]}
                    for row in samples[:32] if isinstance(row, dict)]
            result[key] = vector({'status': 'success', 'data': {'resultType': 'vector', 'result': rows}})
            result[key]['truncated'] = len(samples) > 32 or item.get('truncated') is True
        else:
            entries = item.get('rules')
            if not isinstance(entries, list):
                continue
            rows = [{'name': row.get('name'), 'state': row.get('state'), 'health': row.get('health'),
                     'lastError': row.get('evaluation_error') is not False,
                     'evaluationTime': row.get('evaluation_seconds')}
                    for row in entries[:32] if isinstance(row, dict)]
            result[key] = rules({'status': 'success', 'data': {'groups': [{'rules': rows}]}})
            result[key]['truncated'] = len(entries) > 32 or item.get('truncated') is True
    return result


def collect(runtime, reason, *, budget_seconds=20):
    """Collect before cleanup, under a wall-time budget; never replace the failure."""
    budget_seconds = min(20, max(1, budget_seconds))
    until = time.monotonic() + budget_seconds
    output = {'schema': 'public-c01-diagnostics-1', 'captured_at': datetime.now(UTC).isoformat(),
              'reason': reason if isinstance(reason, str) and re.fullmatch(r'[A-Za-z0-9_]{1,128}', reason) else 'monitoring_failure',
              'budget_seconds': budget_seconds, 'prometheus': {}, 'services': []}
    project = (runtime.state or {}).get('project', '')
    operator = None
    try:
        if isinstance(project, str) and re.fullmatch(r'kmtls-[a-f0-9]{12}', project):
            ids = command(['docker', 'ps', '-aq', '--filter', 'label=secops.runtime=' + project],
                          timeout=min(3, max(.1, until - time.monotonic()))).split()
            if (ids and len(ids) <= 32 and all(re.fullmatch(r'[a-f0-9]{12,64}', v) for v in ids)
                    and time.monotonic() < until):
                template = '{"id":{{json .Id}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"running":{{.State.Running}},"restarting":{{.State.Restarting}},"oom":{{.State.OOMKilled}},"exit_code":{{.State.ExitCode}},"restarts":{{.RestartCount}}}'
                raw = command(['docker', 'inspect', '--format', template, *ids], timeout=min(3, max(.1, until - time.monotonic())))
                for line in raw.splitlines()[:32]:
                    row = json.loads(line)
                    if row.get('service') not in runtime.services:
                        continue
                    if (row['service'] == 'operator' and row.get('running') is True
                            and isinstance(row.get('id'), str) and re.fullmatch(r'[a-f0-9]{64}', row['id'])):
                        operator = row['id']
                    output['services'].append({'service': row['service'],
                        **{k: row[k] for k in ('running', 'restarting', 'oom') if type(row.get(k)) is bool},
                        **{k: row[k] for k in ('exit_code', 'restarts') if type(row.get(k)) is int and 0 <= row[k] <= 1_000_000}})
    except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        output['service_probe_unavailable'] = True

    value = None
    remaining = until - time.monotonic()
    output['probe_launches'] = 0
    if remaining > 0 and operator is not None:
        output['probe_launches'] = 1
        try:
            value = json.loads(command(['docker', 'exec', operator, 'python', '-m',
                                       'scripts.monitoring_diagnostics', '--batch'], timeout=min(14, remaining)))
        except (RuntimeFailure, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
            output['batch_probe_unavailable'] = True
    output['prometheus'] = public_batch(value)
    output['budget_exhausted'] = time.monotonic() >= until
    return output


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch', action='store_true', required=True)
    parser.parse_args()
    print(json.dumps(collect_probes(), allow_nan=False))
