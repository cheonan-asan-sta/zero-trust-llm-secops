"""Bounded public evidence for local C01 failures; no raw payloads or secrets."""

import json
import math
import re
import subprocess
import time
from datetime import UTC, datetime

from scripts.continuous_mtls_runtime import RuntimeFailure, command

ALERTS = {'C01SignalQueueBacklog', 'C01SignalCollectionUnavailable', 'C01ExporterDown', 'C01SignalProcessingFailed'}
QUERIES = {'up': 'up{job="zt-signals"}', 'alerts': 'ALERTS{alertname=~"C01.*"}'}


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

    def probe(payload):
        remaining = until - time.monotonic()
        if remaining <= 0 or operator is None:
            return None
        try:
            value = json.loads(command(['docker', 'exec', '-i', operator, 'python', '-m', 'scripts.monitoring_runtime_control', 'probe'],
                payload=json.dumps({'profile': 'prometheus', **payload}), timeout=min(4, remaining)))
            return value.get('body') if value.get('status') == 200 else None
        except (RuntimeFailure, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
            return None

    for key, expression in QUERIES.items():
        output['prometheus'][key] = vector(probe({'query': expression}))
    output['prometheus']['rules'] = rules(probe({'path': '/api/v1/rules?type=alert'}))
    output['budget_exhausted'] = time.monotonic() >= until
    return output
