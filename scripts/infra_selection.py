"""Evidence-based local selection advice; never authorizes production deployment."""

import argparse
import hashlib
import json
import math
import re
from pathlib import Path

from scripts import runtime_release as release
from scripts.continuous_mtls_runtime import ROOT
from scripts.infra_load_probe import validate_rows
from scripts.measure_signal_infrastructure import distribution
from scripts.monitored_mtls_runtime import MonitoredRuntime


def require(value, reason):
    if not value:
        raise ValueError(reason)


def historical(root):
    contract = json.loads((root / 'infra/selection/evidence.json').read_text(encoding='utf-8'))
    require(contract.get('schema') == 'infra-selection-evidence-1' and set(contract['inputs']) == {'C01', 'C02', 'C03'},
            'selection_history_contract')
    values = {}
    for name, entry in contract['inputs'].items():
        path = root / entry['path']
        require(re.fullmatch(r'docs/infrastructure-results/[a-z0-9-]+\.json', entry['path'])
                and path.resolve().is_relative_to((root / 'docs/infrastructure-results').resolve())
                and not path.is_symlink(), 'selection_history_path')
        require(hashlib.sha256(path.read_bytes()).hexdigest() == entry['sha256'], 'selection_history_hash')
        value = json.loads(path.read_text(encoding='utf-8'))
        require(value.get('completed') is True, 'selection_history_incomplete')
        if name in {'C01', 'C02'}:
            lock = 'observability' if name == 'C01' else 'pep'
            require(value['tools'] == json.loads((root / f'infra/{lock}/tools.lock.json').read_text()),
                    'selection_history_tool_drift')
            candidates = {'prometheus', 'victoriametrics'} if name == 'C01' else {'nginx', 'envoy'}
            expected = {(c, i) for c in candidates for i in range(1, 4)}
            require(len(value['runs']) == 6 and {(r['candidate'], r['iteration']) for r in value['runs']} == expected,
                    'selection_history_repeats')
            for row in value['runs']:
                require(row['complete' if name == 'C01' else 'completed'] is True
                        and len(row['checks']) == (18 if name == 'C01' else 42)
                        and all(c['passed'] is True for c in row['checks'])
                        and len({c['label'] for c in row['checks']}) == len(row['checks'])
                        and row['resource_samples'] and not row['resource_errors'], 'selection_history_checks')
        else:
            result = value['results']
            require(value['db_files'] == value['db_files_after'] and value['db_files']
                    and result['database_files_unchanged_during_offline_scans'] is True
                    and len(result['repeat_consistency']) == 4
                    and all(v is True for v in result['repeat_consistency'].values())
                    and all(result['controls'][tool][version]['passed'] is True
                            for tool in ('grype', 'trivy') for version in ('2.31.0', '2.32.0')),
                    'selection_history_scan')
        values[name] = {'path': entry['path'], 'sha256': entry['sha256'], 'source_commit': value['source_commit'],
                        'historical_only': True}
    return values


def measurement(value):
    require(value.get('schema') == 'infrastructure-selection-verification-2' and value.get('completed') is True
            and value.get('cleanup') == {'containers': 0, 'volumes': 0, 'networks': 0}
            and value.get('image_source_verified') is True and value.get('release_image_payload_verified') is True
            and value.get('conditions') == {
                'repeats': 3, 'concurrency': [1, 4, 8], 'requests_per_wave': 16,
                'resource_scope': 'steady workloads after three valid snapshots; sampler joined before gateway stop',
                'order': 'alternate ascending/descending concurrency each repetition',
                'timing': 'HTTP inside operator includes mTLS handshake; excludes mint and Docker exec startup',
                'capacity_claim': False, 'production_approval': False, 'independent_review': False},
            'selection_measurement_incomplete')
    require(isinstance(value.get('checks'), list) and len(value['checks']) == 37
            and all(c.get('passed') is True for c in value['checks'])
            and len({c['label'] for c in value['checks']}) == 37, 'selection_measurement_checks')
    expected = {(r, c, k) for r in range(1, 4) for c in (1, 4, 8) for k in ('valid', 'shared', 'missing')}
    require(len(value['workloads']) == 27 and {
        (w['repeat'], w['concurrency'], w['kind']) for w in value['workloads']} == expected,
        'selection_workload_coverage')
    samples = {c: [] for c in (1, 4, 8)}
    requests = allowed = 0
    for wave in value['workloads']:
        require(wave.get('passed') is True, 'selection_failed_wave')
        count = {'valid': 16, 'shared': 1, 'missing': 0}[wave['kind']]
        validate_rows(wave['rows'], count, wave['delivered'])
        requests += 16
        allowed += count
        if wave['kind'] == 'shared':
            validate_rows(wave['replay']['rows'], 0, 0)
            requests += 16
        if wave['kind'] == 'valid':
            samples[wave['concurrency']].extend(r['http_ms'] for r in wave['rows'])
    require(len(value['recoveries']) == 3 and {r['repeat'] for r in value['recoveries']} == {1, 2, 3},
            'selection_recovery_coverage')
    for row in value['recoveries']:
        require(type(row['denied_status']) is int and 0 <= row['denied_status'] <= 599
                and row['denied_status'] not in range(200, 300) and row['outage_deliveries'] == 0
                and row['post_recovery_deliveries'] == 1 and row.get('gateway_ready_status') == 422,
                'selection_recovery_delivery')
        for name in ('stop_seconds', 'start_to_new_grant_delivery_seconds', 'start_to_monitoring_healthy_seconds'):
            require(type(row[name]) in {int, float} and math.isfinite(row[name]) and row[name] >= 0,
                    'selection_recovery_duration')
    services = value['services']
    require(len(services) == 14 and value['resource_samples'] and not value['resource_errors']
            and {r['service'] for r in value['resource_samples']} == set(services)
            and all(r['published_ports'] is False and r['host_binds'] is False for r in services.values()),
            'selection_resource_evidence')
    require(len(value['resource_warmup']) == 3 and {r['repeat'] for r in value['resource_warmup']} == {1, 2, 3}
            and all(r['ready'] is True and set(r['service_counts']) == set(services)
                    and all(type(n) is int and n >= 3 for n in r['service_counts'].values())
                    and isinstance(r['errors'], list) for r in value['resource_warmup']), 'selection_resource_baseline')
    require(len(value['resource_windows']) == 3 and {r['repeat'] for r in value['resource_windows']} == {1, 2, 3},
            'selection_resource_windows')
    for window in value['resource_windows']:
        window_rows = [r for r in value['resource_samples'] if r.get('window') == window['repeat']]
        require(type(window['samples']) is int and window['samples'] == len(window_rows)
                and {r['service'] for r in window_rows} == set(services), 'selection_resource_window_coverage')
    require(sum(r['samples'] for r in value['resource_windows']) == len(value['resource_samples']),
            'selection_resource_window_coverage')
    return {'requests': requests, 'allowed': allowed, 'denied': requests - allowed,
            'valid_http_ms_by_concurrency': {str(c): distribution(rows) for c, rows in samples.items()},
            'gateway_start_to_new_grant_delivery_ms': distribution([
                r['start_to_new_grant_delivery_seconds'] * 1000 for r in value['recoveries']]),
            'resource_samples': len(value['resource_samples']), 'resource_errors': 0,
            'resource_scope': value['conditions']['resource_scope'],
            'resource_warmup_errors': sum(len(r['errors']) for r in value['resource_warmup'])}


def assess(value, root=ROOT):
    summary = measurement(value)
    require(re.fullmatch(r'[a-f0-9]{40}', value['source_commit']), 'selection_source_commit')
    current = MonitoredRuntime(root / 'runtime/c02/selection-audit-only').release_inputs()
    release.verify(value['release_lock'], current)
    for field in ('source_input_sha256', 'configuration_sha256'):
        inputs = value[field]
        require(isinstance(inputs, dict) and inputs, 'selection_source_evidence')
        for name, expected in inputs.items():
            require(name in current['payload']['files'] and hashlib.sha256((root / name).read_bytes()).hexdigest() == expected,
                    'selection_source_drift')
    expected = {p.relative_to(root).as_posix() for folder in ('app', 'scripts')
                for p in (root / folder).rglob('*.py') if '__pycache__' not in p.parts}
    require(set(value['source_input_sha256']) == expected, 'selection_source_coverage')
    history = historical(root)
    return {'schema': 'infra-selection-advice-1', 'advisory_only': True, 'source_commit': value['source_commit'],
            'source_dirty': value['source_dirty'], 'release_sha256': current['sha256'],
            'historical_evidence': history, 'measurement': summary,
            'decisions': {
                'C01': {'candidate': 'Prometheus + Alertmanager', 'status': 'local_conditional',
                        'reason': 'Historical paired safety trial; two-component local stack; current locked mTLS load evidence'},
                'C02': {'candidate': 'NGINX auth_request', 'status': 'local_conditional',
                        'reason': 'Fixed GET resource; historical paired safety trial and current one-use load/fault evidence'},
                'C03': {'candidate': 'Syft/Grype and Trivy comparison retained', 'status': 'deferred',
                        'reason': 'Historical frozen DB evidence only; current image scan and independent app reachability review pending'}},
            'production_approved': False, 'week3_complete': False, 'independent_review_complete': False,
            'remaining': ['Independent teammate reproduction and app-state contract review',
                          'Current-image supply-chain rescan and residual finding disposition',
                          'Production thresholds, sustained load and RTO/RPO targets not established'],
            'limits': ['Selected current stack measured; alternative stacks have historical measurements only',
                       'Three short bounded repetitions on one shared Docker host; not a capacity/SLA proof',
                       'No policy change, no cloud/model API, no production rollout authorized']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    value = json.loads(args.report.read_text(encoding='utf-8'))
    result = assess(value)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
