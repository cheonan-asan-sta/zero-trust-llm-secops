"""Current locked mTLS load/fault evidence for conditional local tool selection."""

import argparse
import copy
import json
import re
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from scripts.continuous_mtls_runtime import ROOT, RuntimeFailure, command
from scripts.infra_load_probe import validate_rows
from scripts.measure_signal_infrastructure import Sampler
from scripts.monitoring_readiness import FRESH_UP
from scripts.test_monitored_mtls_runtime import MonitoredChecks


class SelectionChecks(MonitoredChecks):
    def __init__(self, directory):
        allowed = (ROOT / 'runtime/c02').resolve()
        directory = Path(directory).resolve()
        if directory == allowed or not directory.is_relative_to(allowed) or directory.exists():
            raise ValueError('selection_fresh_scoped_directory_required')
        super().__init__(directory)
        self.report.update(schema='infrastructure-selection-verification-2', workloads=[], recoveries=[],
            resource_samples=[], resource_errors=[], resource_windows=[], resource_warmup=[],
            conditions={'repeats': 3, 'concurrency': [1, 4, 8], 'requests_per_wave': 16,
                'resource_scope': 'steady workloads after three valid snapshots; sampler joined before gateway stop',
                'order': 'alternate ascending/descending concurrency each repetition',
                'timing': 'HTTP inside operator includes mTLS handshake; excludes mint and Docker exec startup',
                'capacity_claim': False, 'production_approval': False, 'independent_review': False})

    def healthy(self):
        return ('secops_signal_collection_success 1' in self.metric()
                and len(rows := self.query(FRESH_UP)) == 1 and rows[0]['value'][1] == '1')

    def workload(self, repeat, concurrency, kind):
        before = self.served()
        value = json.loads(self.runtime.execute('operator', ['python', '-m', 'scripts.infra_load_probe'],
                           json.dumps({'kind': kind, 'concurrency': concurrency}), timeout=120))
        after = self.served()
        expected = {'valid': 16, 'shared': 1, 'missing': 0}[kind]
        value.update(repeat=repeat, delivered=after - before, expected_delivered=expected,
                     resource_before=before, resource_after=after, passed=False)
        self.report['workloads'].append(value)
        self.save()  # Keep actual statuses/timings/counters even when the first assertion fails.
        # A shared wave and its replay are bracketed by one resource counter.
        timing = validate_rows(value['rows'], expected, after - before)
        if kind == 'shared':
            replay = validate_rows(value['replay']['rows'], 0, 0)
            value['replay']['timing'] = replay
        self.require(value['kind'] == kind and value['concurrency'] == concurrency, 'selection_wrong_wave')
        self.require(self.healthy(), 'selection_monitoring_not_healthy_under_load')
        value.update(passed=True, timing=timing)
        self.add(f'load_{repeat}_{concurrency}_{kind}', delivered=after - before)
        self.save()

    def recovery(self, repeat):
        pair = self.mint(f'selection-fault-{repeat}')
        before = self.served()
        gateway = self.runtime.container('gateway')
        stopped = time.monotonic()
        command(['docker', 'stop', '--time', '2', gateway])
        stop_seconds = time.monotonic() - stopped
        try:
            result = self.runtime.probe({'profile': 'frontend', 'path': '/documents', 'headers': {
                'X-Session-ID': pair[0], 'X-Grant-Token': pair[1]}})
            from scripts.pep_lab import DOCUMENT_HASH
            self.require(result['status'] not in range(200, 300) and result['body_sha256'] != DOCUMENT_HASH
                         and self.served() == before, 'selection_outage_delivered_resource')
            denial = result['status']
        finally:
            started = time.monotonic()
            command(['docker', 'start', gateway])
        self.wait(self.gateway_ready,
                  'selection_gateway_not_recovered')
        fresh = self.mint(f'selection-after-fault-{repeat}')
        self.access(fresh, True, f'gateway_recovery_{repeat}_new_grant_delivers_once')
        ready_seconds = time.monotonic() - started
        self.wait(self.healthy, 'selection_monitoring_not_recovered')
        self.report['recoveries'].append({'repeat': repeat, 'denied_status': denial,
            'gateway_ready_status': 422,
            'outage_deliveries': 0, 'post_recovery_deliveries': 1, 'stop_seconds': stop_seconds,
            'start_to_new_grant_delivery_seconds': ready_seconds,
            'start_to_monitoring_healthy_seconds': time.monotonic() - started})
        self.save()

    def gateway_ready(self):
        # A malformed inbox request has no signed event and cannot be committed.
        # It traverses collector -> gateway -> native core with the existing identities.
        program = """import json
from pathlib import Path
from scripts.mtls_transport import request
status,_=request(Path('/tls/profile.json'),'/zero-trust/signals/inbox',{},
                 {'X-API-Key':Path('/auth/api-key.txt').read_text().strip()})
print(json.dumps({'status':status}))
"""
        result = json.loads(self.runtime.execute('collector', ['python', '-c', program]))
        return result.get('status') == 422

    def prepare_resources(self, repeat, containers):
        sampler = Sampler(containers, self.path.parent / 'warmup-resources.jsonl', 1)

        def counts():
            floor = sampler.errors[-1]['at'] if sampler.errors else None
            return {name: sum(row['service'] == name and (floor is None or row['at'] > floor)
                              for row in sampler.rows) for name in self.runtime.services}

        def ready():
            return all(n >= 3 for n in counts().values())

        sampler.thread.start()
        try:
            self.runtime.wait(ready, timeout=30)
        finally:
            sampler.stop()
            self.report['resource_warmup'].append({'repeat': repeat, 'ready': ready(),
                'service_counts': counts(), 'samples': len(sampler.rows), 'errors': sampler.errors})
            self.save()
        self.require(ready(), 'selection_resource_baseline_not_ready')

    def measure_workloads(self):
        for repeat in range(1, 4):
            containers = {self.runtime.container(s): s for s in self.runtime.services}
            self.prepare_resources(repeat, containers)
            sampler = Sampler(containers, self.path.parent / 'resources.jsonl', 1)
            sampler.thread.start()
            try:
                for concurrency in ([1, 4, 8] if repeat % 2 else [8, 4, 1]):
                    for kind in ('valid', 'shared', 'missing'):
                        self.workload(repeat, concurrency, kind)
            finally:
                sampler.stop()  # Never leave a Docker stats request crossing an intentional stop/start.
                self.report['resource_samples'].extend(row | {'window': repeat} for row in sampler.rows)
                self.report['resource_errors'].extend(sampler.errors)
                self.report['resource_windows'].append({'repeat': repeat, 'samples': len(sampler.rows)})
                self.save()
            self.require(not sampler.errors and {r['service'] for r in sampler.rows} == set(self.runtime.services),
                         'selection_resource_measurement_incomplete')
            self.recovery(repeat)

    def run(self):
        runtime = self.runtime
        runtime.up()
        for name in ('project', 'image_id', 'source_commit', 'source_dirty', 'image_source_verified'):
            self.report[name] = runtime.state[name]
        self.report.update(source_input_sha256=runtime.state['source_sha256'],
                           configuration_sha256=runtime.state['configuration_sha256'])
        self.release_phase()
        self.report['release_lock'] = copy.deepcopy(runtime.state['release'])
        hardening = {}
        for service in runtime.services:
            detail = self.inspect(service)
            host = detail['HostConfig']
            self.require(detail['State']['Running'] and detail['Config']['User'] == '10001:10001' and host['ReadonlyRootfs']
                         and 'ALL' in host['CapDrop'] and 'no-new-privileges:true' in host['SecurityOpt']
                         and not host.get('PortBindings') and not any(m['Type'] == 'bind' for m in detail['Mounts']),
                         'selection_service_boundary')
            hardening[service] = {'image_id': detail['Image'], 'published_ports': False, 'host_binds': False}
        self.report['services'] = hardening
        for name in runtime.definition(runtime.state['project'], 'app', 'nginx')['networks']:
            detail = json.loads(command(['docker', 'network', 'inspect', runtime.state['project'] + '_' + name]))[0]
            self.require(detail['Internal'], 'selection_external_network')
        self.scrape = runtime.execute('exporter', ['python', '-c',
            "from pathlib import Path;print(Path('/auth/scrape.token').read_text())"]).strip()
        self.wait(self.healthy, 'selection_monitoring_not_ready')
        self.measure_workloads()
        self.report.update(completed=True, measured_at=datetime.now(UTC).isoformat())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    checks = SelectionChecks(args.directory)
    try:
        checks.run()
    except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        reason = str(exc) if isinstance(exc, RuntimeFailure) or re.fullmatch(r'selection_[a-z_]{1,96}', str(exc)) else type(exc).__name__
        checks.report.update(completed=False, failure=reason)
    finally:
        try:
            checks.cleanup()
        except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            checks.report.update(completed=False, cleanup_failed=True)
            checks.save()
    print(json.dumps({'completed': checks.report['completed'], 'checks': len(checks.report['checks'])}))
    return 0 if checks.report['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
