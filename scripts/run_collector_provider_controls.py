"""Owned local process/endpoint HA, not physical host HA or attack accuracy."""

import argparse
import base64
import hashlib
import json
import os
import selectors
import shutil
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from scripts.f1_lab.collector_freshness import CollectorScope, read_capture
from scripts.f1_lab.collector_provider_ha import ProviderEndpoint, ProviderProfile
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_collector import READ_ENV
from scripts.run_systemd_caller_controls import FIXTURE, setup_broker


def run(directory):
    require(os.name == 'posix' and os.geteuid() == 0
            and Path('/proc/1/comm').read_text().strip() == 'systemd', 'provider_controls_systemd_root')
    source = Path(__file__).resolve().parents[1]
    require(str(source).startswith('/run/'), 'provider_controls_owned_snapshot')
    output = Path(directory)
    output.mkdir(parents=True, exist_ok=False)
    tag = uuid.uuid4().hex
    config = Path('/run')/('zh91-'+tag[:12])
    config.mkdir(mode=0o755)
    target_name = 'zh91t-'+tag[:12]
    target = target_name+'.service'
    collector_prefix, health_prefix, probe_name = ['zh91'+c+'-'+tag[:12] for c in ('c', 'h', 'p')]
    collector, health, probe = collector_prefix+'@'+target_name+'.service', health_prefix+'@'+target_name+'.service', probe_name+'.service'
    state_name, health_name, cache_name = ['secops-ha91'+c+'-'+tag for c in ('e', 'h', 's')]
    evidence, health_state, cache = Path('/var/lib')/state_name, Path('/var/lib')/health_name, Path('/var/cache')/cache_name
    latest = evidence/target_name/'latest.json'
    uid, gid = 1, 1  # existing daemon account, no account installation
    created, providers, checks, captures = [], {}, [], []
    report = {'schema': 'collector-provider-ha-controls-1', 'completed': False, 'cases': checks,
              'aws_calls': 0, 'paid_api_calls': 0, 'physical_host_ha_tested': False,
              'organization_identity_tested': False, 'host_wide_audit_tested': False,
              'production_installation_completed': False, 'goal_qualified': False}

    def check(name, condition=True):
        require(condition, 'provider_controls_'+name)
        checks.append(name)

    def command(*args):
        return subprocess.run(['/usr/bin/systemctl', *args], env=READ_ENV,
                              capture_output=True, timeout=25, check=False)

    def install(name, text):
        path = Path('/run/systemd/system')/name
        with path.open('x', encoding='utf8') as stream:
            stream.write(text)
        created.append(path)

    def messages(unit):
        result = subprocess.run(['/usr/bin/journalctl', '--no-pager', '-u', unit, '-n', '60', '-o', 'cat'],
            env=READ_ENV, capture_output=True, timeout=8, check=True)
        require(len(result.stdout) <= 65536, 'provider_controls_journal_bound')
        return [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith('{')]

    def start_provider(index, key):
        path = sockets[index]
        require(index not in providers and not path.exists(), 'provider_controls_new_owned_process')
        process = subprocess.Popen(['/usr/bin/setpriv', '--reuid='+str(uid), '--regid='+str(gid),
            '--clear-groups', '--bounding-set=-all', '--no-new-privs', '/usr/bin/python3',
            '-m', 'scripts.serve_collector_credential', '--socket', str(path), '--allowed-uid', str(uid),
            '--allowed-service-unit', collector, '--maximum-connections', '32', '--lifetime-seconds', '600'],
            env={**READ_ENV, 'PYTHONPATH': os.environ['PYTHONPATH'], 'PYTHONDONTWRITEBYTECODE': '1',
                 'AWS_EC2_METADATA_DISABLED': 'true'}, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        providers[index] = process
        process.stdin.write(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        process.stdin.close()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            require(bool(selector.select(timeout=10)), 'provider_controls_ready_deadline')
            ready = json.loads(process.stdout.readline(8193))
        require(ready['ready'] and ready['peer_authorization_basis'] == 'systemd_main_process'
                and ready['dumpable'] is False
                and ready['worker_security'] == {'effective_uid': uid, 'effective_capabilities': 0,
                    'bounding_capabilities': 0, 'no_new_privileges': True}, 'provider_controls_process_security')
        return ready['worker_security']

    def stop_provider(index, *, strict=True):
        process = providers.pop(index)
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        tail, errors = process.stdout.read(16385), process.stderr.read(16385)
        process.stdout.close()
        process.stderr.close()
        if strict:
            require(process.returncode == 0 and len(tail)+len(errors) <= 16384
                    and b'PRIVATE KEY' not in tail+errors, 'provider_controls_clean_process_exit')
            require(not sockets[index].exists(), 'provider_controls_socket_removed')
        if process.returncode != 0:
            return {'exit_code': process.returncode}
        return json.loads(tail) if tail.strip() else {}

    def collect(success, expected_key=None):
        before = latest.read_bytes() if latest.exists() else None
        command('reset-failed', collector)
        result = command('start', collector)
        values = [v for v in messages(collector) if 'completed' in v]
        require(values, 'provider_controls_collection_report')
        last = values[-1]
        report.setdefault('collector_attempts', []).append({'exit_code': result.returncode, 'report': last})
        require((result.returncode == 0) == success and last['completed'] is success,
                'provider_controls_collection_result')
        if success:
            payload = read_capture(latest)
            require(payload['runtime_proof']['key_id'] == expected_key
                    and last['provider_selection']['selected_key_id'] == expected_key,
                    'provider_controls_selected_key')
            require(last['collector_security']['effective_uid'] == uid
                    and last['collector_security']['effective_capabilities'] == ((1<<19)|(1<<2))
                    and last['collector_security']['bounding_capabilities'] == ((1<<19)|(1<<2))
                    and last['collector_security']['no_new_privileges'], 'provider_controls_collector_sandbox')
            captures.append({'key_id': expected_key, 'sha256': hashlib.sha256(latest.read_bytes()).hexdigest(),
                             'observed_at': payload['event']['observed_at']})
        else:
            require(latest.read_bytes() == before, 'provider_controls_failed_collection_preserves_latest')
        return last

    def health_status(expected):
        command('reset-failed', health)
        result = command('start', health)
        values = [v for v in messages(health) if 'state' in v]
        require(values and values[-1]['state'] == expected
                and (result.returncode == 0) == (expected == 'fresh'), 'provider_controls_health')
        require(values[-1]['worker_security']['effective_capabilities'] == 0,
                'provider_controls_keyless_health_caps')
        return values[-1]

    try:
        keys, registry, _, _ = setup_broker(output/'public-setup', target)
        second = Ed25519PrivateKey.generate()
        runtime = next(a for a in registry.authorities if a.kind == 'runtime')
        registry = registry.model_copy(update={'authorities': [*registry.authorities,
            runtime.model_copy(update={'key_id': 'proc-2', 'public_key': base64.urlsafe_b64encode(
                second.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip('=')})]})
        scope = CollectorScope(tenant_id='local-lab', server_id='shared-lab', unit=target,
                               source_id='local-proc', key_id='proc-1')
        sockets = []
        for name in ('p', 's'):
            parent = config/name
            parent.mkdir(mode=0o700)
            os.chown(parent, uid, gid)
            sockets.append(parent/'key.sock')
        registry_path, profile_path, environment = config/'service-registry.json', config/'providers.json', config/'collector.conf'

        def configure(value):
            registry_path.write_bytes(canonical(value.model_dump(mode='json'))+b'\n')
            registry_path.chmod(0o644)
            pin = hashlib.sha256(registry_path.read_bytes()).hexdigest()
            profile = ProviderProfile(scope=scope, registry_sha256=pin, endpoints=[
                ProviderEndpoint(key_id=key_id, socket_path=str(path), peer_uid=uid)
                for key_id, path in zip(('proc-1', 'proc-2'), sockets, strict=True)])
            profile_path.write_bytes(canonical(profile.model_dump(mode='json'))+b'\n')
            profile_path.chmod(0o644)
            environment.write_text('TENANT_ID=local-lab\nSERVER_ID=shared-lab\nRUNTIME_SOURCE_ID=local-proc\n'
                'RUNTIME_KEY_ID=proc-1\nSTANDBY_RUNTIME_KEY_ID=proc-2\nSERVICE_REGISTRY_SHA256='+pin+'\n'
                'PROVIDER_PROFILE_SHA256='+hashlib.sha256(profile_path.read_bytes()).hexdigest()+'\n'
                'PYTHONPATH='+os.environ['PYTHONPATH']+'\n', encoding='utf8')
            environment.chmod(0o644)

        configure(registry)

        def template(name):
            text = (source/'infra/systemd'/name).read_text()
            if name == 'secops-capture-health-ha@.service':
                text += '\n'+(source/'infra/systemd/secops-capture-health-ha@.service.d/collector-metrics.conf').read_text()
            for old, new in {
                'User=secops-collector': 'User=daemon', 'Group=secops-collector': 'Group=daemon',
                '/opt/secops/.venv/bin/python': '/usr/bin/python3', '/opt/secops': str(source),
                '/etc/secops/collector-ha/%i.conf': str(environment),
                '/etc/secops/collector-providers/%i.json': str(profile_path),
                '/etc/secops/service-registry.json': str(registry_path),
                '/var/lib/secops-evidence': str(evidence), 'StateDirectory=secops-evidence': 'StateDirectory='+state_name,
                '/var/lib/secops-capture-health': str(health_state), 'StateDirectory=secops-capture-health': 'StateDirectory='+health_name,
                '/var/cache/secops-capture-status': str(cache), 'CacheDirectory=secops-capture-status': 'CacheDirectory='+cache_name,
            }.items():
                text = text.replace(old, new)
            return text

        install(target, '[Service]\nType=simple\nUser=nobody\nExecStart=/usr/bin/python3 -u -c "'
                +FIXTURE.replace('time.sleep(90)', 'time.sleep(600)').replace('"', '\\"')+'"\n')
        install(collector_prefix+'@.service', template('secops-execution-collector-ha@.service'))
        install(health_prefix+'@.service', template('secops-capture-health-ha@.service'))
        # Same UID as the real collector/health, different non-delegated unit.
        probe_code = ('import socket,json;s=socket.socket(socket.AF_UNIX);s.settimeout(3);'
                      's.connect('+repr(str(sockets[0]))+');b=s.recv(33);s.close();'
                      'assert not b;print(json.dumps({"same_uid_denied":True}))')
        probe_script = config/'probe.py'
        probe_script.write_text(probe_code, encoding='utf8')
        probe_script.chmod(0o644)
        install(probe, '[Service]\nType=oneshot\nUser=daemon\nGroup=daemon\n'
                'NoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nPrivateNetwork=yes\n'
                'ExecStart=/usr/bin/python3 '+str(probe_script)+'\n')
        require(command('daemon-reload').returncode == 0 and command('start', target).returncode == 0,
                'provider_controls_start_target')
        security = [start_provider(0, keys['runtime']), start_provider(1, second)]
        check('two_fresh_runtime_provider_processes_have_zero_caps_nnp_and_no_inherited_signer_memory')
        require(command('start', probe).returncode == 0
                and any(v.get('same_uid_denied') for v in messages(probe)), 'provider_controls_same_uid_probe')
        check('same_uid_different_systemd_unit_cannot_retrieve_runtime_key')
        collect(True, 'proc-1')
        health_status('fresh')
        check('actual_primary_key_collects_and_keyless_health_accepts_fresh_signed_observation')
        stopped = stop_provider(0)
        require(stopped['delivered'] == 1 and stopped['rejected'] >= 1, 'provider_controls_primary_counts')
        collect(True, 'proc-2')
        health_status('fresh')
        standby_raw = latest.read_bytes()
        check('primary_process_and_socket_loss_fails_over_to_distinct_preapproved_runtime_key')
        stop_provider(1)
        collect(False)
        outage_start = time.monotonic()
        observed = datetime.fromisoformat(read_capture(latest)['event']['observed_at'])
        until = time.monotonic()+35
        while (datetime.now(UTC)-observed).total_seconds() <= 31:
            require(time.monotonic() < until, 'provider_controls_real_outage_deadline')
            time.sleep(0.15)
        health_status('stale')
        check('both_providers_down_preserves_last_bytes_and_real_30_second_freshness_becomes_stale')
        report['actual_outage_wait_seconds'] = round(time.monotonic()-outage_start, 3)
        start_provider(0, keys['runtime'])
        start_provider(1, second)
        collect(True, 'proc-1')
        health_status('fresh')
        check('restored_primary_produces_new_evidence_without_renewing_old_standby_observation')
        # A separate file is supplied to the same persistent monitor ledger;
        # the live latest is never replaced with replayed bytes.
        replay_root = config/'replay'
        replay_root.mkdir(mode=0o700)
        os.chown(replay_root, uid, gid)
        replay = replay_root/'old-standby.json'
        replay.write_bytes(standby_raw)
        replay.chmod(0o600)
        os.chown(replay, uid, gid)
        replay_unit = 'zh91r-'+tag[:12]+'.service'
        health_text = template('secops-capture-health-ha@.service').replace('%i.service', target).replace('%i', target_name)
        health_text = health_text.replace(str(latest), str(replay))
        install(replay_unit, health_text)
        require(command('daemon-reload').returncode == 0 and command('start', replay_unit).returncode != 0,
                'provider_controls_replay_start')
        replayed = [v for v in messages(replay_unit) if 'state' in v][-1]
        require(replayed['reason'] == 'capture_regression', 'provider_controls_replay_fence')
        check('one_persistent_monitor_rejects_old_standby_after_new_primary_without_live_latest_replacement')
        stop_provider(0)
        start_provider(0, Ed25519PrivateKey.generate())
        collect(False)
        health_status('fresh')
        check('wrong_primary_key_hard_fails_despite_available_standby_and_preserves_previous_latest')
        stop_provider(0)
        start_provider(0, keys['runtime'])
        collect(True, 'proc-1')
        check('corrected_preapproved_primary_recovers_without_changing_trust_pins')
        revoked = registry.model_copy(update={'version': registry.version+1, 'authorities': [
            a.model_copy(update={'enabled': False}) if a.key_id == 'proc-1' else a for a in registry.authorities]})
        configure(revoked)  # explicit trusted fixture admin update, never auto-repin
        collect(True, 'proc-2')
        health_status('fresh')
        check('explicit_admin_revocation_skips_primary_and_accepts_only_current_preapproved_standby')
        report.update(completed=True, captures=captures, provider_security=security,
            distinct_preapproved_runtime_keys=True, original_target_restarted=False,
            automatic_registry_pin_update=False, raw_private_keys_persisted=False,
            authority_or_grant_reissued=False, normal_collector_observation_controls=True)
    finally:
        for index in list(providers):
            stopped = stop_provider(index, strict=False)
            report.setdefault('provider_shutdowns', []).append({'provider': index, **stopped})
        for unit in (collector, health, probe, target):
            command('stop', unit)
            command('reset-failed', unit)
        for path in created:
            command('stop', path.name)
            command('reset-failed', path.name)
            path.unlink(missing_ok=True)
        command('daemon-reload')
        for path, parent, prefix in ((evidence, Path('/var/lib'), 'secops-ha91e-'),
            (health_state, Path('/var/lib'), 'secops-ha91h-'), (cache, Path('/var/cache'), 'secops-ha91s-'),
            (config, Path('/run'), 'zh91-')):
            require(path.parent == parent and path.name.startswith(prefix), 'provider_controls_cleanup_scope')
            if path.exists():
                shutil.rmtree(path)
        report['owned_units_removed'] = all(not path.exists() for path in created)
        report['owned_provider_processes_stopped'] = not providers
        report['owned_state_removed'] = not any(p.exists() for p in (config, evidence, health_state, cache))
        (output/'run.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
    print(json.dumps({'completed': True, 'cases': len(checks)}))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    args = parser.parse_args()
    run(args.directory)


if __name__ == '__main__':
    main()
