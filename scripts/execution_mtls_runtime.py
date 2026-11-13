"""Opt-in continuous execution observation intake on the existing local mTLS graph.

The protected upstream directory is an adapter boundary, not an EDR or cloud sensor.
Capture signatures come from a distinct observer key outside the delivery daemon.
"""

import argparse
import copy
import hashlib
import json
import secrets
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import runtime_release as release
from scripts.continuous_mtls_assets import DEVICES, TENANT, USER
from scripts.continuous_mtls_runtime import (
    ROOT,
    SERVICES,
    VOLUMES,
    RuntimeFailure,
    command,
    compose_spec,
)
from scripts.mtls_fixtures import authority, leaf
from scripts.recoverable_mtls_runtime import RECOVERY_VOLUMES, RecoverableRuntime, recovery_spec

EXTRA_VOLUMES = ('execution-state', 'execution-input', 'execution-tls', 'execution-auth',
                 'context-tls', 'context-auth')
SCOPE = {'source': 'cloudtrail', 'user_id': USER, 'device_id': DEVICES[0],
         'resource_id': 'zt-demo-documents', 'action': 'READ', 'principal_hash': 'runtime-observed-actor'}


def definition(project, image, nginx):
    spec = compose_spec(project, image, nginx)
    service = copy.deepcopy(spec['services']['collector'])
    service.update(entrypoint=['python', '-m', 'scripts.execution_mtls_runtime', 'serve'],
                   volumes=['execution-state:/observer/state', 'execution-input:/observer/input',
                            'execution-tls:/tls:ro', 'execution-auth:/auth:ro'], networks={'core': {}},
                   logging={'driver': 'json-file', 'options': {'max-size': '2m', 'max-file': '3'}})
    spec['services']['execution-observer'] = service
    spec['volumes'].update({name: {'external': True, 'name': project + '-' + name} for name in EXTRA_VOLUMES})
    return spec


def add_material(material):
    """Independent CA for this one peer; append its trust without changing old leaves."""
    ca = authority('Execution observer local CA')
    ca_pem = ca[1].public_bytes(serialization.Encoding.PEM).decode()
    peer = leaf(ca, 'execution-observer', server=False)
    core = material['core-tls']
    core['ca.pem'] += ca_pem
    profile = json.loads(core['server.json'])
    profile['peers'][peer['fingerprint']] = 'execution-observer'
    core['server.json'] = json.dumps(profile)
    material['execution-tls'] = {
        # Server CA remains the original one. This leaf's CA is trusted by core only.
        'ca.pem': material['operator-tls']['ca.pem'], 'observer.pem': peer['cert'], 'observer.key': peer['key'],
        'core.json': json.dumps(json.loads(material['operator-tls']['core.json']) | {
            'cert': 'observer.pem', 'key': 'observer.key',
        }),
    }
    token = secrets.token_urlsafe(32)
    accounts = json.loads(material['core-auth']['accounts.json'])
    accounts['accounts'].append({'sha256': hashlib.sha256(token.encode()).hexdigest(),
                                'subject': 'runtime-execution-observer', 'tenant_id': TENANT,
                                'roles': ['analyst'], 'enabled': True})
    material['core-auth']['accounts.json'] = json.dumps(accounts)
    material['execution-auth'] = {'api-key.txt': token}
    # A nonempty volume prevents Docker copy-up from resetting its private root
    # permissions when the producer later mounts this volume at the image /data.
    material['execution-input'] = {'.observer-feed': 'immutable-execution-feed-1\n'}
    reviewer = leaf(ca, 'context-reviewer', server=False)
    profile['peers'][reviewer['fingerprint']] = 'context-reviewer'
    core['server.json'] = json.dumps(profile)
    material['context-tls'] = {
        'ca.pem': material['operator-tls']['ca.pem'], 'reviewer.pem': reviewer['cert'], 'reviewer.key': reviewer['key'],
        'core.json': json.dumps(json.loads(material['operator-tls']['core.json']) | {
            'cert': 'reviewer.pem', 'key': 'reviewer.key',
        }),
    }
    context_token = secrets.token_urlsafe(32)
    accounts['accounts'].append({'sha256': hashlib.sha256(context_token.encode()).hexdigest(),
                                'subject': 'runtime-context-reviewer', 'tenant_id': TENANT,
                                'roles': ['admin'], 'enabled': True})
    material['core-auth']['accounts.json'] = json.dumps(accounts)
    material['context-auth'] = {'api-key.txt': context_token}
    now = datetime.now(UTC)
    registry = json.loads(material['registry']['sources.json'])
    for kind in ('execution', 'behavior'):
        key = Ed25519PrivateKey.generate()
        source = {'tenant_id': TENANT, 'source_id': 'runtime-' + kind, 'enabled': True,
                  'user_ids': [USER], 'device_ids': [DEVICES[0]], 'roles': ['employee'],
                  kind + '_scopes': [SCOPE], 'keys': [{
                      'key_id': 'key-1', 'enabled': True,
                      'public_key_pem': key.public_key().public_bytes(
                          serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
                      'not_before': (now - timedelta(seconds=30)).isoformat(),
                      'not_after': (now + timedelta(days=1)).isoformat(),
                  }]}
        registry['sources'].append(source)
        private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
        if kind == 'execution':
            material['execution-state'] = {
                'private.pem': private, 'sources.json': json.dumps({'sources': [source]}),
                'config.json': json.dumps({'tenant_id': TENANT, 'source_id': 'runtime-execution', 'key_id': 'key-1'}),
            }
        else:
            material['operator-auth']['behavior-private.pem'] = private
    material['registry']['sources.json'] = json.dumps(registry)
    return material


def recoverable_definition(project, image, nginx, *, restored):
    spec = recovery_spec(project, image, nginx, restored=restored, spec=definition(project, image, nginx))
    observer = spec['services']['execution-observer']
    observer['volumes'].append('recovery-public:/admission:ro')
    observer['entrypoint'] += ['--expected-phase', 'approved' if restored else 'original']
    return spec


class ExecutionRuntime(RecoverableRuntime):
    services = (*SERVICES, 'execution-observer')
    volumes = (*VOLUMES, *EXTRA_VOLUMES, *RECOVERY_VOLUMES)

    def definition(self, project, image, nginx):
        return definition(project, image, nginx)

    def release_inputs(self):
        args = ('kmtls-000000000000', 'sha256:' + '0' * 64, 'sha256:' + '1' * 64)
        return release.capture(ROOT, {'original': recoverable_definition(*args, restored=False),
                                      'approved': recoverable_definition(*args, restored=True)})

    def active_definition(self, project, image, nginx):
        return recoverable_definition(project, image, nginx, restored='restore_id' in self.state)

    def make_assets(self):
        return add_material(super().make_assets())

    def before_start(self):
        super().before_start()
        # Volume roots inherit the image /data mode. Tighten only our owned volumes.
        for name in ('execution-state', 'execution-input'):
            command(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
                     '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--mount',
                     f"type=volume,src={self.state['volumes'][name]},dst=/data", '--entrypoint', 'python',
                     self.state['image_id'], '-c', "import os;os.chmod('/data',0o700)"])

    def _stop_writers(self):
        self.compose('stop', '--timeout', '10', 'execution-observer')
        super()._stop_writers()
        self._assert_unused('execution-state', 'execution-input')

    def observer_probe(self, request):
        return json.loads(self.execute('execution-observer',
                          ['python', '-m', 'scripts.continuous_mtls_assets', 'probe'], json.dumps(request)))

    def context_probe(self, request):
        self.verify_release()
        network = self.state['project'] + '_core'
        detail = json.loads(command(['docker', 'network', 'inspect', network]))[0]
        if detail.get('Labels', {}).get('secops.runtime') != self.state['project']:
            raise RuntimeFailure('context_reviewer_network_scope')
        return json.loads(command([
            'docker', 'run', '--rm', '--network', network, '--read-only', '--user', '10001:10001',
            '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--pids-limit', '128',
            '--memory', '192m', '--cpus', '.5', '--tmpfs', '/data:uid=10001,gid=10001,mode=0700',
            '--mount', f"type=volume,src={self.state['volumes']['context-tls']},dst=/tls,readonly",
            '--mount', f"type=volume,src={self.state['volumes']['context-auth']},dst=/auth,readonly",
            '--entrypoint', 'python', '-i', self.state['image_id'],
            '-m', 'scripts.continuous_mtls_assets', 'probe',
        ], payload=json.dumps(request)))


def serve(expected_phase):
    import os

    from scripts.behavior_execution_collector import main as collector_main
    from scripts.continuous_mtls_assets import _credential
    from scripts.mtls_app_recovery import phase
    if phase()['phase'] != expected_phase:
        raise ValueError('execution_observer_fenced')
    os.environ['AUTH_MODE'] = 'disabled'
    os.environ['EXECUTION_COLLECTOR_API_KEY'] = _credential('api-key.txt')
    collector_main(['run', '--directory', '/observer/state', '--input-directory', '/observer/input',
                    '--base-url', 'https://core:8000', '--tls-profile', '/tls/core.json', '--poll-seconds', '0.2'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('up', 'status', 'down', 'recover', 'serve'))
    parser.add_argument('--expected-phase', choices=('original', 'approved'))
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/execution-mtls')
    parser.add_argument('--purge', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.mode == 'serve':
            serve(args.expected_phase)
            return 0
        runtime = ExecutionRuntime(args.directory)
        if args.mode == 'up':
            result = runtime.up()
        elif args.mode == 'recover':
            result = runtime.recover()
        elif args.mode == 'status':
            runtime.load()
            result = runtime.status()
        else:
            result = runtime.down(purge=args.purge)
        print(json.dumps(result))
        return 0
    except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({'runtime': 'unavailable'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
