"""Opt-in 18-service persistent CA/JWK rotation and two-node CA graph.

The host coordinator reuses the existing signed-plan ceremony. Authority secrets
live in a network-isolated vault job; no online service has that vault/socket.
"""

import argparse
import copy
import hashlib
import json
import subprocess
import time
from pathlib import Path

from scripts import authority_custodian as custody
from scripts import authority_runtime_assets as authority
from scripts import persistent_authority_assets as assets
from scripts import persistent_authority_control as control
from scripts import rekey_runtime_assets as rekey
from scripts import runtime_release as release
from scripts.authority_rotation_coordinator import Coordinator, DockerBackend, lease
from scripts.certificate_controller import LifecycleError
from scripts.continuous_mtls_runtime import ROOT, RuntimeFailure, command
from scripts.monitored_mtls_runtime import INPUTS
from scripts.rekey_mtls_runtime import RekeyRuntime
from scripts.rekey_mtls_runtime import definition as rekey_definition


def definition(project, image, nginx):
    spec = rekey_definition(project, image, nginx)
    spec['volumes'].update({n: {'external': True, 'name': project + '-' + n} for n in assets.VOLUMES})
    spec['networks']['ca-db'] = {'internal': True, 'labels': {'secops.runtime': project}}
    primary = spec['services']['ca']
    primary.update(entrypoint=['python', '-m', 'scripts.persistent_authority_control', 'ca'],
                   volumes=['ca-state:/ca:ro', 'authority-ca-a-db:/db-tls:ro'],
                   networks={'ca': {'aliases': ['ca', 'ca-a']}, 'ca-db': {}})
    secondary = copy.deepcopy(primary)
    secondary.update(volumes=['ca-state:/ca:ro', 'authority-ca-b-db:/db-tls:ro'],
                     networks={'ca': {'aliases': ['ca-b']}, 'ca-db': {}})
    database = copy.deepcopy(primary)
    database.update(image='sha256:' + '4' * 64, entrypoint=['sh', '/pg-tls/start.sh'],
                    volumes=['authority-db-data:/pgdata', 'authority-db-tls:/pg-tls:ro'], networks={'ca-db': {'aliases': ['ca-db']}})
    database['tmpfs'] = [*database['tmpfs'], '/var/lib/postgresql/data:rw,nosuid,nodev,size=1m']
    spec['services'].update(**{'ca-secondary': secondary, 'ca-db': database})
    return spec


class PersistentAuthorityRuntime(RekeyRuntime):
    services = RekeyRuntime.services + ('ca-secondary', 'ca-db')
    volumes = RekeyRuntime.volumes + assets.VOLUMES
    seed_last_at = None  # Acceptance subclass alone accelerates the initial ceremony.

    @property
    def profile_path(self):
        return self.directory / 'authority-profile.json'

    @property
    def journal_path(self):
        return self.directory / 'authority-coordinator.json'

    def definition(self, project, image, nginx):
        return definition(project, image, nginx)

    def release_inputs(self):
        return release.capture(ROOT, definition('kmtls-000000000000', 'sha256:' + '0' * 64, 'sha256:' + '1' * 64),
                               (*INPUTS, *authority.INPUTS, rekey.INPUT, *assets.INPUTS))

    def expected_image(self, service):
        if service == 'ca-secondary':
            return self.state.get('authority_image_id', 'sha256:' + '3' * 64)
        if service == 'ca-db':
            return self.state.get('authority_database_image_id', 'sha256:' + '4' * 64)
        return super().expected_image(service)

    def prepare_extra_images(self):
        super().prepare_extra_images()
        lock = json.loads((ROOT / assets.INPUTS[0]).read_bytes())
        reference = lock['postgres']['image']
        command(['docker', 'pull', '--platform', 'linux/amd64', reference], timeout=300)
        base = json.loads(command(['docker', 'image', 'inspect', '--platform', 'linux/amd64', reference]))[0]
        # RepoDigests contains repository@digest, without the human tag even
        # when the approved pull reference is repository:tag@digest.
        repository, digest = reference.rsplit('@', 1)
        canonical_reference = repository.rsplit(':', 1)[0] + '@' + digest
        release.image_identity(base, reference=canonical_reference)
        build = self.directory / 'postgres-build'
        build.mkdir()
        (build / 'Dockerfile').write_text(f'FROM {reference}\nUSER 0\nRUN groupadd -g 10001 secops && useradd -u 10001 -g 10001 secops && mkdir /pgdata && chown 10001:10001 /pgdata\nUSER 10001:10001\n', encoding='utf-8')
        (build / '.dockerignore').write_text('*\n!Dockerfile\n', encoding='utf-8')
        tag = self.state['project'] + '-postgres'
        command(['docker', 'build', '--tag', tag, str(build)], timeout=300)
        detail = json.loads(command(['docker', 'image', 'inspect', tag]))[0]
        layers = base['RootFS']['Layers']
        if not layers or detail['RootFS']['Layers'][:len(layers)] != layers:
            raise RuntimeFailure('authority_database_base_changed')
        self.state.update(authority_database_image=tag, authority_database_reference=reference,
                          authority_database_image_id=release.image_identity(detail), authority_database_tools=lock)
        self.save()

    def build_material(self):
        policy = json.loads((ROOT / assets.INPUTS[1]).read_bytes())
        return assets.material(policy, last_at=self.seed_last_at)

    def make_assets(self):
        material = super().make_assets()
        self.state.update(authority_initial_configuration=json.loads(material['certificate-state']['config.json']),
            authority_initial_ca=json.loads(material['ca-state']['ca.json']),
            authority_initial_root=material['ca-state']['root.pem'], authority_initial_issuer=material['ca-state']['issuer.pem'],
            authority_database_anchor=json.loads(material['ca-state']['database-anchor.json']))
        # Mutable authority files are checked against signed history, never
        # accepted as new hash baselines after rotation. Other profiles keep the
        # original immutable-file validation.
        self.state['authority_public_sha256'] = {volume: {name: hashlib.sha256(material[volume][name].encode()).hexdigest()
            for name in names} for volume, names in assets.PUBLIC_FILES.items()}
        self.save()
        return material

    def helper_mounts(self):
        return [*super().helper_mounts(), 'ca-state:/ca:ro']

    def helper(self, *args, network='none', **kwargs):
        if network != 'none':
            raise RuntimeFailure('authority_verifier_requires_network_none')
        return super().helper(*args, network=network, **kwargs)

    def verify_owned_volumes(self):
        names = list(self.state['volumes'].values())
        # Inspect before any --mount; Docker must never create missing/foreign volumes.
        rows = json.loads(command(['docker', 'volume', 'inspect', *names], timeout=10))
        if (len(rows) != len(names) or {r['Name'] for r in rows} != set(names)
                or any(r.get('Labels', {}).get('secops.runtime') != self.state['project'] for r in rows)):
            raise RuntimeFailure('authority_volume_scope')

    def journal(self):
        value = json.loads(control.read(self.journal_path)) if self.journal_path.exists() else control.initial_journal(self.state['authority_initial_root'])
        control.journal(value, self.state['authority_initial_ca'], self.state['authority_initial_root'])
        return value

    def verify_monitoring_configuration(self):
        self.verify_owned_volumes()
        request = {'initial_configuration': self.state['authority_initial_configuration'],
            'initial_configuration_sha256': self.state['authority_configuration_sha256'],
            'initial_ca': self.state['authority_initial_ca'], 'initial_root': self.state['authority_initial_root'],
            'initial_issuer': self.state['authority_initial_issuer'], 'journal': self.journal(),
            'rekey': {'templates': rekey.templates(), 'profiles': self.state['rekey_profile_identities'],
                      'initialized': bool(self.state.get('authority_initialized'))}}
        result = json.loads(self.helper(['-m', 'scripts.persistent_authority_control', 'verify'], json.dumps(request), readonly=True))
        if result.get('verified') is not True:
            raise RuntimeFailure('persistent_authority_configuration_changed')

    def verify_authority_configuration(self):
        # Already checked, including signed authority changes, in the monitoring
        # preflight hook above. No config is resealed here.
        if self.journal()['phase'] != 'idle':
            raise RuntimeFailure('authority_transition_requires_pinned_resume')

    def verify_authority_public_assets(self):
        self.verify_owned_volumes()
        expected = self.state['authority_public_sha256']
        if set(expected) != set(assets.PUBLIC_FILES) or any(set(expected[v]) != set(names) for v, names in assets.PUBLIC_FILES.items()):
            raise RuntimeFailure('authority_public_inventory_changed')
        argv = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
                '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--memory', '256m', '--cpus', '1']
        for volume in assets.PUBLIC_FILES:
            argv += ['--mount', f"type=volume,src={self.state['volumes'][volume]},dst=/fixed/{volume},readonly"]
        program = '''import hashlib,json,sys
from pathlib import Path
result={}
for volume,names in json.load(sys.stdin).items():
 result[volume]={}
 for name in names:
  p=Path('/fixed')/volume/name
  if p.is_symlink() or not p.is_file():raise ValueError('public_asset_required')
  with p.open('rb') as f:body=f.read(65537)
  if not 0<len(body)<=65536:raise ValueError('public_asset_size')
  result[volume][name]=hashlib.sha256(body.replace(b'\\r\\n',b'\\n')).hexdigest()
print(json.dumps(result))'''
        actual = json.loads(command([*argv, '--entrypoint', 'python', '-i', self.state['authority_image_id'], '-c', program],
                                    payload=json.dumps(assets.PUBLIC_FILES), timeout=15))
        if actual != expected:
            raise RuntimeFailure('authority_public_configuration_drift')

    def verify_authority_database(self):
        self.verify_owned_volumes()
        if self.state.get('authority_initialized'):
            command(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
                '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--mount',
                f"type=volume,src={self.state['volumes']['authority-db-data']},dst=/pgdata,readonly",
                '--entrypoint', 'sh', self.state['authority_database_image_id'], '-c',
                'test -s /pgdata/db/PG_VERSION && test -f /pgdata/initialized && test ! -e /pgdata/initialize.once'])

    def verify_extra_images(self):
        # Fail before readonly helpers can accidentally create an absent volume.
        self.verify_owned_volumes()
        release.image_identity(json.loads(command(['docker', 'image', 'inspect', self.state['authority_database_image']]))[0],
                               self.state['authority_database_image_id'])
        if self.state['authority_database_tools'] != json.loads((ROOT / assets.INPUTS[0]).read_bytes()):
            raise RuntimeFailure('authority_database_tool_drift')
        super().verify_extra_images()

    def sql(self, statement, *, database='stepca'):
        return self.execute('ca-db', ['psql', '-h', '/tmp', '-U', 'postgres', '-d', database,
                                     '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1'], statement, timeout=10).strip()

    def before_start(self):
        if not self.state.get('authority_initialized') and not getattr(self, '_bootstrap_provisioners', None):
            raise RuntimeFailure('authority_initialization_requires_new_approved_bootstrap')
        self.compose('up', '--detach', 'ca-db')
        self.wait(lambda: self.sql('SELECT 1;', database='postgres') == '1', timeout=45)
        if not self.state.get('authority_database_initialized'):
            anchor = self.state['authority_database_anchor']['identifier']
            # Only freshly generated hex is interpolated; descriptor checks and
            # the immutable anchor file bind subsequent startup to this database.
            if len(anchor) != 48 or any(c not in '0123456789abcdef' for c in anchor):
                raise RuntimeFailure('authority_database_anchor_shape')
            self.sql('CREATE ROLE secops_ca LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;\n'
                'CREATE DATABASE stepca OWNER secops_ca;\n'
                "ALTER ROLE secops_ca SET default_transaction_isolation='serializable';\n"
                "ALTER ROLE secops_ca SET statement_timeout='3s';\nALTER ROLE secops_ca SET lock_timeout='2s';", database='postgres')
            self.sql('CREATE SCHEMA runtime_guard AUTHORIZATION postgres; REVOKE ALL ON SCHEMA runtime_guard FROM PUBLIC; '
                'CREATE TABLE runtime_guard.anchor(singleton integer PRIMARY KEY CHECK(singleton=1), identifier text NOT NULL, enrollment_complete boolean NOT NULL); '
                f"INSERT INTO runtime_guard.anchor VALUES(1,'{anchor}',false); "
                'REVOKE ALL ON runtime_guard.anchor FROM PUBLIC; GRANT USAGE ON SCHEMA runtime_guard TO secops_ca; '
                'GRANT SELECT ON runtime_guard.anchor TO secops_ca;')
            self.state['authority_database_initialized'] = True
            self.save()
        else:
            expected = self.state['authority_database_anchor']['identifier'] + '|true'
            if self.sql('SELECT identifier,enrollment_complete FROM runtime_guard.anchor WHERE singleton=1;') != expected.replace('|true', '|t'):
                raise RuntimeFailure('authority_database_state_required')
            counts = self.sql('SELECT (SELECT count(*) FROM used_ott), (SELECT count(*) FROM revoked_x509_certs), (SELECT count(*) FROM x509_certs);').split('|')
            if len(counts) != 3 or any(not n.isdigit() for n in counts) or int(counts[0]) < 39 or int(counts[2]) < 39:
                raise RuntimeFailure('authority_database_state_required')
        super().before_start()

    def after_enrollment(self):
        self.sql('UPDATE runtime_guard.anchor SET enrollment_complete=true WHERE singleton=1;')

    def authority_health(self):
        results = [json.loads(self.execute(name, ['python', '-m', 'scripts.persistent_authority_control', 'health'], timeout=5))
                   for name in ('ca', 'ca-secondary')]
        if not all(r.get('healthy') is True and type(r.get('server_time')) is int for r in results):
            return {'healthy': False}
        return {'healthy': True, 'server_time': max(r['server_time'] for r in results)}

    def make_profile(self):
        return {'schema': 'persistent-authority-profile-1', 'directory': self.directory.relative_to(ROOT).as_posix(),
            'project': self.state['project'], 'image': self.state['authority_image_id'],
            'ca': {'name': self.state['project'] + '-ca-1', 'id': self.container('ca')},
            'leaf': {'name': self.state['project'] + '-certificate-controller-1', 'id': self.container('certificate-controller')},
            'ca_replicas': [{'name': self.state['project'] + '-' + service + '-1', 'id': self.container(service), 'endpoint': endpoint}
                            for service, endpoint in [('ca', 'ca-a'), ('ca-secondary', 'ca-b')]],
            'volumes': {key: self.state['volumes'][volume] for key, volume in {
                'vault': 'authority-vault', 'ca': 'ca-state', 'leaf': 'certificate-state', 'renewal': 'renewal-tls'}.items()},
            'initial_root': self.state['authority_initial_root'], 'poll_seconds': 1, 'policy_refresh_seconds': 300,
            'transition_timeout_seconds': 600}

    def up(self):
        result = super().up()
        profile = self.make_profile()
        if self.journal()['phase'] != 'idle':
            raise RuntimeFailure('authority_transition_requires_pinned_resume')
        self.profile_path.write_text(json.dumps(profile, sort_keys=True), encoding='utf-8')
        self.state['authority_profile_sha256'] = custody.digest(profile)
        self.save()
        return result

    def down(self, *, purge=False):
        if self.descriptor.exists():
            self.load()
            if not purge and self.state.get('authority_initial_root') and self.journal()['phase'] != 'idle':
                raise RuntimeFailure('authority_transition_requires_pinned_resume')
        result = super().down(purge=purge)
        tag = self.state['project'] + '-postgres'
        if purge and command(['docker', 'image', 'ls', '--quiet', tag]).strip():
            command(['docker', 'image', 'rm', tag])
        return result


class GraphBackend(DockerBackend):
    def __init__(self, runtime, profile):
        self.runtime, self.profile, self.project = runtime, profile, runtime.state['project']
        if (profile.get('schema') != 'persistent-authority-profile-1'
                or custody.digest(profile) != runtime.state.get('authority_profile_sha256')
                or profile != json.loads(control.read(runtime.profile_path, 65536))):
            raise LifecycleError('persistent_authority_profile_changed')
        runtime.verify_release()
        if profile != runtime.make_profile():
            raise LifecycleError('persistent_authority_container_changed')

    @classmethod
    def from_profile(cls, profile):
        path = Path(profile['directory'])
        if path.is_absolute():
            raise LifecycleError('persistent_authority_directory_scope')
        runtime = PersistentAuthorityRuntime(ROOT / path)
        runtime.load()
        return cls(runtime, profile)

    def owned_container(self, expected):
        records = [self.profile['ca'], self.profile['leaf'], *self.profile['ca_replicas']]
        if expected not in records:
            raise LifecycleError('persistent_authority_container_scope')
        found = json.loads(self.command(['inspect', expected['id']]))[0]
        service = ('certificate-controller' if expected == self.profile['leaf'] else
                   'ca' if expected['name'] == self.profile['ca']['name'] else 'ca-secondary')
        spec = self.runtime.definition(self.project, 'app', 'nginx')['services'][service]
        wanted = {}
        for entry in spec['volumes']:
            volume, target, *flags = entry.split(':')
            wanted[target] = (self.runtime.state['volumes'][volume], not flags)
        actual = {m['Destination']: (m.get('Name'), m['RW']) for m in found['Mounts'] if m['Type'] == 'volume'}
        if (found['Id'] != expected['id'] or found['Name'] != '/' + expected['name'] or found['Image'] != self.profile['image']
                or found['Config']['Labels'].get('secops.runtime') != self.project
                or found['Config']['Labels'].get('com.docker.compose.service') != service
                or actual != wanted or any(m['Type'] == 'bind' for m in found['Mounts'])
                or found['HostConfig'].get('Privileged') or not found['HostConfig'].get('ReadonlyRootfs')
                or set(found['HostConfig'].get('CapDrop') or []) != {'ALL'} or found['HostConfig'].get('CapAdd')
                or 'no-new-privileges:true' not in (found['HostConfig'].get('SecurityOpt') or [])
                or set(found['NetworkSettings']['Networks']) != {self.project + '_' + name for name in spec['networks']}
                or found['Config'].get('User') != '10001:10001'):
            raise LifecycleError('persistent_authority_container_changed')
        return expected['name']

    def custodian(self, operation, payload=None):
        self.runtime.verify_owned_volumes()
        for node in [self.profile['leaf'], *self.profile['ca_replicas']]:
            self.owned_container(node)
        return super().custodian(operation, payload)

    def before_authority_tick(self):
        self.runtime.verify_monitoring_configuration()
        self.runtime.verify_authority_public_assets()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('up', 'down', 'status', 'tick', 'once', 'run'))
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/persistent-authority')
    parser.add_argument('--purge', action='store_true')
    args = parser.parse_args()
    try:
        runtime = PersistentAuthorityRuntime(args.directory)
        if args.mode == 'up':
            result = runtime.up()
        elif args.mode == 'down':
            result = runtime.down(purge=args.purge)
        else:
            runtime.load()
            if args.mode == 'status':
                state = runtime.journal()
                result = {'phase': state['phase'], 'epoch': state['epoch'], 'services': runtime.status()['services']}
            else:
                profile = json.loads(control.read(runtime.profile_path, 65536))
                backend = GraphBackend(runtime, profile)
                with lease(runtime.directory):
                    coordinator = Coordinator(profile, runtime.directory, backend)
                    deadline = time.monotonic() + profile['transition_timeout_seconds']
                    while True:
                        try:
                            coordinator.tick()
                        except (OSError, ValueError, KeyError, TypeError) as error:
                            coordinator.state['last_error'] = str(error) if isinstance(error, LifecycleError) else 'authority_operation_failed'
                            coordinator.persist()
                            if args.mode != 'run':
                                raise
                        state = coordinator.state
                        if args.mode == 'tick' or args.mode == 'once' and state['phase'] == 'idle':
                            result = {'phase': state['phase'], 'epoch': state['epoch'], 'error': state['last_error']}
                            break
                        if time.monotonic() > deadline and state['phase'] != 'idle':
                            raise RuntimeFailure('authority_transition_timeout_no_rollback')
                        if state['phase'] == 'idle':
                            deadline = time.monotonic() + profile['transition_timeout_seconds']
                        time.sleep(profile['poll_seconds'])
        print(json.dumps(result))
        return 0
    except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({'runtime': 'unavailable', 'reason': 'persistent_authority_operation_failed'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
