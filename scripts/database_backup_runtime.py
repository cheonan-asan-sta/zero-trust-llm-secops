"""Opt-in encrypted CA DB backup and isolated restore drill, never live restore."""

import argparse
import base64
import json
import secrets
import subprocess
import time
from pathlib import Path

from scripts import authority_custodian as custody
from scripts import authority_runtime_assets as authority
from scripts import persistent_authority_assets as assets
from scripts import persistent_authority_control as control
from scripts import rekey_runtime_assets as rekey
from scripts import runtime_release as release
from scripts.ca_recovery_state import save
from scripts.certificate_controller import LifecycleError
from scripts.continuous_mtls_runtime import ROOT, command
from scripts.database_backup_store import LIMIT, validate_manifest
from scripts.database_transport_runtime import (
    TransportCoordinator,
    TransportRuntime,
    management_lease,
)
from scripts.database_transport_runtime import definition as transport_definition
from scripts.monitored_mtls_runtime import INPUTS
from scripts.persistent_authority_runtime import GraphBackend

VOLUMES = ('database-backups', 'database-backup-key')
TABLES = ('public.used_ott', 'public.revoked_x509_certs', 'public.x509_certs',
          'public.x509_certs_data', 'runtime_guard.anchor')
PHASES = {'quiescing', 'stopped', 'sealed', 'verified', 'resuming', 'complete'}
RESTORE_COMMAND = ['sh', '-ec', ('initdb -D /restore/db -U postgres --auth-local=trust --auth-host=reject >/dev/null; '
                   'exec postgres -D /restore/db -k /tmp -c listen_addresses= -c shared_buffers=16MB -c max_connections=10')]


def definition(project, image, nginx):
    spec = transport_definition(project, image, nginx)
    spec['volumes'].update({n: {'external': True, 'name': project + '-' + n} for n in VOLUMES})
    return spec


def snapshot(query):
    result = {}
    for table in TABLES:
        raw = query("SELECT count(*),encode(sha256(convert_to(coalesce(string_agg(row_to_json(t)::text,E'\\n' "
                    "ORDER BY row_to_json(t)::text COLLATE \"C\"),''),'UTF8')),'hex') FROM " + table + ' t;')
        count, digest = raw.split('|')
        result[table] = {'rows': int(count), 'sha256': digest}
    return result


class BackupRuntime(TransportRuntime):
    volumes = TransportRuntime.volumes + VOLUMES

    @property
    def backup_path(self):
        return self.directory / 'database-backup-journal.json'

    def definition(self, project, image, nginx):
        return definition(project, image, nginx)

    def release_inputs(self):
        return release.capture(ROOT, definition('kmtls-000000000000', 'sha256:' + '0' * 64, 'sha256:' + '1' * 64),
                               (*INPUTS, *authority.INPUTS, rekey.INPUT, *assets.INPUTS))

    def build_material(self):
        material, provisioners = super().build_material()
        material[VOLUMES[0]] = {}
        material[VOLUMES[1]] = {'key.hex': secrets.token_hex(32)}
        return material, provisioners

    def make_profile(self):
        return super().make_profile() | {'database_backup': True}

    def preflight(self):
        return super().preflight() | {'database_backup': {'enabled': True, 'manual_trigger': True,
            'live_restore_supported': False, 'maximum_dump_bytes': LIMIT, 'maximum_archives': 16,
            'restore_network': 'none', 'online_backup_mounts': 0}}

    def backup_journal(self):
        if not self.backup_path.exists():
            if self.state.get('backup_started'):
                raise LifecycleError('backup_journal_required')
            return None
        value = json.loads(control.read(self.backup_path, 65536))
        if (not isinstance(value, dict) or set(value) != {'phase', 'manifest', 'restore_paused', 'archive', 'verified'}
                or value['phase'] not in PHASES or type(value['restore_paused']) is not bool
                or type(value['verified']) is not bool):
            raise LifecycleError('backup_journal_invalid')
        validate_manifest(value['manifest'])
        if value['manifest']['project'] != self.state['project']:
            raise LifecycleError('backup_project_changed')
        archive = value['archive']
        if archive is not None:
            import re
            if (not isinstance(archive, dict) or set(archive) != {'exists', 'archive_sha256', 'dump_sha256', 'bytes'}
                    or archive['exists'] is not True or type(archive['bytes']) is not int or not 5 <= archive['bytes'] <= LIMIT
                    or any(not isinstance(archive[k], str) or re.fullmatch('[a-f0-9]{64}', archive[k]) is None
                           for k in ('archive_sha256', 'dump_sha256'))):
                raise LifecycleError('backup_archive_invalid')
        if (value['phase'] in {'sealed', 'verified', 'resuming', 'complete'} and archive is None
                or value['phase'] in {'verified', 'resuming', 'complete'} and not value['verified']):
            raise LifecycleError('backup_journal_incomplete')
        return value

    def transport_idle(self):
        journal = self.backup_journal()
        if journal and journal['phase'] != 'complete' and not getattr(self, '_backup_active', False):
            raise LifecycleError('backup_requires_pinned_resume')
        super().transport_idle()

    def observation(self):
        result = super().observation()
        journal = self.backup_journal()
        return result | {'backup': {'phase': journal['phase'] if journal else 'absent',
            'id': journal['manifest']['id'] if journal else None,
            'isolated_restore_verified': bool(journal and journal['verified']),
            'live_restore_supported': False}}

    def before_transport_down(self, purge):
        if purge:
            journal = self.backup_journal()
            if journal:
                RestoreDrill(self, journal['manifest']).cleanup()

    def backup_store(self, operation, manifest, dump=None):
        self.verify_owned_volumes()
        argv = ['docker', 'run', '--rm', '--network', 'none', '--log-driver', 'none', '--read-only', '--user', '10001:10001',
            '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1', '--pids-limit', '32',
            '--tmpfs', '/data:rw,nosuid,nodev,size=1m,uid=10001,gid=10001',
            '--label', 'secops.runtime=' + self.state['project']]
        if operation == 'seal':
            argv += ['--name', self.state['project'] + '-backup-writer']
        argv += ['--mount', 'type=volume,src=' + self.state['volumes'][VOLUMES[0]] + ',dst=/backup' +
                 ('' if operation == 'seal' else ',readonly'), '--mount',
                 'type=volume,src=' + self.state['volumes'][VOLUMES[1]] + ',dst=/key,readonly',
                 '--entrypoint', 'python', '-i', self.state['authority_image_id'], '-m', 'scripts.database_backup_store']
        request = {'operation': operation, 'manifest': manifest}
        if dump is not None:
            request['dump'] = base64.b64encode(dump).decode()
        return json.loads(command(argv, payload=json.dumps(request), timeout=60))

    def checkpoint_security(self, manifest):
        """Optional independent recovery checkpoint, while both CA writers stop."""


class RestoreDrill:
    """Disposable tmpfs PostgreSQL: no network, secrets, host bind or live data."""

    def __init__(self, runtime, manifest):
        self.runtime, self.manifest = runtime, manifest
        self.name = runtime.state['project'] + '-backup-restore'

    def owned(self):
        found = command(['docker', 'ps', '-aq', '--filter', 'name=^/' + self.name + '$']).strip()
        if not found:
            return None
        detail = json.loads(command(['docker', 'inspect', found]))[0]
        config, host = detail['Config'], detail['HostConfig']
        if (detail['Name'] != '/' + self.name or detail['Image'] != self.runtime.state['authority_database_image_id']
                or config['Labels'].get('secops.runtime') != self.runtime.state['project']
                or config['Labels'].get('secops.backup') != self.manifest['id']
                or config['User'] != '10001:10001' or config['Entrypoint'] != RESTORE_COMMAND[:1]
                or config['Cmd'] != RESTORE_COMMAND[1:] or host['NetworkMode'] != 'none'
                or host['Privileged'] or not host['ReadonlyRootfs'] or host.get('CapAdd')
                or set(host.get('CapDrop') or []) != {'ALL'}
                or 'no-new-privileges:true' not in (host.get('SecurityOpt') or [])
                or any(m['Type'] != 'tmpfs' for m in detail['Mounts'])
                or set(host.get('Tmpfs') or {}) != {'/restore', '/tmp', '/var/lib/postgresql/data'}
                or host['Memory'] != 256 * 1024**2 or host['NanoCpus'] != 1000000000
                or host['MemorySwap'] != 256 * 1024**2 or host['LogConfig']['Type'] != 'none'
                or host['PidsLimit'] != 64 or host.get('PortBindings') or host.get('Binds')):
            raise LifecycleError('backup_restore_container_scope')
        return detail['Id']

    def cleanup(self):
        ident = self.owned()
        if ident:
            command(['docker', 'rm', '--force', ident])

    def query(self, ident, statement):
        if self.owned() != ident:
            raise LifecycleError('backup_restore_container_changed')
        return command(['docker', 'exec', ident, 'psql', '-h', '/tmp', '-U', 'postgres', '-d', 'postgres',
            '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', statement], timeout=10).strip()

    def start(self):
        self.cleanup()  # A lost response can leave only this fully scoped sandbox.
        r = self.runtime
        command(['docker', 'create', '--name', self.name, '--network', 'none', '--read-only', '--user', '10001:10001',
            '--log-driver', 'none',
            '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--memory', '256m', '--memory-swap', '256m',
            '--cpus', '1', '--pids-limit', '64', '--label', 'secops.runtime=' + r.state['project'],
            '--label', 'secops.backup=' + self.manifest['id'],
            '--tmpfs', '/restore:rw,nosuid,nodev,size=256m,uid=10001,gid=10001',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m,uid=10001,gid=10001',
            '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,nodev,size=1m,uid=10001,gid=10001',
            '--entrypoint', RESTORE_COMMAND[0], r.state['authority_database_image_id'], *RESTORE_COMMAND[1:]])
        ident = self.owned()
        try:
            command(['docker', 'start', ident])
            r.wait(lambda: self.query(ident, 'SELECT 1;') == '1', timeout=30)
        except BaseException:
            self.cleanup()
            raise
        return ident

    def verify(self, dump):
        ident = self.start()
        try:
            result = subprocess.run(['docker', 'exec', '-i', ident, 'pg_restore', '--exit-on-error', '--single-transaction',
                '--no-owner', '--no-privileges', '-h', '/tmp', '-U', 'postgres', '-d', 'postgres'],
                input=dump, capture_output=True, timeout=60, check=False)
            if result.returncode or result.stderr:
                raise LifecycleError('backup_restore_failed')
            if snapshot(lambda statement: self.query(ident, statement)) != self.manifest['security']:
                raise LifecycleError('backup_restored_security_mismatch')
            return {'verified': True, 'tables': len(TABLES), 'network': 'none', 'persistent_mounts': 0}
        finally:
            self.cleanup()


class BackupCoordinator:
    def __init__(self, runtime):
        self.runtime = runtime
        self.profile = json.loads(control.read(runtime.profile_path, 65536))
        self.backend = GraphBackend(runtime, self.profile)
        self.state = runtime.backup_journal()

    def persist(self):
        save(self.runtime.backup_path, self.state)

    def admit(self):
        r = self.runtime
        r.verify_release()
        r.verify_owned_volumes()
        if r.journal()['phase'] != 'idle' or r.transport_journal()['phase'] != 'idle':
            raise LifecycleError('backup_waits_for_idle_rotations')
        if self.profile != r.make_profile() or custody.digest(self.profile) != r.state['authority_profile_sha256']:
            raise LifecycleError('backup_pinned_profile_changed')
        if self.state and self.state['phase'] != 'complete' and self.state['manifest']['profile'] != custody.digest(self.profile):
            raise LifecycleError('backup_pending_profile_changed')
        for node in [self.profile['leaf'], self.profile['transport_database'], *self.profile['ca_replicas']]:
            self.backend.owned_container(node)
        r.verify_monitoring_configuration()
        r.verify_public_configuration()
        r.verify_authority_public_assets()

    def stopped(self):
        for node in self.profile['ca_replicas']:
            self.backend.owned_container(node)
            if json.loads(command(['docker', 'inspect', '--format', '{{json .State}}', node['id']]))['Running']:
                raise LifecycleError('backup_requires_stopped_ca')
        if self.runtime.sql("SELECT count(*) FROM pg_stat_activity WHERE usename='secops_ca';") != '0':
            raise LifecycleError('backup_requires_no_ca_sessions')

    def tick(self, *, new=False):
        r = self.runtime
        r._backup_active = True
        try:
            self.admit()
            if self.state is None or new and self.state['phase'] == 'complete':
                # Persist intent before pausing or stopping anything; capture security
                # only after all known writers stop, not at this first intent.
                self.state = {'phase': 'quiescing', 'restore_paused': r.controller_status()['paused'],
                    'manifest': {'schema': 'database-backup-1', 'id': secrets.token_hex(12), 'project': r.state['project'],
                        'profile': custody.digest(self.profile), 'created_at': int(time.time()),
                        'security': {n: {'rows': 0, 'sha256': '0' * 64} for n in TABLES}},
                    'archive': None, 'verified': False}
                if r.backup_store('capacity', self.state['manifest'])['available'] < 1:
                    raise LifecycleError('backup_retention_capacity')
                self.persist()
                r.state['backup_started'] = True
                r.save()
            s = self.state
            if s['phase'] == 'quiescing':
                self.backend.leaf('pause', value=True)
                if not self.backend.leaf('status')['paused']:
                    return
                command(['docker', 'stop', '--time', '2', *[n['id'] for n in self.profile['ca_replicas']]], timeout=30)
                self.stopped()
                s['manifest']['security'] = snapshot(r.sql)
                validate_manifest(s['manifest'])
                s['phase'] = 'stopped'
            elif s['phase'] == 'stopped':
                self.stopped()
                if snapshot(r.sql) != s['manifest']['security']:
                    raise LifecycleError('backup_live_security_changed')
                r.checkpoint_security(s['manifest'])
                result = r.backup_store('inspect', s['manifest'])
                if not result['exists']:
                    output = subprocess.run(['docker', 'exec', self.profile['transport_database']['id'], 'pg_dump',
                        '-Fc', '--no-owner', '--no-privileges', '-h', '/tmp', '-U', 'postgres', '-d', 'stepca'],
                        capture_output=True, timeout=60, check=False)
                    if output.returncode or output.stderr or not 5 <= len(output.stdout) <= LIMIT:
                        raise LifecycleError('backup_dump_failed')
                    if snapshot(r.sql) != s['manifest']['security']:
                        raise LifecycleError('backup_live_security_changed')
                    result = r.backup_store('seal', s['manifest'], output.stdout)
                s.update(archive=result, phase='sealed')
            elif s['phase'] == 'sealed':
                self.stopped()
                value = r.backup_store('read', s['manifest'])
                dump = value.pop('dump')
                if value != s['archive']:
                    raise LifecycleError('backup_archive_changed')
                RestoreDrill(r, s['manifest']).verify(base64.b64decode(dump, validate=True))
                if snapshot(r.sql) != s['manifest']['security']:
                    raise LifecycleError('backup_live_security_changed')
                s.update(verified=True, phase='verified')
            elif s['phase'] == 'verified':
                self.stopped()
                if snapshot(r.sql) != s['manifest']['security']:
                    raise LifecycleError('backup_live_security_changed')
                # Persist permission to resume before starting either original CA.
                s['phase'] = 'resuming'
            elif s['phase'] == 'resuming':
                command(['docker', 'start', *[n['id'] for n in self.profile['ca_replicas']]])
                r.wait(lambda: r.authority_health().get('healthy') is True, timeout=30)
                TransportCoordinator(r).live()
                self.backend.leaf('pause', value=s['restore_paused'])
                s['phase'] = 'complete'
            self.persist()
        finally:
            r._backup_active = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('up', 'down', 'status', 'preflight', 'backup', 'resume'))
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/database-backup')
    parser.add_argument('--purge', action='store_true')
    args = parser.parse_args()
    try:
        r = BackupRuntime(args.directory)
        if args.mode in {'up', 'down'}:
            result = r.up() if args.mode == 'up' else r.down(purge=args.purge)
        elif args.mode == 'status':
            result = r.observation()
        else:
            with management_lease(r.directory):
                r.load()
                if args.mode == 'preflight':
                    result = r.preflight()
                else:
                    worker = BackupCoordinator(r)
                    if args.mode == 'resume' and worker.state is None:
                        raise LifecycleError('backup_no_pending_operation')
                    deadline = time.monotonic() + 300
                    worker.tick(new=args.mode == 'backup')
                    while worker.state['phase'] != 'complete':
                        if time.monotonic() > deadline:
                            raise LifecycleError('backup_timeout_requires_resume')
                        worker.tick()
                    result = {'verified': True, 'backup': worker.state, 'live_restore_supported': False}
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({'verified': False, 'reason': 'database_backup_requires_pinned_resume'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
