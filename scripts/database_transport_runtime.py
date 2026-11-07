"""Optional timed DB root/server/client key rotation with pinned maintenance resume."""

import argparse
import json
import subprocess
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

from scripts import authority_custodian as custody
from scripts import authority_runtime_assets as authority
from scripts import database_transport_custodian as transport
from scripts import persistent_authority_assets as assets
from scripts import persistent_authority_control as control
from scripts import rekey_runtime_assets as rekey
from scripts import runtime_release as release
from scripts.authority_rotation_coordinator import Coordinator, lease
from scripts.certificate_controller import LifecycleError, save
from scripts.continuous_mtls_runtime import ROOT, RuntimeFailure, command
from scripts.monitored_mtls_runtime import INPUTS
from scripts.persistent_authority_runtime import GraphBackend, PersistentAuthorityRuntime
from scripts.persistent_authority_runtime import definition as parent_definition

VAULT = 'database-transport-vault'


@contextmanager
def management_lease(directory):
    """All supported management writers share the scheduler's OS lock."""
    directory.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        try:
            stack.enter_context(lease(directory))
        except OSError:
            raise RuntimeFailure('database_transport_management_busy') from None
        yield


def definition(project, image, nginx):
    spec = parent_definition(project, image, nginx)
    spec['volumes'][VAULT] = {'external': True, 'name': project + '-' + VAULT}
    return spec


class TransportRuntime(PersistentAuthorityRuntime):
    volumes = PersistentAuthorityRuntime.volumes + (VAULT,)

    def write_manifest(self):
        if not getattr(self, '_transport_observing', False):
            super().write_manifest()

    def observation(self):
        # load normally regenerates Compose inputs. A public observation must
        # not race the scheduler or rewrite files while its lease is held.
        self._transport_observing = True
        try:
            self.load()
            s = self.transport_journal()
            return {'phase': s['phase'], 'epoch': s['epoch'],
                'last_error': 'pinned_resume_required' if s.get('last_error') else None,
                'recovery_required': s['phase'] != 'idle',
                'pending_plan_sha256': custody.digest(s['plan']) if s['plan'] else None,
                'remaining_history_slots': 64 - len(s['history']),
                'observation_only': True}
        finally:
            self._transport_observing = False

    def up(self):
        with management_lease(self.directory):
            return super().up()

    def definition(self, project, image, nginx):
        return definition(project, image, nginx)

    def release_inputs(self):
        return release.capture(ROOT, definition('kmtls-000000000000', 'sha256:' + '0' * 64, 'sha256:' + '1' * 64),
                               (*INPUTS, *authority.INPUTS, rekey.INPUT, *assets.INPUTS))

    @property
    def transport_path(self):
        return self.directory / 'database-transport-journal.json'

    def build_material(self):
        material, provisioners = super().build_material()
        files, vault, anchor = transport.seed()
        for volume in files:
            material[volume].update(files[volume])
        material[VAULT] = vault
        self.state['transport_anchor'] = anchor
        self.save()
        return material, provisioners

    def transport_journal(self):
        value = json.loads(control.read(self.transport_path)) if self.transport_path.exists() else transport.initial(self.state['transport_anchor'])
        transport.checked(self.state['transport_anchor'], value)
        return value

    def transport_idle(self):
        if self.transport_journal()['phase'] != 'idle' and not getattr(self, '_transport_active', False):
            raise RuntimeFailure('database_transport_requires_pinned_resume')

    def make_profile(self):
        return super().make_profile() | {'transport_lifecycle': True,
            'transport_database': {'name': self.state['project'] + '-ca-db-1', 'id': self.container('ca-db')}}

    def verify_monitoring_configuration(self):
        self.transport_idle()
        super().verify_monitoring_configuration()

    def authority_public_inventory(self):
        return {v: tuple(n for n in names if n not in transport.FILES.get(v, ()))
                for v, names in super().authority_public_inventory().items()
                if any(n not in transport.FILES.get(v, ()) for n in names)}

    def authority_public_expected(self):
        return {v: {n: self.state['authority_public_sha256'][v][n] for n in names}
                for v, names in self.authority_public_inventory().items()}

    def verify_authority_public_assets(self):
        super().verify_authority_public_assets()
        try:
            self.transport_job('verify')
        except RuntimeFailure:
            raise RuntimeFailure('database_transport_preflight_failed') from None

    def database_transport_root_hash(self):
        checked = transport.checked(self.state['transport_anchor'], self.transport_journal())
        return transport.file_hash(checked['root'])

    def preflight(self):
        return super().preflight() | {'database_transport_automation': {
            'enabled': True, 'requires_running_host_scheduler': True, 'policy': transport.POLICY,
            'epoch': self.transport_journal()['epoch']}}

    def transport_job(self, operation):
        self.verify_owned_volumes()
        if operation in {'prepare', 'install', 'commit'} and not getattr(self, '_transport_active', False):
            raise LifecycleError('transport_mutation_requires_host_coordinator')
        if operation == 'install':
            profile = json.loads(control.read(self.profile_path, 65536))
            backend = GraphBackend(self, profile)
            for node in [*profile['ca_replicas'], profile['transport_database']]:
                backend.owned_container(node)
                if json.loads(command(['docker', 'inspect', '--format', '{{json .State}}', node['id']]))['Running']:
                    raise LifecycleError('transport_mutation_requires_stopped_nodes')
        argv = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
            '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--memory', '128m', '--cpus', '1',
            '--label', 'secops.runtime=' + self.state['project']]
        readonly = operation == 'verify'
        if not readonly:
            # Docker's name reservation fences a helper that survives a lost
            # host/CLI response; never launch a second mutator alongside it.
            argv += ['--name', self.state['project'] + '-database-transport-custodian']
        for volume in transport.FILES:
            argv += ['--mount', f"type=volume,src={self.state['volumes'][volume]},dst=/transport/{volume}" + (',readonly' if readonly else '')]
        if not readonly:
            argv += ['--mount', f"type=volume,src={self.state['volumes'][VAULT]},dst=/vault"]
        result = json.loads(command([*argv, '--entrypoint', 'python', '-i', self.state['authority_image_id'],
                '-m', 'scripts.database_transport_custodian'], payload=json.dumps({'operation': operation,
                'anchor': self.state['transport_anchor'], 'journal': self.transport_journal()}), timeout=20))
        if result.get('verified') is False:
            raise RuntimeFailure('database_transport_ceremony_failed')
        return result

    def down(self, *, purge=False):
        with management_lease(self.directory):
            if self.descriptor.exists():
                self.load()
                if not purge:
                    self.transport_idle()
                self.before_transport_down(purge)
            return super().down(purge=purge)

    def before_transport_down(self, purge):
        pass


def runtime_type(directory):
    path = Path(directory) / 'authority-profile.json'
    if path.exists() and json.loads(control.read(path, 65536)).get('database_recovery_checkpoint') is True:
        from scripts.database_recovery_runtime import RecoveryRuntime
        return RecoveryRuntime
    if path.exists() and json.loads(control.read(path, 65536)).get('database_backup') is True:
        from scripts.database_backup_runtime import BackupRuntime
        return BackupRuntime
    return TransportRuntime


class TransportCoordinator:
    def __init__(self, runtime):
        self.runtime = runtime
        self.profile = json.loads(control.read(runtime.profile_path, 65536))
        self.backend = GraphBackend(runtime, self.profile)
        self.state = runtime.transport_journal()

    def persist(self):
        save(self.runtime.transport_path, self.state)

    def nodes(self):
        return [*self.profile['ca_replicas'], self.profile['transport_database']]

    def admit(self):
        r = self.runtime
        r.verify_release()
        r.verify_owned_volumes()
        if self.profile != r.make_profile() or custody.digest(self.profile) != r.state['authority_profile_sha256']:
            raise LifecycleError('transport_pinned_objects_changed')
        if r.journal()['phase'] != 'idle':
            raise LifecycleError('transport_waits_for_authority_idle')
        if self.state['phase'] != 'idle' and self.state['profile_digest'] != custody.digest(self.profile):
            raise LifecycleError('transport_pending_profile_changed')
        for node in [self.profile['leaf'], *self.nodes()]:
            self.backend.owned_container(node)
        r.verify_monitoring_configuration()
        r.verify_public_configuration()
        r.verify_authority_public_assets()

    def leaf(self, operation, **kwargs):
        return self.backend.leaf(operation, **kwargs)

    def stopped(self):
        for node in self.nodes():
            self.backend.owned_container(node)
            if json.loads(command(['docker', 'inspect', '--format', '{{json .State}}', node['id']]))['Running']:
                raise LifecycleError('transport_mutation_requires_stopped_nodes')

    def live(self):
        r = self.runtime
        result = r.transport_job('verify')
        if not result['transport'] or not result['transport']['verified']:
            raise LifecycleError('transport_candidate_not_ready')
        expected = r.state['authority_database_anchor']['identifier'] + '|t'
        if r.sql('SELECT identifier,enrollment_complete FROM runtime_guard.anchor WHERE singleton=1;') != expected:
            raise LifecycleError('transport_database_anchor_changed')
        for service in ('ca', 'ca-secondary'):
            result = json.loads(r.execute(service, ['python', '-m', 'scripts.persistent_authority_control', 'health'], timeout=5))
            if not result.get('healthy'):
                raise LifecycleError('transport_ca_not_ready')
            result = json.loads(r.execute(service, ['python', '-c',
                "import json;from scripts.authority_database_guard import verify;print(json.dumps(verify()))"], timeout=8))
            if not result.get('verified') or not result.get('enrolled'):
                raise LifecycleError('transport_live_database_identity_failed')
        return {'verified': True, 'ca_nodes': 2, 'database_anchor': True, 'enrollment_and_security_tables': True}

    def tick(self):
        r, s = self.runtime, self.state
        r._transport_active = True
        try:
            r.transport_idle()
            if s['phase'] == 'idle' and s.get('next_due_at', 0) > time.time():
                return
            self.admit()
            phase = s['phase']
            if phase == 'idle':
                if s.get('next_due_at', 0) > time.time():
                    return
                status = r.controller_status()
                s.update(restore_paused=status['paused'], profile_digest=custody.digest(self.profile), phase='quiescing')
                self.persist()
                self.leaf('pause', value=True)
            elif phase == 'quiescing':
                self.leaf('pause', value=True)
                if not self.leaf('status')['paused']:
                    return
                result = r.transport_job('prepare')
                if result['due']:
                    s.update(plan=result['plan'], phase='prepared')
                else:
                    s.update(phase='resuming', next_due_at=min(result['next_due_at'], time.time() + 300))
            elif phase == 'prepared':
                command(['docker', 'stop', '--time', '2', *[n['id'] for n in self.nodes()]], timeout=30)
                self.stopped()
                s['phase'] = 'stopped'
            elif phase == 'stopped':
                self.stopped()
                r.transport_job('install')
                s['phase'] = 'installed'
            elif phase == 'installed':
                # Same pinned objects only. Restart is repeated after a lost response;
                # neither a new DB nor a new candidate is created.
                command(['docker', 'start', self.profile['transport_database']['id']])
                r.wait(lambda: r.sql('SELECT 1;') == '1', timeout=30)
                command(['docker', 'start', *[n['id'] for n in self.profile['ca_replicas']]])
                r.wait(lambda: r.authority_health().get('healthy') is True, timeout=30)
                s['phase'] = 'started'
            elif phase == 'started':
                s['live_evidence'] = self.live()
                s['phase'] = 'committing'
            elif phase == 'committing':
                self.live()
                result = r.transport_job('commit')
                if not result.get('committed') or result['sealed_bundles'] != 1:
                    raise LifecycleError('transport_old_secrets_not_retired')
                s['history'].append(s['plan'])
                s.update(epoch=s['plan']['epoch'], manifest=custody.digest(s['plan']), plan=None, phase='resuming',
                         next_due_at=time.time() + min(transport.POLICY['period_seconds'], 300))
            elif phase == 'resuming':
                self.leaf('pause', value=s['restore_paused'])
                s.update(phase='idle', profile_digest=None)
            else:
                raise LifecycleError('transport_phase')
            s['last_error'] = None
            self.persist()
        finally:
            r._transport_active = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('up', 'down', 'status', 'preflight', 'tick', 'once', 'run'))
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/database-transport')
    parser.add_argument('--purge', action='store_true')
    args = parser.parse_args()
    try:
        r = runtime_type(args.directory)(args.directory)
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
                    worker = TransportCoordinator(r)
                    authority = Coordinator(worker.profile, r.directory, worker.backend)
                    deadline = time.monotonic() + 600
                    while True:
                        try:
                            if authority.state['phase'] == 'idle':
                                worker.tick()
                            if worker.state['phase'] == 'idle':
                                authority.tick()
                        except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError):
                            worker.state['last_error'] = 'transport_or_authority_failed_requires_pinned_resume'
                            worker.persist()
                            raise
                        if args.mode == 'tick' or args.mode == 'once' and worker.state['phase'] == authority.state['phase'] == 'idle':
                            result = {'transport_epoch': worker.state['epoch'], 'authority_epoch': authority.state['epoch']}
                            break
                        if time.monotonic() > deadline:
                            raise LifecycleError('transport_timeout_requires_resume')
                        if worker.state['phase'] == authority.state['phase'] == 'idle':
                            deadline = time.monotonic() + 600
                        time.sleep(1)
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({'verified': False, 'reason': 'database_transport_runtime_failed'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
