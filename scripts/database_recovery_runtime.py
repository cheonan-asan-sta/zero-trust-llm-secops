"""Opt-in manual recovery checkpoint and isolated compatibility assessment."""

import argparse
import base64
import copy
import json
import secrets
import subprocess
import time
from pathlib import Path

from scripts import authority_runtime_assets as authority
from scripts import persistent_authority_assets as assets
from scripts import rekey_runtime_assets as rekey
from scripts import runtime_release as release
from scripts.certificate_controller import LifecycleError
from scripts.continuous_mtls_runtime import ROOT, command
from scripts.database_backup_runtime import BackupCoordinator, BackupRuntime, RestoreDrill
from scripts.database_backup_runtime import definition as backup_definition
from scripts.database_backup_store import validate_manifest
from scripts.database_recovery_checkpoint import ZERO, anchor
from scripts.database_transport_runtime import management_lease
from scripts.monitored_mtls_runtime import INPUTS
from scripts.persistent_authority_control import read

VOLUMES = ('database-checkpoint', 'database-checkpoint-key')


def definition(project, image, nginx):
    value = backup_definition(project, image, nginx)
    value['volumes'].update({n: {'external': True, 'name': project + '-' + n} for n in VOLUMES})
    return value


class RecoveryRuntime(BackupRuntime):
    volumes = BackupRuntime.volumes + VOLUMES

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

    def make_assets(self):
        material = super().make_assets()
        self.state['checkpoint_head'] = copy.deepcopy(ZERO)
        self.save()
        return material

    def make_profile(self):
        return super().make_profile() | {'database_recovery_checkpoint': True}

    def preflight(self):
        return super().preflight() | {'database_recovery_checkpoint': {
            'enabled': True, 'freshness': 'last_explicit_quiesced_checkpoint',
            'live_restore_supported': False, 'automatic_capture': False}}

    def checkpoint_job(self, operation, manifest):
        self.verify_owned_volumes()
        expected = anchor(self.state.get('checkpoint_head'))
        argv = ['docker', 'run', '--rm', '--network', 'none', '--log-driver', 'none', '--read-only',
                '--user', '10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
                '--memory', '128m', '--memory-swap', '128m', '--cpus', '1', '--pids-limit', '32',
                '--label', 'secops.runtime=' + self.state['project']]
        if operation == 'publish':
            argv += ['--name', self.state['project'] + '-checkpoint-writer']
        argv += ['--mount', 'type=volume,src=' + self.state['volumes'][VOLUMES[0]] + ',dst=/checkpoint' +
                 ('' if operation == 'publish' else ',readonly'), '--mount',
                 'type=volume,src=' + self.state['volumes'][VOLUMES[1]] + ',dst=/key,readonly',
                 '--entrypoint', 'python', '-i', self.state['authority_image_id'], '-m',
                 'scripts.database_recovery_checkpoint']
        return json.loads(command(argv, payload=json.dumps({'operation': operation,
                          'manifest': manifest, 'expected': expected}), timeout=30))

    def checkpoint_security(self, manifest):
        # Called with management lease, pinned stopped CAs and matching live DB.
        result = self.checkpoint_job('publish', manifest)
        self.state['checkpoint_head'] = anchor(result['head'])
        self.save()

    def assess(self, manifest):
        validate_manifest(manifest)
        if manifest['project'] != self.state['project']:
            raise LifecycleError('checkpoint_project_changed')
        self.verify_release()
        self.transport_idle()
        value = self.backup_store('read', manifest)
        if not value.get('exists'):
            raise LifecycleError('checkpoint_archive_missing')
        result = self.checkpoint_job('assess', manifest)
        RestoreDrill(self, manifest).verify(base64.b64decode(value['dump'], validate=True))
        return result | {'archive_sha256': value['archive_sha256'], 'isolated_restore_verified': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('up', 'down', 'status', 'preflight', 'backup', 'resume', 'assess'))
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/database-recovery')
    parser.add_argument('--manifest', type=Path, help='Public authenticated archive manifest, required for assess')
    parser.add_argument('--purge', action='store_true')
    args = parser.parse_args()
    try:
        r = RecoveryRuntime(args.directory)
        if args.mode in {'up', 'down'}:
            result = r.up() if args.mode == 'up' else r.down(purge=args.purge)
        elif args.mode == 'status':
            result = r.observation()
        else:
            with management_lease(r.directory):
                r.load()
                if args.mode == 'assess':
                    if args.manifest is None:
                        raise LifecycleError('checkpoint_manifest_required')
                    result = r.assess(json.loads(read(args.manifest, 65536)))
                elif args.mode == 'preflight':
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
        print(json.dumps({'verified': False, 'reason': 'database_recovery_requires_review'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
