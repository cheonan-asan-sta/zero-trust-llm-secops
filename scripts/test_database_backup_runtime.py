"""One combined transport/CA acceptance plus encrypted DB backup/restore drill."""

import argparse
import base64
import copy
import json
import secrets
import subprocess
import sys
import time
from pathlib import Path

from scripts import authority_custodian as custody
from scripts.certificate_controller import LifecycleError
from scripts.continuous_mtls_runtime import ROOT, RuntimeFailure, command
from scripts.database_backup_runtime import (
    VOLUMES,
    BackupCoordinator,
    BackupRuntime,
    RestoreDrill,
    snapshot,
)
from scripts.database_transport_runtime import TransportCoordinator, management_lease
from scripts.persistent_authority_control import read
from scripts.test_database_transport_runtime import Checks as ParentChecks
from scripts.test_persistent_authority_runtime import AcceptanceRuntime
from scripts.test_transport_process_recovery import kill_worker, public_failure


class AcceptanceBackup(AcceptanceRuntime, BackupRuntime):
    pass


class Checks(ParentChecks):
    expected_volumes = 39
    backup_resume_timeout = 300
    backup_interrupt_timeout = 240

    def __init__(self, directory, *, runtime_class=AcceptanceBackup):
        super().__init__(directory, runtime_class=runtime_class)
        self.report['schema'] = 'database-backup-verification-1'

    def interrupt_backup(self):
        r, token = self.runtime, secrets.token_hex(12)
        marker = r.directory / ('backup-fault-' + token + '.json')
        child = subprocess.Popen([sys.executable, '-m', 'scripts.test_database_backup_process',
            '--directory', str(r.directory), '--token', token, '--timeout', str(self.backup_interrupt_timeout)], cwd=ROOT,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            started = time.monotonic()
            deadline = started + self.backup_interrupt_timeout
            while not marker.exists():
                if child.poll() is not None or time.monotonic() > deadline:
                    detail = {'child_exited': child.poll() is not None, 'exit_code': child.poll(),
                              'elapsed_seconds': time.monotonic() - started,
                              'budget_seconds': self.backup_interrupt_timeout}
                    failure = r.directory / ('backup-fault-failure-' + token + '.json')
                    if failure.exists():
                        value = json.loads(read(failure, 65536))
                        if value.get('token') == token:
                            detail['child_failure'] = value['failure']
                    self.report['backup_interruption_failure'] = detail
                    self.save()
                    raise RuntimeFailure('backup_child_failed_before_checkpoint')
                time.sleep(.2)
            self.require(json.loads(marker.read_bytes()) == {'token': token, 'phase': 'sealed', 'boundary': 'before'},
                         'backup_checkpoint_changed')
            kill_worker(child)
            self.require(child.returncode != 0, 'backup_child_not_killed')
        finally:
            if child.poll() is None:
                kill_worker(child)
        state = r.backup_journal()
        self.require(state['phase'] == 'stopped' and state['archive'] is None, 'backup_lost_ack_recorded')
        with management_lease(r.directory):
            worker = BackupCoordinator(r)
            worker.stopped()
            archive = r.backup_store('inspect', state['manifest'])
            self.require(archive['exists'], 'backup_publish_not_durable')
        self.report['backup_interruption'] = {'checkpoint': 'sealed', 'persisted_phase': 'stopped',
            'boundary': 'before', 'exit_nonzero': child.returncode != 0, 'lock_reacquired': True,
            'manifest_sha256': custody.digest(state['manifest']), 'archive_sha256': archive['archive_sha256']}
        self.add('backup_actual_process_kill_after_encrypted_publish_before_ack')
        return archive

    def damage_archive(self, manifest, *, restore=False):
        # Test-only reversible corruption of ciphertext in the isolated Linux volume.
        r = self.runtime
        r.verify_owned_volumes()
        program = """import json,sys
from pathlib import Path
from scripts.ca_recovery_state import atomic
v=json.load(sys.stdin);p=Path('/backup')/(v['id']+'.json');saved=p.with_suffix('.saved')
if v['restore']:
 atomic(p,saved.read_bytes());saved.unlink()
else:
 atomic(saved,p.read_bytes());e=json.loads(p.read_bytes());e['ciphertext']='AAAA';atomic(p,json.dumps(e))
"""
        command(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
            '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--tmpfs', '/data:size=1m',
            '--label', 'secops.runtime=' + r.state['project'], '--mount',
            'type=volume,src=' + r.state['volumes'][VOLUMES[0]] + ',dst=/backup', '--entrypoint', 'python', '-i',
            r.state['authority_image_id'], '-c', program], payload=json.dumps({'id': manifest['id'], 'restore': restore}))

    def drive_backup(self, *, new=False):
        r = self.runtime
        with management_lease(r.directory):
            worker = BackupCoordinator(r)
            worker.tick(new=new)
            deadline = time.monotonic() + self.backup_resume_timeout
            while worker.state['phase'] != 'complete':
                if time.monotonic() > deadline:
                    raise RuntimeFailure('backup_test_resume_timeout')
                worker.tick()
            return copy.deepcopy(worker.state)

    def run(self):
        super().run()
        self.backup_checks()

    def refresh_active_leaves(self):
        r = self.runtime
        before = self.pause()
        original = r.controller_configuration()['renew_before']
        self.configure(paused=False, renew_before={c['name']: 3599 if c['name'].startswith('renew-') else 1199
            for c in before['credentials'].values()})
        try:
            self.wait(lambda: all(c['generation'] > before['credentials'][uid]['generation']
                for uid, c in r.controller_status()['credentials'].items() if uid != self.collector),
                'backup_active_renewal_not_completed', timeout=120)
        finally:
            current = self.pause()
            self.configure(renew_before=original)
        self.require(current['credentials'][self.collector]['fingerprint'] == before['credentials'][self.collector]['fingerprint'],
                     'backup_preparation_reissued_retired_identity')
        return current

    def refresh_before_backup(self):
        r = self.runtime
        current = self.refresh_active_leaves()
        self.add('active_leaves_renew_before_backup_without_reissuing_retired_collector')
        retired_at = current['credentials'][self.collector]['not_after']
        active_at = min(c['not_after'] for uid, c in current['credentials'].items() if uid != self.collector)
        self.require(active_at > retired_at + 1, 'backup_clock_fixture_needs_distinct_lifetimes')
        original_helper = r.helper
        for label, instant, allowed in [('expired_retired_identity_without_pins_passes_integrity_only', retired_at + 1, True),
                                        ('expired_active_identity_still_refuses_admission', active_at + 1, False)]:
            def helper(program, payload=None, *, _instant=instant, **options):
                if program == ['-m', 'scripts.persistent_authority_control', 'verify']:
                    program = ['-c', '''import json,sys
from datetime import datetime,UTC
from scripts import rekey_runtime_control as rekey
from scripts.persistent_authority_control import verify
class Clock(datetime):
 @classmethod
 def now(cls,tz=None):return datetime.fromtimestamp(INSTANT,UTC)
rekey.datetime=Clock
print(json.dumps(verify(json.load(sys.stdin))))
'''.replace('INSTANT', repr(_instant))]
                return original_helper(program, payload, **options)
            r.helper = helper
            try:
                try:
                    r.verify_monitoring_configuration()
                except (RuntimeFailure, ValueError):
                    self.require(not allowed, 'backup_retired_archive_rejected')
                else:
                    self.require(allowed, 'backup_active_expiry_admitted')
            finally:
                r.helper = original_helper
            self.add(label)

    def focused(self):
        r = self.runtime
        r.up()
        self.pause()
        self.ready()
        for name, key in {'project': 'project', 'image_id': 'image_id', 'source_commit': 'source_commit', 'source_dirty': 'source_dirty',
                'source_input_sha256': 'source_sha256', 'configuration_sha256': 'configuration_sha256', 'image_source_verified': 'image_source_verified',
                'release_lock': 'release', 'release_image_payload_verified': 'release_image_payload_verified'}.items():
            self.report[name] = copy.deepcopy(r.state[key])
        current = r.controller_status()
        self.collector = next(uid for uid, c in current['credentials'].items() if c['name'] == 'collector')
        self.require(self.rpc('revoke', id=self.collector)['revoked'], 'backup_focused_revocation_failed')
        self.configure(disabled=[self.collector])
        profile = json.loads(r.execute('gateway', ['python', '-c', "from pathlib import Path;print(Path('/tls/profile.json').read_text())"]))
        self.require(profile['peers'].pop(current['credentials'][self.collector]['fingerprint']) == 'collector', 'backup_focused_pin_scope')
        r.write_volume('gateway-tls', {'profile.json': json.dumps(profile)})
        self.require(int(r.sql('SELECT count(*) FROM revoked_x509_certs;')) > 0, 'backup_focused_revocation_missing')
        self.report['schema'] = 'database-backup-focused-verification-1'
        self.backup_checks()

    def backup_checks(self):
        self.report['completed'] = False
        r = self.runtime
        self.refresh_before_backup()
        spec = r.definition(r.state['project'], 'app', 'nginx')
        self.require(not any(m.split(':')[0] in VOLUMES for service in spec['services'].values()
                             for m in service['volumes']), 'backup_key_online_mount')
        self.add('backup_ciphertext_and_key_volumes_are_separate_and_absent_from_online_services')
        before, pinned = snapshot(r.sql), r.make_profile()
        archive = self.interrupt_backup()
        for action in (r.up, r.down, lambda: TransportCoordinator(r).tick()):
            try:
                action()
            except (LifecycleError, RuntimeFailure) as error:
                self.require(str(error) == 'backup_requires_pinned_resume', 'backup_wrong_pending_denial')
            else:
                raise RuntimeFailure('backup_pending_management_admitted')
        self.require(r.observation()['backup']['phase'] == 'stopped', 'backup_status_unavailable')
        self.add('pending_backup_blocks_normal_start_stop_rotation_but_allows_observation')
        manifest = r.backup_journal()['manifest']
        self.damage_archive(manifest)
        try:
            with management_lease(r.directory):
                worker = BackupCoordinator(r)
                try:
                    worker.tick()
                except (LifecycleError, RuntimeFailure):
                    worker.stopped()
                    self.require(r.controller_status()['paused'], 'backup_corruption_resumed_issuance')
                else:
                    raise RuntimeFailure('backup_corruption_accepted')
        finally:
            self.damage_archive(manifest, restore=True)
        self.add('tampered_ciphertext_refuses_resume_and_keeps_both_ca_writers_stopped')
        first = self.drive_backup()
        self.require(first['manifest'] == manifest and first['archive'] == archive, 'backup_resume_changed_candidate')
        self.add('lost_publish_ack_reuses_same_authenticated_archive_and_manifest')
        self.require(first['verified'] and first['phase'] == 'complete', 'backup_not_verified')
        self.add('custom_dump_restores_in_network_none_tmpfs_postgres_and_matches_five_security_tables')
        self.require(snapshot(r.sql) == before, 'backup_changed_live_security_rows')
        self.add('backup_restore_drill_preserves_live_nonce_revocation_certificates_and_anchor')
        self.require(r.make_profile() == pinned and r.controller_status()['paused'], 'backup_changed_objects_or_pause')
        self.add('same_ca_db_leaf_objects_and_original_pause_restored_after_live_tls_checks')
        r.down()
        r.up()
        self.require(r.backup_journal() == first and RestoreDrill(r, first['manifest']).owned() is None,
                     'backup_restart_or_sandbox_cleanup_failed')
        self.add('normal_restart_preserves_backup_journal_and_leaves_no_restore_container')
        second = self.drive_backup(new=True)
        self.require(second['manifest']['id'] != first['manifest']['id'], 'backup_overwrote_prior_archive')
        old = r.backup_store('read', first['manifest'])
        dump = base64.b64decode(old.pop('dump'), validate=True)
        self.require(old == first['archive'] and RestoreDrill(r, first['manifest']).verify(dump)['verified'],
                     'backup_old_archive_not_independently_verifiable')
        self.add('second_backup_keeps_first_archive_independently_restorable_in_isolation')
        self.report['backups'] = [first, second]
        self.report['final_backup_preflight'] = r.preflight()
        self.report['completed'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/database-backup-acceptance')
    parser.add_argument('--backup-only', action='store_true', help='Focused backup and retired/active expiry boundary on a fresh graph')
    args = parser.parse_args()
    checks = Checks(args.directory)
    try:
        checks.focused() if args.backup_only else checks.run()
    except (RuntimeError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        checks.report.update(completed=False, failure='database_backup_acceptance_failed', failure_detail=public_failure(error))
        checks.record_authority_failure()
    finally:
        try:
            checks.cleanup()
        except (RuntimeError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
            checks.report.update(completed=False, cleanup_failed=True)
            checks.save()
    print(json.dumps({'completed': checks.report['completed'], 'checks': len(checks.report['checks'])}))
    return 0 if checks.report['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
