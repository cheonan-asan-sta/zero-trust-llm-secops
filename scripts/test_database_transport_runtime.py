"""Combined workload CA/HA and DB transport timed rekey/resume acceptance."""

import argparse
import copy
import hashlib
import json
import secrets
import subprocess
import sys
import time
from pathlib import Path

from scripts import authority_custodian as custody
from scripts.authority_rotation_coordinator import lease
from scripts.certificate_controller import save
from scripts.continuous_mtls_runtime import ROOT, RuntimeFailure, command
from scripts.database_transport_runtime import VAULT, TransportCoordinator, TransportRuntime
from scripts.persistent_authority_control import read
from scripts.test_persistent_authority_runtime import AcceptanceRuntime
from scripts.test_persistent_authority_runtime import Checks as ParentChecks
from scripts.test_transport_process_recovery import kill_worker, public_failure


class AcceptanceTransport(AcceptanceRuntime, TransportRuntime):
    pass


SECURITY_TABLES = ('used_ott', 'revoked_x509_certs')


def security_rows(runtime):
    return {name: set(runtime.sql('SELECT md5(row_to_json(t)::text) FROM ' + name +
                                 ' t ORDER BY 1;').splitlines()) for name in SECURITY_TABLES}


def renewal_rows_preserved(before, after):
    """Controlled credential maintenance cannot lose any old security rows.

    Real rekey preparation may append consumed attempts and revoked old client
    certificates. DB rotations themselves must still preserve the entire
    post-preparation snapshot exactly; additions are allowed only in preparation.
    """
    return (set(before) == set(after) == set(SECURITY_TABLES)
            and before['used_ott'] <= after['used_ott']
            and before['revoked_x509_certs'] <= after['revoked_x509_certs'])


class Checks(ParentChecks):
    expected_volumes = 41

    def __init__(self, directory, *, runtime_class=AcceptanceTransport):
        super().__init__(directory, runtime_class=runtime_class)
        self.report['schema'] = 'database-transport-rotation-verification-1'

    def refresh_active_leaves(self, *, label='backup'):
        """Renew through the real controller before a long paused test ceremony.

        This changes test scheduling only, never certificate validity or the
        runtime's expired-active-identity rejection. Disabled clients stay retired.
        """
        r = self.runtime
        before = self.pause()
        original = r.controller_configuration()['renew_before']
        self.configure(paused=False, renew_before={
            c['name']: 3599 if c['name'].startswith('renew-') else 1199
            for c in before['credentials'].values()})
        try:
            self.wait(lambda: all(c['generation'] > before['credentials'][uid]['generation']
                for uid, c in r.controller_status()['credentials'].items() if uid != self.collector),
                label + '_active_renewal_not_completed', timeout=120)
        finally:
            current = self.pause()
            self.configure(renew_before=original)
        self.require(current['credentials'][self.collector]['fingerprint'] ==
                     before['credentials'][self.collector]['fingerprint'],
                     label + '_preparation_reissued_retired_identity')
        return current

    def force_transport_due(self):
        r = self.runtime
        journal = r.transport_journal()
        if journal['phase'] != 'idle':
            raise RuntimeFailure('transport_test_force_requires_idle')
        r.verify_owned_volumes()
        command(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
            '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--mount',
            'type=volume,src=' + r.state['volumes'][VAULT] + ',dst=/vault', '--entrypoint', 'python',
            r.state['authority_image_id'], '-c', "import json;from pathlib import Path;from scripts.certificate_controller import save;p=Path('/vault/state.json');s=json.loads(p.read_bytes());s['last_at']=0;save(p,s)"])
        # Test-only wakeup; production refresh/period/margin stay unchanged.
        journal['next_due_at'] = 0
        save(r.transport_path, journal)

    def retired_db_identity(self, *, save=False):
        r = self.runtime
        r.verify_owned_volumes()
        argv = ['docker', 'run', '--rm', '--network', 'container:' + r.container('ca-db'), '--read-only',
            '--user', '10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
            '--label', 'secops.runtime=' + r.state['project'], '--mount',
            'type=volume,src=' + r.state['volumes']['certificate-state'] + ',dst=/test-state', '--mount',
            'type=volume,src=' + r.state['volumes']['authority-ca-a-db'] + ',dst=/current,readonly',
            '--entrypoint', 'python', '-i', r.state['authority_image_id'], '-c', """import json,sys,ssl,struct
from pathlib import Path
from datetime import UTC,datetime
from cryptography import x509
from scripts.certificate_controller import atomic
from scripts.authority_database_guard import Probe
save=json.load(sys.stdin);root=Path('/test-state/old-db-client')
if save:
 root.mkdir(exist_ok=True)
 for name in ('root.pem','client.pem','client.key'):atomic(root/name,Path('/current',name).read_bytes())
# Current server trust is held constant so old-server trust cannot mask the
# rejection of the old client root. Test-only secrets stay in Linux volumes.
atomic(root/'root.pem',Path('/current/root.pem').read_bytes())
unexpired=x509.load_pem_x509_certificate((root/'client.pem').read_bytes()).not_valid_after_utc>datetime.now(UTC)
try:
 p=Probe(root);p.close();result={'accepted':True,'unexpired':unexpired}
except (OSError,ValueError,ssl.SSLError,struct.error):result={'accepted':False,'unexpired':unexpired}
print(json.dumps(result))
"""]
        return json.loads(command(argv, payload=json.dumps(save), timeout=10))

    def drive_transport(self, epoch, *, interrupt=False):
        r = self.runtime
        self.force_transport_due()
        if interrupt:
            self.process_recovery()
        worker = TransportCoordinator(r)
        deadline = time.monotonic() + 480
        with lease(r.directory):
            while time.monotonic() < deadline:
                worker.tick()
                s = worker.state
                if s['phase'] == 'idle' and s['epoch'] == epoch:
                    self.report.setdefault('transport_ceremonies', []).append(copy.deepcopy(s))
                    return s
                time.sleep(.2)
        raise RuntimeFailure('transport_acceptance_timeout')

    def process_recovery(self):
        r, candidate = self.runtime, None
        pinned = r.make_profile()
        checkpoints = [('stopped', 'stopped'), ('installed', 'stopped'),
                       ('resuming', 'committing'), ('idle', 'resuming')]
        for target, recorded_phase in checkpoints:
            token = secrets.token_hex(12)
            marker = r.directory / ('transport-fault-' + token + '.json')
            started = time.monotonic()
            child = subprocess.Popen([sys.executable, '-m', 'scripts.test_transport_process_recovery',
                '--directory', str(r.directory), '--checkpoint', target, '--token', token],
                cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 420
                while not marker.exists():
                    if child.poll() is not None or time.monotonic() > deadline:
                        detail = {'child_exited': child.poll() is not None, 'exit_code': child.poll(),
                                  'checkpoint': target, 'elapsed_seconds': time.monotonic() - started}
                        failure = r.directory / ('transport-fault-failure-' + token + '.json')
                        if failure.exists():
                            value = json.loads(read(failure, 65536))
                            if value.get('token') == token:
                                detail['child_failure'] = value['failure']
                        self.report['transport_interruption_failure'] = detail
                        self.save()
                        raise RuntimeFailure('transport_fault_child_failed_before_checkpoint')
                    time.sleep(.2)
                expected = {'token': token, 'phase': target, 'boundary': 'after' if target == 'stopped' else 'before'}
                self.require(json.loads(marker.read_bytes()) == expected and child.poll() is None,
                             'transport_fault_checkpoint_mismatch')
                if target == 'stopped':
                    self.concurrent_management_denied()
                kill_worker(child)
                self.require(child.returncode != 0, 'transport_fault_worker_not_killed')
            finally:
                if child.poll() is None:
                    kill_worker(child)
            state = r.transport_journal()
            self.require(state['phase'] == recorded_phase, 'transport_lost_response_was_acknowledged')
            plan = custody.digest(state['plan'] or state['history'][-1])
            candidate = candidate or plan
            self.require(plan == candidate and r.make_profile() == pinned,
                         'transport_process_resume_changed_candidate_or_objects')
            # A new process must be able to acquire the kernel-released lock.
            with lease(r.directory):
                resumed = TransportCoordinator(r)
                self.require(resumed.state == state, 'transport_process_resume_changed_journal')
            if target == 'stopped':
                try:
                    r.up()
                except RuntimeFailure as error:
                    self.require(str(error) == 'database_transport_requires_pinned_resume', 'transport_wrong_pending_denial')
                else:
                    raise RuntimeFailure('transport_pending_up_admitted')
                self.add('pending_transport_blocks_ordinary_start_and_new_coordinator_resumes_same_plan')
            self.report.setdefault('process_interruptions', []).append({
                'checkpoint': target, 'boundary': expected['boundary'], 'persisted_phase': recorded_phase,
                'exit_nonzero': child.returncode != 0, 'same_candidate_sha256': candidate,
                'same_pinned_objects': True, 'lock_reacquired': True,
                'seconds': round(time.monotonic() - started, 3)})
            self.save()
            self.add('actual_host_process_kill_and_resume_at_' + target)

    def concurrent_management_denied(self):
        r = self.runtime
        for operation in [r.up, r.down, lambda: r.down(purge=True)]:
            try:
                operation()
            except RuntimeFailure as error:
                self.require(str(error) == 'database_transport_management_busy', 'transport_wrong_busy_denial')
            else:
                raise RuntimeFailure('transport_concurrent_management_admitted')
        for mode in ('tick', 'once', 'run', 'preflight'):
            result = subprocess.run([sys.executable, '-m', 'scripts.database_transport_runtime', mode,
                '--directory', str(r.directory)], cwd=ROOT, capture_output=True, text=True, timeout=15, check=False)
            self.require(result.returncode == 1 and json.loads(result.stdout).get('verified') is False,
                         'transport_concurrent_cli_admitted')
        self.add('live_scheduler_lease_blocks_start_stop_purge_ticks_and_preflight')
        paths = [p for p in r.directory.iterdir() if p.is_file() and p.suffix != '.lock']
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        result = subprocess.run([sys.executable, '-m', 'scripts.database_transport_runtime', 'status',
            '--directory', str(r.directory)], cwd=ROOT, capture_output=True, text=True, timeout=15, check=False)
        status = json.loads(result.stdout)
        self.require(result.returncode == 0 and status['observation_only'] and status['recovery_required']
                     and status['phase'] == 'stopped' and status['pending_plan_sha256'], 'transport_readonly_status_failed')
        self.require({p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths} == before,
                     'transport_status_wrote_management_state')
        self.add('status_during_live_scheduler_reads_signed_journal_without_writing_inputs')

    def run(self):
        super().run()
        self.transport_checks()

    def transport_checks(self, *, authority_epoch=3, interrupt=True):
        self.report['completed'] = False
        r = self.runtime
        before = self.refresh_active_leaves(label='transport')
        self.add('active_leaves_renew_before_first_paused_transport_ceremony', cycle=1)
        initial = self.retired_db_identity(save=True)
        self.require(initial['accepted'] and initial['unexpired'], 'transport_old_client_positive_control')
        self.add('old_database_client_authenticates_before_transport_rotation')
        # Snapshot DB rows without depending on private SQL column names.
        snapshot_query = "SELECT md5(coalesce(string_agg(row_to_json(t)::text,E'\\n' ORDER BY row_to_json(t)::text),'')) FROM {} t;"
        tables = SECURITY_TABLES
        security = {name: r.sql(snapshot_query.format(name)) for name in tables}
        first = self.drive_transport(1, interrupt=interrupt)
        self.require(first['live_evidence'] == {'verified': True, 'ca_nodes': 2, 'database_anchor': True,
                     'enrollment_and_security_tables': True}, 'transport_live_barrier_missing')
        self.add('timer_rotates_db_root_server_and_both_client_private_keys_with_live_mtls_barrier')
        retired = self.retired_db_identity()
        self.require(not retired['accepted'] and retired['unexpired'], 'transport_old_client_root_still_accepted')
        self.add('old_db_client_denied_under_current_server_trust_after_root_rotation')
        self.require(all(r.sql(snapshot_query.format(name)) == digest for name, digest in security.items()),
                     'transport_rotation_changed_nonce_or_revocation_rows')
        self.add('transport_rotation_preserves_exact_consumed_nonce_and_revocation_table_rows')
        self.require(r.controller_status()['paused'] and r.journal()['epoch'] == authority_epoch,
                     'transport_rotation_changed_workload_authority_or_pause')
        self.require({u: c['fingerprint'] for u, c in r.controller_status()['credentials'].items()} ==
                     {u: c['fingerprint'] for u, c in before['credentials'].items()}, 'transport_rotation_reissued_workload')
        self.add('workload_ca_epoch_leaf_identities_and_retired_collector_unchanged_by_db_rotation')
        prior_rows = security_rows(r)
        prior_credentials = r.controller_status()['credentials']
        second_before = self.refresh_active_leaves(label='transport')
        self.add('active_leaves_renew_before_second_paused_transport_ceremony', cycle=2)
        renewed_rows = security_rows(r)
        server_generations = sum(c['generation'] - prior_credentials[uid]['generation']
            for uid, c in second_before['credentials'].items() if c['purpose'] == 'serverAuth')
        self.report['fixture_renewal_security'] = {
            'original_consumed_nonces_retained': prior_rows['used_ott'] <= renewed_rows['used_ott'],
            'original_revocation_rows_retained': prior_rows['revoked_x509_certs'] <= renewed_rows['revoked_x509_certs'],
            'observed_server_generation_increments': server_generations,
            'observed_new_consumed_nonces': len(renewed_rows['used_ott'] - prior_rows['used_ott']),
            'removed_consumed_nonce_rows': len(prior_rows['used_ott'] - renewed_rows['used_ott']),
            'observed_new_revocation_rows': len(renewed_rows['revoked_x509_certs'] - prior_rows['revoked_x509_certs']),
            'removed_revocation_rows': len(prior_rows['revoked_x509_certs'] - renewed_rows['revoked_x509_certs']),
            'maintenance_additions_are_measurement_only': True}
        self.save()
        self.require(renewal_rows_preserved(prior_rows, renewed_rows),
                     'transport_fixture_renewal_changed_existing_security_rows')
        self.add('preparation_retains_every_prior_consumed_nonce_and_revocation_row')
        security = {name: r.sql(snapshot_query.format(name)) for name in tables}
        second = self.drive_transport(2)
        self.require(len(second['history']) == 2 and second['history'][1]['previous'] == custody.digest(second['history'][0]),
                     'transport_second_chain_missing')
        self.add('second_timed_transport_rotation_chains_to_first_without_resealing_anchor')
        self.require({u: c['fingerprint'] for u, c in r.controller_status()['credentials'].items()} ==
                     {u: c['fingerprint'] for u, c in second_before['credentials'].items()},
                     'second_transport_rotation_reissued_workload')
        self.require(all(r.sql(snapshot_query.format(name)) == digest for name, digest in security.items()),
                     'second_transport_rotation_changed_security_rows')
        r.down()
        r.up()
        self.require(r.transport_journal()['epoch'] == 2 and r.preflight()['database_transport']['verified'],
                     'transport_normal_resume_failed')
        self.add('normal_down_up_preserves_rotated_db_trust_and_signed_transport_epoch')
        original = r.transport_path.read_bytes()
        changed = json.loads(original)
        changed['history'][-1]['proof'] = 'AAAA'
        self.stopped_gate('tampered_transport_signed_history_refuses_all_services_before_start',
            lambda: r.transport_path.write_text(json.dumps(changed)), lambda: r.transport_path.write_bytes(original))
        self.require(all(r.sql(snapshot_query.format(name)) == digest for name, digest in security.items()),
                     'transport_restart_lost_security_rows')
        self.add('post_rotation_restart_and_tamper_recovery_retain_original_security_state')
        self.report['final_transport'] = r.transport_journal()
        self.report['final_transport_preflight'] = r.preflight()
        self.report['completed'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/database-transport-acceptance')
    args = parser.parse_args()
    checks = Checks(args.directory)
    try:
        checks.run()
    except (RuntimeError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        checks.report.update(completed=False, failure='database_transport_acceptance_failed', failure_detail=public_failure(error))
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
