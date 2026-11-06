"""Combined workload CA/HA and DB transport timed rekey/resume acceptance."""

import argparse
import copy
import json
import subprocess
import time
from pathlib import Path

from scripts import authority_custodian as custody
from scripts.authority_rotation_coordinator import lease
from scripts.certificate_controller import save
from scripts.continuous_mtls_runtime import ROOT, RuntimeFailure, command
from scripts.database_transport_runtime import VAULT, TransportCoordinator, TransportRuntime
from scripts.test_persistent_authority_runtime import AcceptanceRuntime
from scripts.test_persistent_authority_runtime import Checks as ParentChecks


class AcceptanceTransport(AcceptanceRuntime, TransportRuntime):
    pass


class Checks(ParentChecks):
    expected_volumes = 37

    def __init__(self, directory):
        super().__init__(directory, runtime_class=AcceptanceTransport)
        self.report['schema'] = 'database-transport-rotation-verification-1'

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
        worker = TransportCoordinator(r)
        deadline = time.monotonic() + 480
        restarted = False
        with lease(r.directory):
            while time.monotonic() < deadline:
                worker.tick()
                s = worker.state
                if interrupt and not restarted and s['phase'] == 'stopped':
                    plan = custody.digest(s['plan'])
                    try:
                        r.up()
                    except RuntimeFailure as error:
                        self.require(str(error) == 'database_transport_requires_pinned_resume', 'transport_wrong_pending_denial')
                    else:
                        raise RuntimeFailure('transport_pending_up_admitted')
                    worker = TransportCoordinator(r)
                    self.require(custody.digest(worker.state['plan']) == plan, 'transport_candidate_replaced_on_resume')
                    restarted = True
                    self.add('pending_transport_blocks_ordinary_start_and_new_coordinator_resumes_same_plan')
                if s['phase'] == 'idle' and s['epoch'] == epoch:
                    self.report.setdefault('transport_ceremonies', []).append(copy.deepcopy(s))
                    return s
                time.sleep(.2)
        raise RuntimeFailure('transport_acceptance_timeout')

    def run(self):
        super().run()
        self.report['completed'] = False
        r = self.runtime
        self.pause()
        before = r.controller_status()
        initial = self.retired_db_identity(save=True)
        self.require(initial['accepted'] and initial['unexpired'], 'transport_old_client_positive_control')
        self.add('old_database_client_authenticates_before_transport_rotation')
        # Snapshot DB rows without depending on private SQL column names.
        snapshot_query = "SELECT md5(coalesce(string_agg(row_to_json(t)::text,E'\\n' ORDER BY row_to_json(t)::text),'')) FROM {} t;"
        tables = ('used_ott', 'revoked_x509_certs')
        security = {name: r.sql(snapshot_query.format(name)) for name in tables}
        first = self.drive_transport(1, interrupt=True)
        self.require(first['live_evidence'] == {'verified': True, 'ca_nodes': 2, 'database_anchor': True,
                     'enrollment_and_security_tables': True}, 'transport_live_barrier_missing')
        self.add('timer_rotates_db_root_server_and_both_client_private_keys_with_live_mtls_barrier')
        retired = self.retired_db_identity()
        self.require(not retired['accepted'] and retired['unexpired'], 'transport_old_client_root_still_accepted')
        self.add('old_db_client_denied_under_current_server_trust_after_root_rotation')
        self.require(all(r.sql(snapshot_query.format(name)) == digest for name, digest in security.items()),
                     'transport_rotation_changed_nonce_or_revocation_rows')
        self.add('transport_rotation_preserves_exact_consumed_nonce_and_revocation_table_rows')
        self.require(r.controller_status()['paused'] and r.journal()['epoch'] == 3,
                     'transport_rotation_changed_workload_authority_or_pause')
        self.require({u: c['fingerprint'] for u, c in r.controller_status()['credentials'].items()} ==
                     {u: c['fingerprint'] for u, c in before['credentials'].items()}, 'transport_rotation_reissued_workload')
        self.add('workload_ca_epoch_leaf_identities_and_retired_collector_unchanged_by_db_rotation')
        second = self.drive_transport(2)
        self.require(len(second['history']) == 2 and second['history'][1]['previous'] == custody.digest(second['history'][0]),
                     'transport_second_chain_missing')
        self.add('second_timed_transport_rotation_chains_to_first_without_resealing_anchor')
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
    except (RuntimeError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        checks.report.update(completed=False, failure='database_transport_acceptance_failed')
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
