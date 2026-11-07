"""Focused Docker acceptance for manual checkpoint rollback denial.

This driver requires a fresh directory and cleans only its own project. It is
explicitly separate from the older full transport/backup acceptance.
"""

import argparse
import copy
import json
import subprocess
from pathlib import Path

from scripts.continuous_mtls_runtime import ROOT, RuntimeFailure
from scripts.database_recovery_runtime import RecoveryRuntime
from scripts.database_transport_runtime import management_lease
from scripts.test_database_backup_runtime import Checks as BackupChecks
from scripts.test_persistent_authority_runtime import AcceptanceRuntime
from scripts.test_transport_process_recovery import public_failure


class AcceptanceRecovery(AcceptanceRuntime, RecoveryRuntime):
    pass


class Checks(BackupChecks):
    expected_volumes = 41

    def __init__(self, directory):
        super().__init__(directory, runtime_class=AcceptanceRecovery)

    def run(self):
        self.focused()
        self.report.update(completed=False, schema='database-recovery-checkpoint-verification-1')
        r = self.runtime
        previous = copy.deepcopy(self.report['backups'][0]['manifest'])
        initial = copy.deepcopy(r.state['checkpoint_head'])
        with management_lease(r.directory):
            self.require(r.assess(previous)['checkpoint_compatible'], 'unchanged_snapshot_not_compatible')
        self.add('unchanged_older_archive_matches_last_explicit_checkpoint_in_isolation')
        # Generate and revoke an extra certificate through the actual CA APIs.
        # This is a test-only bootstrap signer; no synthetic SQL revocation rows.
        self.csr = json.loads(r.execute('certificate-controller', ['python', '-c',
            ("import json;from pathlib import Path;s=json.loads(Path('/state/state.json').read_bytes());"
             "print(json.dumps(next(c['csr'] for c in s['credentials'].values() if c['name']=='collector'))) ")]))
        self.ready()
        issued = self.ca(self.fresh(), endpoint='ca-a', store=True)
        self.require(issued['status'] == 201, 'checkpoint_probe_issue_failed')
        self.require(self.ca({'serial': issued['serial']}, endpoint='ca-b', mode='revoke')['status'] == 200,
                     'checkpoint_probe_revoke_failed')
        latest = self.drive_backup(new=True)
        self.require(latest['manifest']['security']['public.revoked_x509_certs']['rows'] >
                     previous['security']['public.revoked_x509_certs']['rows'], 'checkpoint_revocation_not_captured')
        self.require(r.state['checkpoint_head']['sequence'] > initial['sequence'], 'checkpoint_did_not_advance')
        self.add('actual_post_backup_revocation_advances_independent_checkpoint')
        with management_lease(r.directory):
            try:
                r.assess(previous)
            except (ValueError, RuntimeFailure):
                pass
            else:
                raise RuntimeFailure('checkpoint_accepted_security_rollback')
            self.require(r.assess(latest['manifest'])['checkpoint_compatible'], 'checkpoint_latest_restore_rejected')
        self.add('old_archive_denied_after_new_revocation_while_latest_restore_passes')
        before = copy.deepcopy(r.state['checkpoint_head'])
        r.down()
        r.up()
        self.require(r.state['checkpoint_head'] == before, 'checkpoint_restart_reset_host_anchor')
        with management_lease(r.directory):
            self.require(r.assess(latest['manifest'])['checkpoint_compatible'], 'checkpoint_restart_assessment_failed')
        self.add('normal_restart_preserves_checkpoint_anchor_and_compatible_restore')
        self.report.update(completed=True, checkpoint_head=before,
                           freshness='last_explicit_quiesced_checkpoint', live_restore_supported=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/database-recovery-acceptance')
    args = parser.parse_args()
    checks = Checks(args.directory)
    try:
        checks.run()
    except (RuntimeError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        checks.report.update(completed=False, failure='database_recovery_acceptance_failed',
                             failure_detail=public_failure(error))
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
