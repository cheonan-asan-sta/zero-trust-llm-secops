"""Real mTLS continuous evidence ingestion with restart and fail-closed boundaries.

All observations here are explicitly synthetic fixtures, not a detection benchmark.
"""

import argparse
import hashlib
import json
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from scripts.continuous_mtls_runtime import ROOT, RuntimeFailure
from scripts.execution_mtls_runtime import ExecutionRuntime
from scripts.test_continuous_mtls_runtime import Checks as BaseChecks
from scripts.test_recoverable_mtls_runtime import READ_STATE, RESTORE_EXITS

ACTOR = {'principal_id': 'runtime-user', 'workload_id': 'runtime-backup', 'executable_sha256': '4' * 64}
DESTINATIONS = [{'kind': 'https', 'host': 'archive.example.test', 'port': 443, 'path': '/backup'}]


class Checks(BaseChecks):
    def __init__(self, directory):
        super().__init__(directory, runtime_class=ExecutionRuntime)
        self.report['schema'] = 'execution-mtls-verification-1'

    def api(self, path, body=None, *, observer=False, expected=200):
        request = {'path': path, 'method': 'POST' if body is not None else 'GET'}
        if body is not None:
            request['body'] = body
        result = (self.runtime.observer_probe(request) if observer else self.runtime.context_probe(request))
        self.require(result['status'] == expected, 'execution_http_' + str(result['status']))
        self.require(result['tls_version'] == 'TLSv1.3', 'execution_tls13_required')
        return result['body']

    def spool(self):
        program = """import sqlite3,json
c=sqlite3.connect('/observer/state/execution-spool.sqlite3');c.row_factory=sqlite3.Row
print(json.dumps({'records':[dict(r) for r in c.execute('SELECT evidence_id,status,attempts,envelope_sha256 FROM records')],
 'evaluations':[dict(r) for r in c.execute('SELECT evidence_id,status,result FROM evaluations')],
 'files':c.execute('SELECT COUNT(*) FROM input_files').fetchone()[0],
 'archive':[dict(r) for r in c.execute('SELECT ordinal,evidence_id,raw_bytes,digest FROM execution_archive ORDER BY ordinal')]}))
"""
        return json.loads(self.runtime.execute('execution-observer', ['python', '-c', program]))

    def fixture(self, name, *, actor=ACTOR, destinations=DESTINATIONS):
        issued = self.runtime.mint({'session_id': 'session-' + name})
        self.require(issued['status'] == 200, 'execution_fixture_session')
        session = issued['body']['session']
        data = {'session': session, 'capture_id': name, 'actor': actor, 'destinations': destinations}
        bundle = json.loads(self.runtime.execute('operator', ['python', '-m', 'scripts.execution_runtime_fixture'],
                                                json.dumps(data)))
        return bundle, issued['body']

    def publish(self, bundle, filename=None):
        self.runtime.write_volume('execution-input', {
            (filename or bundle['capture']['capture_id']) + '.json': json.dumps(bundle),
        })

    def result(self, name):
        evidence_id = 'execution-' + name
        rows = [row for row in self.spool()['evaluations'] if row['evidence_id'] == evidence_id]
        return json.loads(rows[0]['result']) if rows and rows[0]['status'] == 'acknowledged' else None

    def await_result(self, name, verdict):
        self.wait(lambda: self.result(name) is not None, 'execution_evaluation_unavailable')
        result = self.result(name)
        self.require(result['verdict'] == verdict and result['enforcement_eligible'] is False,
                     'execution_unexpected_verdict_' + result['verdict'])
        self.add('observed_' + name, verdict=verdict, reason=result['reason'],
                 enforcement_eligible=False, capture_id=name,
                 completed_at=datetime.now(UTC).isoformat())
        return result

    def response_quorum(self):
        target = self.mint('execution-response-quorum')

        def post(path, body, reviewer=None, expected=200):
            request = {'path': '/response/requests' + path, 'method': 'POST', 'body': body}
            reply = (self.runtime.probe(request) if reviewer is None
                     else self.runtime.reviewer_probe(reviewer, request))
            self.require(reply['status'] == expected and reply['tls_version'] == 'TLSv1.3',
                         'execution_response_quorum_http')
            return reply['body']

        view = post('', {'request_id': 'execution-response', 'session_id': target[0],
                         'expected_session_version': 1, 'action': 'isolate_device',
                         'expires_at': (datetime.now(UTC) + timedelta(seconds=295)).isoformat(),
                         'reason': 'Explicit local simulated containment review'}, expected=201)

        def version():
            return {'expected_version': view['version'], 'request_digest': view['request_digest']}

        post('/execution-response/execute', version(), expected=409)
        post('/execution-response/approvals', version() | {'reason': 'Requester cannot self approve'}, expected=403)
        for reviewer in ('a', 'b'):
            view = post('/execution-response/approvals', version() | {'reason': 'Independent identity fixture review'},
                        reviewer=reviewer)
        result = post('/execution-response/execute', version())
        self.require(result['result']['status'] == 'SIMULATED' and result['result']['effect_applied'] is False,
                     'execution_response_external_effect')
        self.add('two_isolated_reviewer_identities_require_quorum_before_simulation',
                 reviewers=view['approved_by'], effect_applied=False, human_independent_review=False)

    def run(self):
        runtime = self.runtime
        runtime.up()
        self.report.update(release=runtime.state['release'], image_id=runtime.state['image_id'],
                           nginx_image_id=runtime.state['nginx_image_id'])
        self.require(len(runtime.services) == 10 and len(runtime.volumes) == 28, 'execution_inventory')
        self.add('locked_mtls_runtime_started', services=10, volumes=28)
        for path in ('/detections/context/baselines', '/detections/context/approvals',
                     '/zero-trust/protected-access', '/response/requests'):
            self.api(path, {}, observer=True, expected=403)
        self.api('/zero-trust/protected-access', {}, expected=403)
        self.add('delivery_peer_cannot_approve_mint_or_execute')
        for index in range(3):
            name = 'baseline-' + str(index)
            bundle, _ = self.fixture(name)
            self.publish(bundle)
            self.await_result(name, 'unknown')
        now = datetime.now(UTC)
        self.api('/detections/context/baselines', {
            'baseline_id': 'runtime-baseline', 'capture_ids': ['baseline-' + str(i) for i in range(3)],
            'valid_from': (now + timedelta(seconds=5)).isoformat(),
            'valid_until': (now + timedelta(minutes=10)).isoformat(), 'note': 'Reviewed synthetic acceptance samples',
        }, expected=201)
        start = datetime.now(UTC) + timedelta(seconds=5)
        self.api('/detections/context/approvals', {
            'approval_id': 'runtime-approval', 'baseline_id': 'runtime-baseline', 'max_uses': 10,
            'execution_policy': {'actor': ACTOR, 'destinations': DESTINATIONS},
            'valid_from': start.isoformat(), 'valid_until': (start + timedelta(minutes=9)).isoformat(),
            'note': 'Exact observed actor and destination, bounded local fixture approval',
        }, expected=201)
        while datetime.now(UTC) <= start + timedelta(seconds=2):
            time.sleep(.1)
        normal, _ = self.fixture('approved-normal')
        self.publish(normal)
        self.await_result('approved-normal', 'normal')
        for name, actor, destinations, verdict in (
            ('wrong-actor', ACTOR | {'workload_id': 'other-job'}, DESTINATIONS, 'threat'),
            ('wrong-destination', ACTOR, [DESTINATIONS[0] | {'host': 'other.example.test'}], 'threat'),
            ('missing-actor', None, DESTINATIONS, 'unknown'),
        ):
            bundle, _ = self.fixture(name, actor=actor, destinations=destinations)
            self.publish(bundle)
            self.await_result(name, verdict)
        before = self.spool()
        normal_hash = next(row['envelope_sha256'] for row in before['records']
                           if row['evidence_id'] == 'execution-approved-normal')
        self.publish(normal, filename='duplicate-normal')
        self.wait(lambda: self.spool()['files'] == before['files'] + 1, 'execution_duplicate_not_ingested')
        self.require(len(self.spool()['records']) == len(before['records']), 'execution_duplicate_record')
        self.add('duplicate_input_preserves_single_envelope', envelope_sha256=normal_hash)
        # Queue while core is unavailable, then kill the daemon, not a graceful CLI restart.
        outage, _ = self.fixture('outage-restart')
        runtime.compose('stop', '--timeout', '2', 'app')
        self.publish(outage)
        self.wait(lambda: any(row['evidence_id'] == 'execution-outage-restart' and row['attempts'] >= 1
                              for row in self.spool()['records']), 'execution_outage_not_queued')
        self.restart('execution-observer')
        runtime.compose('start', 'app')
        self.await_result('outage-restart', 'normal')
        self.add('core_outage_and_sigkill_resume_durable_delivery')
        # Signed capture tampering cannot cause execution admission or evaluation.
        tampered, _ = self.fixture('tampered-capture')
        tampered['capture']['activity']['events'][0]['outcome'] = 'failure'
        # Keep the unsigned linkage consistent so only server signature verification can decide.
        from app.behavior_context_models import SignedBehaviorCapture
        from app.services.trusted_signals import canonical_behavior_capture
        tampered['execution']['capture_input_sha256'] = hashlib.sha256(canonical_behavior_capture(
            SignedBehaviorCapture.model_validate(tampered['capture']))).hexdigest()
        self.publish(tampered)
        self.wait(lambda: any(row['evidence_id'] == 'execution-tampered-capture' and row['status'] == 'rejected'
                              for row in self.spool()['records']), 'execution_tamper_not_rejected')
        self.require(self.result('tampered-capture') is None, 'execution_tamper_evaluated')
        self.add('tampered_capture_rejected_before_execution')
        self.response_quorum()
        # Trusted adverse intake enforces revocation independently of advisory context.
        related = self.mint('related-adverse')
        unrelated = self.mint('unrelated-adverse', user_id='runtime-other', device_id='other-device')
        sent = datetime.now(UTC)
        self.append('execution-adverse')
        self.wait(lambda: self.completed('execution-adverse'), 'execution_adverse_not_processed')
        self.access(related, False, 'trusted_adverse_related_403')
        self.access(unrelated, True, 'trusted_adverse_unrelated_200')
        self.add('trusted_signal_enforcement_timing', event_id='execution-adverse',
                 sent_at=sent.isoformat(), observed_at=datetime.now(UTC).isoformat())
        # Archive within the live mTLS graph before exercising the restore fence.
        retained = json.loads(runtime.execute('execution-observer', [
            'python', '-m', 'scripts.behavior_execution_collector', 'compact',
            '--directory', '/observer/state', '--base-url', 'https://core:8000',
            '--tls-profile', '/tls/core.json', '--input-directory', '/observer/input',
        ]))
        self.require(retained['compacted'] >= 5 and retained['retired_inputs'] >= 5,
                     'execution_terminal_history_not_archived')
        server = json.loads(runtime.execute('app', [
            'python', '-m', 'scripts.context_maintenance', 'compact',
            '--database', '/data/app-behavior-context.sqlite3',
        ]))
        self.require(server['archived_records'] > 0, 'execution_server_history_not_archived')
        history = self.spool()['archive']
        self.publish(normal, filename='duplicate-normal')
        self.wait(lambda: runtime.execute('execution-observer', ['python', '-c',
                  "from pathlib import Path;print(Path('/observer/input/duplicate-normal.json').exists())"]).strip() == 'False',
                  'execution_archived_duplicate_not_retired')
        self.require(self.spool()['archive'] == history and not any(
            row['evidence_id'] == 'execution-approved-normal' for row in self.spool()['records']),
                     'execution_archived_duplicate_requeued')
        self.access(related, False, 'after_archive_related_403')
        unaffected = self.mint('after-archive-unrelated', user_id='runtime-other', device_id='other-device')
        self.access(unaffected, True, 'after_archive_unrelated_200')
        self.add('terminal_spool_and_input_rotation_preserve_original_history',
                 compacted=retained['compacted'], retired_inputs=retained['retired_inputs'],
                 server_archived=server['archived_records'])
        # Use an unaffected subject to prove restore fencing independently of revocation.
        old = self.mint('restore-old-unrelated', user_id='runtime-other', device_id='other-device')
        before_spool = self.spool()
        before_state = json.loads(runtime.execute('app', ['python', '-c', READ_STATE, '/data']))
        original = runtime.recovery_job
        with patch.object(runtime, 'recovery_job', lambda: original(['-c', RESTORE_EXITS[1]])):
            try:
                runtime.recover()
            except RuntimeFailure as error:
                self.require(str(error) == 'runtime_command_failed_73', 'execution_restore_wrong_exit')
            else:
                raise RuntimeFailure('execution_restore_interruption_not_exercised')
        self.require(runtime.phase() == {'phase': 'maintenance'}, 'execution_restore_published_early')
        self.require(not self.inspect('execution-observer')['State']['Running'], 'execution_restore_writer_running')
        self.add('restore_interruption_keeps_observer_stopped', exit_code=73)
        self.runtime = runtime = ExecutionRuntime(runtime.directory)
        runtime.recover()
        self.wait(lambda: self.inspect('execution-observer')['State']['Running'], 'execution_restore_observer_not_running')
        after_state = json.loads(runtime.execute('app', ['python', '-c', READ_STATE, '/data/active']))
        self.require(before_state['behavior_context'] == after_state['behavior_context'],
                     'execution_restore_context_history_changed')
        self.require(self.spool() == before_spool, 'execution_restore_spool_changed')
        self.access(old, False, 'restored_old_token_403')
        fresh = self.mint('restore-fresh-unrelated', user_id='runtime-other', device_id='other-device')
        self.access(fresh, True, 'restored_fresh_token_200')
        self.add('full_restore_preserves_context_and_delivery_history')
        self.report['completed'] = True
        self.report['finished_at'] = datetime.now(UTC).isoformat()
        self.save()
        return self.report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/execution-check')
    args = parser.parse_args(argv)
    checks = Checks(args.directory)
    try:
        checks.run()
        return 0
    except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        checks.report.update(completed=False, error=type(error).__name__)
        if isinstance(error, RuntimeFailure):
            checks.report['error_code'] = str(error)
        checks.save()
        print(json.dumps({'completed': False, 'error': type(error).__name__}))
        return 1
    finally:
        if checks.runtime.descriptor.exists():
            checks.report['cleanup'] = checks.runtime.down(purge=True)
            checks.save()


if __name__ == '__main__':
    raise SystemExit(main())
