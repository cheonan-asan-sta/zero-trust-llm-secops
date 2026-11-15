"""Bounded local shadow soak with real clocks and worker exits; no access or network API."""

import argparse
import base64
import hashlib
import json
import os
import signal as process_signal
import subprocess
import sys
import tempfile
import time
import tracemalloc
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import get_settings
from app.models import SecurityEvent
from app.security import Principal, Role
from app.services.trusted_signals import canonical_signal
from app.zero_trust_models import SignedSessionSignal
from scripts.ca_recovery_state import atomic
from scripts.f1_lab.approvals import ApprovalContext, event_digest, sign
from scripts.f1_lab.detector import ShadowDetector
from scripts.f1_lab.registry import PinnedApprovalVerifier
from scripts.f1_lab.resource_policy import PinnedResourcePolicies
from scripts.f1_lab.source_registry import FrozenSignalVerifier
from scripts.f1_lab.temporal import TemporalStore, TemporalUnavailable

ROOT = Path(__file__).resolve().parents[1]
TENANT, OPERATOR = 'soak-lab', 'soak-operator'
SOURCES = {(TENANT, 'events', 'event-key')}
PRINCIPAL = Principal(OPERATOR, TENANT, frozenset({Role.ANALYST}), 'api_key')
CRASHES = {2: 'after_prepare', 62: 'before_db_commit', 122: 'after_db_commit', 182: 'after_publish'}


class SoakFailure(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise SoakFailure(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def sources_store(root):
    config = json.loads((root/'pins.json').read_bytes())
    policy = PinnedResourcePolicies(root/'policies.json', config['policies'], minimum_version=1)
    return TemporalStore(root/'events.db', root/'control', FrozenSignalVerifier(root/'sources.json', config['sources']),
                         SOURCES, capacity=2000, resource_policies=policy)


class SoakLab:
    def __init__(self, root):
        require(get_settings().app_environment in {'local', 'test'}, 'soak_local_test_only')
        self.root = Path(root)
        require(self.root.is_dir() and not self.root.is_symlink() and not any(self.root.iterdir()),
                'soak_fresh_private_runtime_required')
        self.producer, self.business = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        now = datetime.now(UTC)
        before, after = now-timedelta(minutes=1), now+timedelta(hours=7)
        source = {'sources': [{'source_id': 'events', 'tenant_id': TENANT,
            'user_ids': ['soak-user', 'other-user'], 'device_ids': ['soak-device', 'other-device'], 'roles': ['employee'],
            'keys': [{'key_id': 'event-key', 'public_key_pem': pem(self.producer),
                      'not_before': before.isoformat(), 'not_after': after.isoformat()}]}]}
        policy = {'schema_version': 'f1-resource-policies-1', 'version': 1,
            'issued_at': before.isoformat(), 'expires_at': after.isoformat(),
            'resources': [{'tenant_id': TENANT, 'resource_id': 'resource', 'sensitivity': 'critical',
                'permissions': [{'action': action, 'roles': ['administrator'] if action == 'ADMIN' else ['employee']}
                                for action in ('READ', 'DOWNLOAD', 'LOGIN', 'ADMIN')]}]}
        approvals = {'schema_version': 'zt-business-authorities-1', 'version': 1, 'authorities': [{
            'tenant_id': TENANT, 'issuer_id': 'fixture-owner', 'key_id': 'business-key',
            'public_key_pem': pem(self.business), 'allowed_deviations': ['bulk_export'],
            'user_ids': ['soak-user'], 'device_ids': ['soak-device'], 'resource_ids': ['resource'],
            'actions': ['DOWNLOAD'], 'key_not_before': before.isoformat(), 'key_not_after': after.isoformat()}],
            'revoked_approval_ids': []}
        pins = {}
        for name, body in [('sources', source), ('policies', policy), ('approvals', approvals)]:
            raw = canonical(body)
            atomic(self.root/(name+'.json'), raw)
            pins[name] = hashlib.sha256(raw).hexdigest()
        atomic(self.root/'pins.json', canonical(pins))
        self.store = sources_store(self.root)
        self.store.initialize()
        verifier = PinnedApprovalVerifier(self.root/'approvals.json', pins['approvals'], minimum_version=1)
        self.detector = ShadowDetector(temporal_store=self.store, approval_verifier=verifier)
        self.created = self.accepted = self.negative_probes = self.worker_exits = self.duplicates = 0
        self.approved_jobs = self.export_episodes = self.auth_episodes = self.policy_denials = 0
        self.last_at_risk = None
        self.last_event = None
        self._accept(self.message())

    def message(self, *, session='main', action='READ', posture='healthy', failure=False,
                volume=0, user='soak-user', instant=None):
        self.created += 1
        now = datetime.now(UTC) if instant is None else instant
        event = SecurityEvent.model_validate({'event_id': 'soak-event-'+str(self.created), 'timestamp': now,
            'action': action, 'user': {'user_id': user, 'role': 'employee', 'active': True},
            'device': {'device_id': 'soak-device', 'managed': True, 'security_posture': posture},
            'network': {'ip': '192.0.2.1', 'location': 'local-soak', 'access_method': 'office', 'location_anomaly': False},
            'resource': {'resource_id': 'resource', 'resource_type': 'file', 'sensitivity': 'public', 'required_role': None},
            'auth_context': {'mfa': 'success', 'authentication_result': 'failure' if failure else 'success',
                             'failed_attempts': 1 if failure else 0, 'session_age_minutes': 0},
            'behavior': {'request_rate': 'normal', 'new_device': False, 'unusual_time': False,
                         'download_volume_mb': volume, 'distinct_resources_10m': 1}})
        message = SignedSessionSignal(tenant_id=TENANT, source_id='events', key_id='event-key',
            session_id=session, expected_version=0, event=event, issued_at=now,
            expires_at=now+timedelta(seconds=90), signature='A'*86)
        signature = base64.urlsafe_b64encode(self.producer.sign(canonical_signal(message))).decode().rstrip('=')
        return message.model_copy(update={'signature': signature})

    def _accept(self, message, *, approval=None, already_committed=False):
        result = self.detector.evaluate_signed(message, PRINCIPAL, approval=approval, now=datetime.now(UTC))
        require(result['access_grants'] == result['session_changes'] == result['external_calls'] == 0, 'soak_unexpected_effect')
        require(result['temporal_evidence']['complete'], 'soak_incomplete_evidence')
        require(result['temporal_evidence']['duplicate'] == already_committed, 'soak_duplicate_contract')
        self.accepted += 1
        self.last_event = message
        return result

    def approved_job(self, cycle):
        last = None
        for _ in range(3):
            message = self.message(session='job-'+str(cycle), action='DOWNLOAD', volume=200)
            window = self.store.observe(message, PRINCIPAL, now=datetime.now(UTC))
            context = ApprovalContext(approval_id='approval-'+hashlib.sha256(message.event.event_id.encode()).hexdigest()[:32],
                tenant_id=TENANT, issuer_id='fixture-owner', key_id='business-key', event_sha256=event_digest(message.event),
                user_id='soak-user', device_id='soak-device', resource_id='resource', action='DOWNLOAD',
                permitted_deviations=['bulk_export'], maximum_download_mb=600,
                issued_at=message.issued_at, expires_at=message.issued_at+timedelta(seconds=60),
                window_evidence_sha256=window['evidence_sha256'])
            last = self._accept(message, approval=sign(context, self.business), already_committed=True)
            require(last['signed_window_context_status'] == 'verified'
                    and 'CUMULATIVE_SIGNED_SENSITIVE_DOWNLOAD' not in last['reason_codes'], 'soak_approved_job_rejected')
        require(last['temporal_evidence']['sensitive_download_mb'] == 600, 'soak_approved_volume')
        self.approved_jobs += 1

    def probes(self):
        before = self.store.summary('main', PRINCIPAL, now=datetime.now(UTC))['journal_head_sha256']
        good = self.message()
        bad = [good.model_copy(update={'signature': 'B'*86}), self.message(user='other-user')]
        expired = self.message(instant=datetime.now(UTC)-timedelta(seconds=100))
        bad.append(expired)
        for message in bad:
            try:
                self.store.observe(message, PRINCIPAL, now=datetime.now(UTC))
            except TemporalUnavailable:
                self.negative_probes += 1
            else:
                raise SoakFailure('soak_bad_proof_or_session_accepted')
        after = self.store.summary('main', PRINCIPAL, now=datetime.now(UTC))['journal_head_sha256']
        require(before == after, 'soak_rejected_probe_changed_journal')
        self._accept(good)
        retried = self.detector.evaluate_signed(good, PRINCIPAL, now=datetime.now(UTC))
        require(retried['temporal_evidence']['duplicate'], 'soak_exact_retry_not_idempotent')
        self.duplicates += 1

    def crash_worker(self, phase):
        message = self.message(session='worker-recovery')
        payload = self.root/'worker-input.json'
        atomic(payload, message.model_dump_json().encode())
        outcome = subprocess.run([sys.executable, '-m', 'scripts.run_f1_soak', 'worker', '--root', str(self.root),
            '--phase', phase], cwd=ROOT, capture_output=True, timeout=25, check=False)
        require(outcome.returncode == 73, 'soak_worker_did_not_exit_at_boundary')
        self._accept(message, already_committed=phase in {'after_db_commit', 'after_publish'})
        self.worker_exits += 1

    def cycle(self, index):
        result = self._accept(self.message())
        as_of = datetime.fromisoformat(result['temporal_evidence']['as_of'])
        expected_history = self.last_at_risk is not None and as_of-self.last_at_risk < timedelta(seconds=600)
        require(('RECENT_AT_RISK_DEVICE' in result['reason_codes']) == expected_history, 'soak_adverse_history_or_expiry')
        if index % 45 == 0:
            message = self.message(posture='at_risk')
            self._accept(message)
            self.last_at_risk = message.event.timestamp
        if index % 20 == 0:
            self.approved_job(index)
        if index % 40 == 0:
            for _ in range(3):
                result = self._accept(self.message(session='unapproved-export', action='DOWNLOAD', volume=200))
            require('CUMULATIVE_SIGNED_SENSITIVE_DOWNLOAD' in result['reason_codes'], 'soak_split_export_missed')
            self.export_episodes += 1
        if index % 60 == 0:
            for _ in range(4):
                result = self._accept(self.message(session='failed-logins', action='LOGIN', failure=True))
            require('REPEATED_SIGNED_FAILED_LOGIN_EVENTS' in result['reason_codes'], 'soak_failed_login_sequence_missed')
            self.auth_episodes += 1
        if index % 90 == 0:
            result = self._accept(self.message(session='denied-admin', action='ADMIN'))
            require('AUTHORITATIVE_RESOURCE_POLICY_DENIED' in result['reason_codes'], 'soak_resource_deny_missed')
            result = self._accept(self.message(session='denied-admin'))
            require('RECENT_RESOURCE_POLICY_DENIED' in result['reason_codes'], 'soak_resource_deny_erased')
            self.policy_denials += 1
        if index % 10 == 0:
            self.probes()
        if index in CRASHES:
            self.crash_worker(CRASHES[index])
        head = self.store._witness(self.store._key())['current']
        require(head['seq'] == self.accepted, 'soak_journal_count_mismatch')
        return {'cycle': index, 'accepted_unique_events': self.accepted, 'journal_seq': head['seq'],
            'negative_probes_rejected': self.negative_probes, 'worker_exits_recovered': self.worker_exits,
            'exact_retries': self.duplicates, 'approved_fixture_jobs': self.approved_jobs,
            'unapproved_export_episodes': self.export_episodes, 'failed_login_episodes': self.auth_episodes,
            'resource_denial_episodes': self.policy_denials, 'journal_sha256': head['hash']}


def run(directory, until, *, interval=30, maximum_cycles=1000):
    directory = Path(directory)
    start = datetime.now(UTC)
    require(isinstance(until, datetime) and until.tzinfo is not None and until.utcoffset() is not None
            and timedelta(0) < until-start <= timedelta(hours=6), 'soak_deadline_maximum_six_hours')
    require(type(interval) in {int, float} and 1 <= interval <= 300 and type(maximum_cycles) is int
            and 1 <= maximum_cycles <= 1000, 'soak_cycle_bounds')
    require(not directory.exists() and not directory.is_symlink(), 'soak_fresh_directory_required')
    directory.mkdir(parents=True)
    captured = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
                for p in [Path(__file__), *sorted((ROOT/'scripts/f1_lab').glob('*.py'))]}
    stopped = False

    def stop(_signal, _frame):
        nonlocal stopped
        stopped = True

    previous = process_signal.signal(process_signal.SIGTERM, stop)
    started, duration = time.monotonic(), (until-start).total_seconds()
    report = {'schema': 'f1-shadow-soak-1', 'started_at_utc': start.isoformat(), 'deadline_utc': until.isoformat(),
        'source_files_lf_sha256': captured, 'clock_mode': 'real_wall_clock_with_monotonic_run_bound',
        'interval_seconds': interval, 'cycles': 0, 'completed': False, 'failure_type': None,
        'fixture_approvals': True, 'real_business_approvals': 0, 'metric_scope': 'functional_reliability_not_F1',
        'independent_review': 'pending', 'goal_qualified': False,
        'effects': {'network_calls': 0, 'paid_api_calls': 0, 'cloud_calls': 0, 'access_grants': 0, 'session_changes': 0}}
    tracemalloc.start()
    try:
        with tempfile.TemporaryDirectory(dir=directory, prefix='.private-') as temporary:
            lab = SoakLab(Path(temporary))
            for name in ('sources', 'policies', 'approvals', 'pins'):
                raw = (Path(temporary)/(name+'.json')).read_bytes()
                filename = 'public-'+name+'.json'
                atomic(directory/filename, raw)
                print(json.dumps({'public_artifact': {'name': filename, 'encoding': 'base64', 'bytes': len(raw),
                    'sha256': hashlib.sha256(raw).hexdigest(), 'data': base64.b64encode(raw).decode()}}), flush=True)
            while not stopped and datetime.now(UTC) < until and time.monotonic()-started < duration:
                if report['cycles'] >= maximum_cycles:
                    report['stop_reason'] = 'cycle_bound'
                    break
                row = lab.cycle(report['cycles'])
                report.update(row)
                report['cycles'] += 1
                report['last_heartbeat_utc'] = datetime.now(UTC).isoformat()
                heartbeat = {**row, 'at_utc': report['last_heartbeat_utc']}
                with (directory/'heartbeats.jsonl').open('ab') as stream:
                    stream.write(canonical(heartbeat)+b'\n')
                    stream.flush()
                    os.fsync(stream.fileno())
                atomic(directory/'status.json', canonical(report))
                print(json.dumps({'public_heartbeat': heartbeat}), flush=True)
                target = time.monotonic()+interval
                while not stopped and datetime.now(UTC) < until and time.monotonic() < target and time.monotonic()-started < duration:
                    time.sleep(min(1, max(0, target-time.monotonic())))
            if stopped:
                report['stop_reason'] = 'operator_signal'
            elif 'stop_reason' not in report:
                report['stop_reason'] = 'deadline'
                report['completed'] = True
    except (ValueError, TypeError, OSError, RuntimeError, subprocess.SubprocessError, KeyError, OverflowError) as error:
        report['failure_type'] = type(error).__name__
        report['failure_code'] = str(error) if isinstance(error, SoakFailure) else 'bounded_soak_failure'
        report['stop_reason'] = 'failure'
    finally:
        report['elapsed_seconds'] = round(time.monotonic()-started, 3)
        _current, peak = tracemalloc.get_traced_memory()
        report['python_heap_peak_after_instrumentation_bytes'] = peak
        report['memory_measurement_scope'] = 'tracemalloc Python allocations after imports; excludes native memory and OS page cache'
        tracemalloc.stop()
        report['private_runtime_remaining'] = len(list(directory.glob('.private-*')))
        public_names = ['public-'+name+'.json' for name in ('sources', 'policies', 'approvals', 'pins')]
        report['public_artifact_sha256'] = {name: hashlib.sha256((directory/name).read_bytes()).hexdigest()
            for name in [*public_names, 'heartbeats.jsonl'] if (directory/name).exists()}
        report['public_transport'] = 'explicit_stdout_whitelist_v1; no private control files'
        report['finished_at_utc'] = datetime.now(UTC).isoformat()
        report['source_snapshot_unchanged'] = captured == {name: hashlib.sha256((ROOT/name).read_bytes().replace(b'\r\n', b'\n')).hexdigest() for name in captured}
        report['completed'] = report['completed'] and report['source_snapshot_unchanged'] and not report['private_runtime_remaining']
        atomic(directory/'status.json', canonical(report))
        process_signal.signal(process_signal.SIGTERM, previous)
    return report


def worker(root, phase):
    store = sources_store(root)

    def fault(name):
        if name == phase:
            os._exit(73)

    store._phase = fault
    store.observe(SignedSessionSignal.model_validate_json((root/'worker-input.json').read_bytes()),
                  PRINCIPAL, now=datetime.now(UTC))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    soak = sub.add_parser('run')
    soak.add_argument('--directory', type=Path, required=True)
    soak.add_argument('--until', type=datetime.fromisoformat, required=True)
    soak.add_argument('--interval-seconds', type=int, default=30)
    soak.add_argument('--maximum-cycles', type=int, default=1000)
    child = sub.add_parser('worker')
    child.add_argument('--root', type=Path, required=True)
    child.add_argument('--phase', choices=tuple(CRASHES.values()), required=True)
    args = parser.parse_args()
    if args.mode == 'worker':
        worker(args.root, args.phase)
        return 1
    report = run(args.directory, args.until, interval=args.interval_seconds, maximum_cycles=args.maximum_cycles)
    print(json.dumps(report), flush=True)
    return 0 if report['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
