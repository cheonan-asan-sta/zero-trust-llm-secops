"""Real-clock, bounded subject-window acceptance exercise; fixture identities only."""

import argparse
import base64
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
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
from scripts.f1_lab.resource_policy import PinnedResourcePolicies
from scripts.f1_lab.source_registry import FrozenSignalVerifier
from scripts.f1_lab.subject_temporal import (
    PinnedSubjectApprovalVerifier,
    SubjectApprovalVerifier,
    SubjectShadowDetector,
    SubjectTemporalStore,
)
from scripts.f1_lab.temporal import TemporalUnavailable

ROOT = Path(__file__).resolve().parents[1]
TENANT, OPERATOR = 'subject-soak', 'fixture-analyst'
PRINCIPAL = Principal(OPERATOR, TENANT, frozenset({Role.ANALYST}), 'api_key')
SOURCES = {(TENANT, 'events', 'event-key')}
USERS = ('access-user', 'approved-user', 'export-user', 'auth-user', 'fanout-user', 'worker-user', 'other-user')
CRASHES = {2: 'after_prepare', 62: 'before_db_commit', 122: 'after_db_commit', 182: 'after_publish'}
SOURCE_FILES = ('scripts/run_f1_subject_soak.py', 'scripts/f1_lab/subject_temporal.py', 'scripts/f1_lab/temporal.py',
    'scripts/f1_lab/approvals.py', 'scripts/f1_lab/registry.py', 'scripts/f1_lab/source_registry.py',
    'scripts/f1_lab/detector.py', 'scripts/f1_lab/resource_policy.py', 'app/models.py', 'app/services/trusted_signals.py')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def require(condition, code):
    if not condition:
        raise ValueError('subject_soak_'+code)


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def store_for(root):
    pins = json.loads((root/'pins.json').read_bytes())
    return SubjectTemporalStore(root/'events.db', root/'control', FrozenSignalVerifier(root/'sources.json', pins['sources']),
        SOURCES, capacity=2000, resource_policies=PinnedResourcePolicies(root/'policies.json', pins['policies'], minimum_version=1))


class SubjectSoakLab:
    def __init__(self, root):
        require(get_settings().app_environment in {'local', 'test'}, 'local_test_only')
        self.root = Path(root)
        require(self.root.is_dir() and not self.root.is_symlink() and not any(self.root.iterdir()), 'fresh_private_directory')
        self.producer, self.business = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        now = datetime.now(UTC)
        before, after = now-timedelta(minutes=1), now+timedelta(hours=7)
        bodies = {'sources': {'sources': [{'source_id': 'events', 'tenant_id': TENANT, 'user_ids': list(USERS),
            'device_ids': ['device-a', 'device-b', 'access-device', 'risk-device'], 'roles': ['employee'], 'keys': [{'key_id': 'event-key',
                'public_key_pem': public(self.producer), 'not_before': before.isoformat(), 'not_after': after.isoformat()}]}]},
            'policies': {'schema_version': 'f1-resource-policies-1', 'version': 1, 'issued_at': before.isoformat(),
                'expires_at': after.isoformat(), 'resources': [{'tenant_id': TENANT, 'resource_id': 'resource-'+str(i),
                    'sensitivity': 'critical', 'permissions': [{'action': a, 'roles': ['employee']} for a in ('READ', 'DOWNLOAD', 'LOGIN')]}
                    for i in range(8)]},
            'approvals': {'schema_version': 'zt-business-authorities-1', 'version': 1, 'authorities': [{
                'tenant_id': TENANT, 'issuer_id': 'fixture-owner', 'key_id': 'business-key', 'public_key_pem': public(self.business),
                'allowed_deviations': ['bulk_export'], 'user_ids': ['approved-user'], 'device_ids': ['device-a', 'device-b'],
                'resource_ids': ['resource-'+str(i) for i in range(8)], 'actions': ['DOWNLOAD'],
                'key_not_before': before.isoformat(), 'key_not_after': after.isoformat()}]}}
        pins = {}
        for name, body in bodies.items():
            raw = canonical(body)
            atomic(self.root/(name+'.json'), raw)
            pins[name] = hashlib.sha256(raw).hexdigest()
        atomic(self.root/'pins.json', canonical(pins))
        self.store = store_for(self.root)
        self.store.initialize()
        self.approvals = PinnedSubjectApprovalVerifier(self.root/'approvals.json', pins['approvals'], minimum_version=1)
        self.detector = SubjectShadowDetector(temporal_store=self.store, approval_verifier=self.approvals)
        self.serial, self.seen, self.risk_at = 0, set(), None
        self.counts = {'accepted_unique_events': 0, 'worker_exits_recovered': 0, 'exact_retries': 0,
            'negative_probes_rejected': 0, 'approved_fixture_jobs': 0, 'partial_device_approvals_rejected': 0,
            'unapproved_export_episodes': 0, 'failed_login_episodes': 0, 'fanout_episodes': 0,
            'risk_episodes': 0, 'expired_risk_observations': 0, 'isolation_probes': 0}

    def message(self, user, session, *, action='READ', device='device-a', resource=0, volume=0, posture='healthy', failure=False):
        self.serial += 1
        now = datetime.now(UTC)
        event = SecurityEvent.model_validate({'event_id': 'subject-event-'+str(self.serial), 'timestamp': now.isoformat(),
            'action': action, 'user': {'user_id': user, 'role': 'employee', 'active': True},
            'device': {'device_id': device, 'managed': True, 'security_posture': posture},
            'network': {'ip': '192.0.2.1', 'location': 'fixture', 'access_method': 'office', 'location_anomaly': False},
            'resource': {'resource_id': 'resource-'+str(resource), 'resource_type': 'file', 'sensitivity': 'public', 'required_role': None},
            'auth_context': {'mfa': 'success', 'authentication_result': 'failure' if failure else 'success',
                'failed_attempts': 1 if failure else 0, 'session_age_minutes': 0},
            'behavior': {'request_rate': 'normal', 'new_device': False, 'unusual_time': False,
                'download_volume_mb': volume, 'distinct_resources_10m': 1}})
        result = SignedSessionSignal(tenant_id=TENANT, source_id='events', key_id='event-key', issued_at=now,
            expires_at=now+timedelta(seconds=90), expected_version=0, session_id=session, event=event, signature='A'*86)
        return result.model_copy(update={'signature': base64.urlsafe_b64encode(self.producer.sign(canonical_signal(result))).decode().rstrip('=')})

    def receive(self, message, *, approval=None, detector=None, principal=PRINCIPAL):
        result = (detector or self.detector).evaluate_signed(message, principal, approval=approval, now=datetime.now(UTC))
        require(result['access_grants'] == result['session_changes'] == result['external_calls'] == 0, 'effects')
        require(result['temporal_evidence']['subject_evidence_complete'], 'authority_incomplete')
        ident = message.event.event_id
        if ident not in self.seen:
            self.counts['accepted_unique_events'] += 1
        else:
            require(result['temporal_evidence']['duplicate'], 'seen_event_not_duplicate')
        self.counts['exact_retries'] += result['temporal_evidence']['duplicate']
        self.seen.add(ident)
        return result

    def approved_job(self, index):
        for part in range(3):
            message = self.message('approved-user', f'approved-{index}-{part}', action='DOWNLOAD',
                                   device='device-b' if part == 0 else 'device-a', resource=part, volume=200)
            result = self.receive(message)
        window = result['temporal_evidence']
        context = ApprovalContext(approval_id='approval-'+hashlib.sha256(str(index).encode()).hexdigest()[:32], tenant_id=TENANT,
            issuer_id='fixture-owner', key_id='business-key', event_sha256=event_digest(message.event),
            user_id='approved-user', device_id='device-a', resource_id='resource-2', action='DOWNLOAD',
            permitted_deviations=['bulk_export'], maximum_download_mb=window['sensitive_download_mb'],
            issued_at=message.issued_at, expires_at=message.issued_at+timedelta(seconds=60), window_evidence_sha256=window['evidence_sha256'])
        proof = sign(context, self.business)
        authorities = self.approvals.current()[0]
        partial = SubjectApprovalVerifier(tuple(replace(a, device_ids=frozenset({'device-a'})) for a in authorities.authorities.values()))
        rejected = self.receive(message, approval=proof, detector=SubjectShadowDetector(temporal_store=self.store, approval_verifier=partial))
        require(rejected['signed_window_context_status'] == 'rejected'
            and 'CUMULATIVE_SIGNED_SENSITIVE_DOWNLOAD' in rejected['reason_codes'], 'partial_device_scope_allowed')
        self.counts['partial_device_approvals_rejected'] += 1
        approved = self.receive(message, approval=proof)
        require(not approved['detected'] and approved['signed_window_context_status'] == 'verified', 'approved_job_failed')
        self.counts['approved_fixture_jobs'] += 1

    def crash(self, phase):
        message = self.message('worker-user', 'worker-'+phase)
        atomic(self.root/'worker-input.json', message.model_dump_json().encode())
        process = subprocess.run([sys.executable, '-m', 'scripts.run_f1_subject_soak', 'worker', '--directory', str(self.root),
            '--phase', phase], capture_output=True, timeout=30, check=False)
        require(process.returncode == 73, 'worker_exit_not_observed')
        self.receive(message)
        self.counts['worker_exits_recovered'] += 1

    def cycle(self, index):
        if index % 45 == 0:
            risk = self.message('access-user', 'risk-'+str(index), device='risk-device', posture='at_risk')
            self.receive(risk)
            self.risk_at = risk.event.timestamp
            self.counts['risk_episodes'] += 1
        main = self.message('access-user', 'access-'+str(index), device='access-device')
        result = self.receive(main)
        window = result['temporal_evidence']
        risk_active = datetime.fromisoformat(window['as_of'])-self.risk_at < timedelta(seconds=600)
        require(('RECENT_AT_RISK_DEVICE' in result['reason_codes']) == risk_active, 'risk_expiry_disagrees')
        require(window['sensitive_download_mb'] == 0, 'foreign_volume_leaked')
        self.counts['expired_risk_observations'] += not risk_active
        if index % 20 == 0:
            self.approved_job(index)
        if index % 40 == 0:
            for part in range(3):
                result = self.receive(self.message('export-user', f'export-{index}-{part}', action='DOWNLOAD',
                    device='device-b' if part == 0 else 'device-a', resource=part, volume=200))
            require('CUMULATIVE_SIGNED_SENSITIVE_DOWNLOAD' in result['reason_codes'], 'split_export_missed')
            self.counts['unapproved_export_episodes'] += 1
        if index % 60 == 0:
            for part in range(3):
                result = self.receive(self.message('auth-user', f'auth-{index}-{part}', action='LOGIN', failure=True))
            require('REPEATED_SIGNED_FAILED_LOGIN_EVENTS' in result['reason_codes'], 'split_auth_missed')
            self.counts['failed_login_episodes'] += 1
        if index % 90 == 0:
            for part in range(8):
                result = self.receive(self.message('fanout-user', f'fanout-{index}-{part}', resource=part))
            require('CUMULATIVE_SIGNED_RESOURCE_FANOUT' in result['reason_codes'], 'split_fanout_missed')
            self.counts['fanout_episodes'] += 1
        if index % 10 == 0:
            self.receive(main)
            bad = main.model_copy(update={'signature': 'B'*86})
            try:
                self.store.observe(bad, PRINCIPAL, now=datetime.now(UTC))
            except TemporalUnavailable:
                self.counts['negative_probes_rejected'] += 1
            else:
                raise ValueError('subject_soak_bad_signature_accepted')
            foreign = self.message('other-user', 'other-'+str(index), action='DOWNLOAD', volume=900)
            self.receive(foreign, principal=replace(PRINCIPAL, subject='other-fixture-analyst'))
            summary = self.store.summary(main.session_id, PRINCIPAL, now=datetime.now(UTC))
            require(foreign.event.event_id not in summary['event_ids'] and summary['sensitive_download_mb'] == 0, 'isolation_failed')
            self.counts['isolation_probes'] += 1
        if index in CRASHES:
            self.crash(CRASHES[index])
        witness = json.loads((self.root/'control/witness.json').read_bytes())['state']
        require(witness['pending'] is None and witness['current']['seq'] == self.counts['accepted_unique_events'], 'journal_count')
        return {'cycle': index, **self.counts, 'journal_seq': witness['current']['seq'], 'journal_sha256': witness['current']['hash']}


def worker(root, phase):
    store = store_for(root)
    def fault(name):
        if name == phase:
            os._exit(73)
    store._phase = fault
    message = SignedSessionSignal.model_validate_json((root/'worker-input.json').read_bytes())
    store.observe(message, PRINCIPAL, now=datetime.now(UTC))


def run(directory, until, *, interval=30, maximum_cycles=1000):
    start = datetime.now(UTC)
    require(get_settings().app_environment in {'local', 'test'}, 'local_test_only')
    require(isinstance(until, datetime) and until.tzinfo is not None and start < until <= start+timedelta(hours=6)
            and type(interval) is int and 1 <= interval <= 300 and type(maximum_cycles) is int and 1 <= maximum_cycles <= 1000, 'run_bounds')
    directory = Path(directory)
    require(not directory.exists() and not directory.is_symlink(), 'fresh_output_required')
    directory.mkdir(parents=True)
    captured = {name: hashlib.sha256((ROOT/name).read_bytes().replace(b'\r\n', b'\n')).hexdigest() for name in SOURCE_FILES}
    report = {'schema': 'f1-subject-soak-1', 'started_at': start.isoformat(), 'until': until.isoformat(),
        'completed': False, 'cycles': 0, 'interval_seconds': interval, 'source_files_lf_sha256': captured,
        'new_independent_evaluation': False, 'goal_qualified': False, 'actual_organization_approvals': 0,
        'independent_review': 'pending', 'paid_api_calls': 0, 'cloud_calls': 0, 'access_grants': 0, 'session_changes': 0}
    stop = []
    def interrupted(_signal, _frame):
        stop.append(True)
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    monotonic_start = time.monotonic()
    private = None
    try:
        with tempfile.TemporaryDirectory(dir=directory, prefix='.private-') as temp:
            private = Path(temp)
            lab = SubjectSoakLab(private)
            for name in ('sources', 'policies', 'approvals', 'pins'):
                body = (private/(name+'.json')).read_bytes()
                (directory/('public-'+name+'.json')).write_bytes(body)
                print(json.dumps({'public_artifact': {'name': 'public-'+name+'.json', 'bytes': len(body),
                    'sha256': hashlib.sha256(body).hexdigest(), 'encoding': 'base64', 'data': base64.b64encode(body).decode()}}), flush=True)
            while not stop and report['cycles'] < maximum_cycles and datetime.now(UTC) < until:
                require(time.monotonic()-monotonic_start <= 6*3600+interval, 'monotonic_limit')
                heartbeat = {**lab.cycle(report['cycles']), 'at_utc': datetime.now(UTC).isoformat()}
                with (directory/'heartbeats.jsonl').open('ab') as stream:
                    stream.write(canonical(heartbeat)+b'\n')
                print(json.dumps({'public_heartbeat': heartbeat}), flush=True)
                report['cycles'] += 1
                report['final_counters'] = heartbeat
                time.sleep(max(0, min(interval, (until-datetime.now(UTC)).total_seconds())))
            report['stop_reason'] = 'interrupted' if stop else 'deadline' if datetime.now(UTC) >= until else 'cycle_limit'
            report['completed'] = report['stop_reason'] == 'deadline'
    except (ValueError, TypeError, OSError, subprocess.SubprocessError) as error:
        report['failure_type'] = type(error).__name__
        report['failure_code'] = str(error) if type(error) is ValueError and str(error).startswith('subject_soak_') else 'subject_soak_runtime_failed'
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        report['ended_at'] = datetime.now(UTC).isoformat()
        report['duration_seconds'] = time.monotonic()-monotonic_start
        report['private_runtime_remaining'] = bool(private and private.exists())
        report['source_snapshot_unchanged'] = captured == {name: hashlib.sha256((ROOT/name).read_bytes().replace(b'\r\n', b'\n')).hexdigest() for name in captured}
        report['public_artifact_sha256'] = {name.name: hashlib.sha256(name.read_bytes()).hexdigest() for name in directory.iterdir() if name.is_file()}
        report['completed'] = report['completed'] and not report['private_runtime_remaining'] and report['source_snapshot_unchanged']
        (directory/'status.json').write_text(json.dumps(report, sort_keys=True, indent=2)+'\n', encoding='utf8')
        print(json.dumps(report), flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('run', 'worker'))
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--until')
    parser.add_argument('--interval', type=int, default=30)
    parser.add_argument('--maximum-cycles', type=int, default=1000)
    parser.add_argument('--phase', choices=tuple(CRASHES.values()))
    args = parser.parse_args()
    if args.mode == 'worker':
        require(args.phase is not None, 'worker_phase_required')
        worker(args.directory, args.phase)
        return 1
    require(args.until is not None, 'until_required')
    return 0 if run(args.directory, datetime.fromisoformat(args.until), interval=args.interval, maximum_cycles=args.maximum_cycles)['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
