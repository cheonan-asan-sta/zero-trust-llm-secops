"""Predeclared controlled session fixtures; labels never come from detector output.

These are functional regression controls, not a blind enterprise dataset. The
operator plans are simulated issuance inputs, never proof of real organizational approval.
"""

import argparse
import hashlib
import json
import random
import tempfile
from collections import Counter
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path
from typing import Annotated

from pydantic import Field

from app.models import SecurityEvent, StrictModel

RULES = {
    'credential': '8a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d',
    'device': '9b2c3d4e-5f60-4b7c-9d8e-9f0a1b2c3d4e',
    'privilege': 'ac3d4e5f-6071-4c8d-ae9f-0a1b2c3d4e5f',
    'lateral': 'bd4e5f60-7182-4d9e-bf0a-1b2c3d4e5f60',
    'exfiltration': 'ce5f6071-8293-4eaf-801b-2c3d4e5f6071',
    'remote': 'd1e2f3a4-b5c6-4d7e-8f90-a1b2c3d4e5f6',
}
FILES = ('inputs.jsonl', 'labels.jsonl', 'operator-plans.jsonl', 'NOTICE.md')
CaseID = Annotated[str, Field(pattern=r'^case-[a-f0-9]{20}$')]


class ControlledSession(StrictModel):
    case_id: CaseID
    session_id: str = Field(pattern=r'^session-[a-f0-9]{20}$')
    tenant_id: str = Field(pattern=r'^controlled-lab$')
    events: list[SecurityEvent] = Field(min_length=1, max_length=50)


class ControlledLabel(StrictModel):
    case_id: CaseID
    family_id: str = Field(min_length=3, max_length=100)
    threat: bool = Field(strict=True)
    expected_rule_ids: list[str] = Field(max_length=6)
    variant: int = Field(strict=True, ge=0, le=7)
    label_source: str = Field(pattern=r'^predeclared_controlled_operation_not_detector_output$')


class OperatorPlan(StrictModel):
    case_id: CaseID
    issuer_group: str = Field(min_length=3, max_length=100)
    permitted_deviations: list[str] = Field(min_length=1, max_length=6)
    maximum_window_download_mb: float = Field(ge=0, allow_inf_nan=False)
    approval_source: str = Field(pattern=r'^simulated_operator_plan_not_real_organizational_approval$')


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def specifications():
    # A specification is an authored operation and intent. No classifier is imported.
    return [
        ('slow-failed-login', True, ['credential'], 'failure', 4, 30, {}, None),
        ('distributed-failed-login', True, ['credential'], 'failure_distributed', 4, 35, {}, None),
        ('critical-split-export', True, ['exfiltration'], 'download', 5, 120, {'resource.sensitivity': 'critical'}, None),
        ('high-split-export', True, ['exfiltration'], 'download_high', 4, 130, {'resource.sensitivity': 'high'}, None),
        ('slow-read-traversal', True, ['lateral'], 'fanout', 9, 50, {}, None),
        ('fast-read-traversal', True, ['lateral'], 'fanout', 9, 5, {'behavior.request_rate': 'high'}, None),
        ('recent-device-compromise', True, ['device'], 'compromised_then_healthy', 2, 20, {}, None),
        ('known-adverse-device', True, ['device'], 'read', 2, 10, {'device.security_posture': 'at_risk'}, None),
        ('inactive-identity', True, ['credential'], 'read', 2, 10, {'user.active': False}, None),
        ('rejected-mfa', True, ['credential'], 'login', 2, 10,
            {'auth_context.mfa': 'failed', 'auth_context.failed_attempts': 1,
             'auth_context.authentication_result': 'failure'}, None),
        ('admin-role-violation', True, ['privilege'], 'admin', 2, 10, {'resource.required_role': 'administrator'}, None),
        ('download-role-violation', True, ['privilege'], 'small_download', 2, 10,
            {'user.role': 'viewer', 'resource.required_role': 'administrator'}, None),
        ('unapproved-remote', True, ['remote'], 'remote', 2, 10, {}, None),
        ('unverified-remote-context', True, ['remote'], 'read', 2, 10,
            {'network.access_method': 'remote', 'auth_context.mfa': 'unknown'}, None),
        ('new-unknown-endpoint', True, ['device'], 'read', 2, 10,
            {'device.managed': False, 'device.security_posture': 'unknown', 'behavior.new_device': True}, None),
        ('business-approval-with-compromise', True, ['device'], 'remote', 2, 10,
            {'device.security_posture': 'compromised'}, ['remote_access']),
        ('business-approval-with-inactive-user', True, ['credential'], 'remote', 2, 10,
            {'user.active': False}, ['remote_access']),
        ('business-approval-with-rejected-mfa', True, ['credential'], 'remote', 2, 10,
            {'auth_context.mfa': 'failed', 'auth_context.failed_attempts': 1,
             'auth_context.authentication_result': 'failure'}, ['remote_access']),
        ('bounded-typing-errors', False, [], 'failure', 2, 30, {}, None),
        ('normal-authentication', False, [], 'login', 4, 30, {}, None),
        ('bounded-sensitive-transfer', False, [], 'small_download', 4, 100,
            {'resource.sensitivity': 'critical'}, None),
        ('public-export', False, [], 'large_download', 2, 30, {'resource.sensitivity': 'public'}, None),
        ('internal-report-export', False, [], 'large_download', 2, 30, {'resource.sensitivity': 'internal'}, None),
        ('approved-critical-backup', False, [], 'backup', 5, 90, {'resource.sensitivity': 'critical'}, ['bulk_export']),
        ('approved-load-drill', False, [], 'failure', 5, 30, {}, ['authentication_failure']),
        ('approved-report-fanout', False, [], 'fanout', 10, 15,
            {'behavior.request_rate': 'high'}, ['resource_fanout']),
        ('approved-remote-support', False, [], 'remote', 3, 30, {}, ['remote_access']),
        ('healthy-registered-byod', False, [], 'read', 3, 30,
            {'device.managed': False, 'behavior.new_device': True}, None),
        ('role-matched-administration', False, [], 'admin', 3, 30,
            {'user.role': 'administrator', 'resource.required_role': 'administrator'}, None),
        ('off-hours-local-login', False, [], 'login', 3, 30, {'behavior.unusual_time': True}, None),
        ('approved-endpoint-enrollment', False, [], 'read', 3, 30,
            {'device.managed': False, 'device.security_posture': 'unknown', 'behavior.new_device': True},
            ['new_unmanaged_device']),
        ('approved-emergency-role', False, [], 'admin', 2, 30,
            {'resource.required_role': 'administrator'}, ['role_mismatch']),
    ]


def _set(raw, name, value):
    parts = name.split('.')
    target = raw
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value


def build(*, variants=3, seed=20261112):
    if type(variants) is not int or not 1 <= variants <= 8 or type(seed) is not int:
        raise ValueError('controlled_session_parameters')
    plans = [(spec, variant) for spec in specifications() for variant in range(variants)]
    random.Random(seed).shuffle(plans)
    inputs, labels, operators = [], [], []
    for ordinal, (spec, variant) in enumerate(plans):
        name, threat, domains, kind, count, interval, patch, approved_deviations = spec
        opaque = sha(canonical(['f1-controlled-session-1', seed, ordinal]))[:20]
        case_id, session_id = 'case-'+opaque, 'session-'+opaque
        start = datetime(2026, 11, 12, tzinfo=UTC)+timedelta(seconds=ordinal*1800)
        events = []
        for index in range(count):
            action = ('LOGIN' if kind.startswith('failure') or kind == 'login' else 'DOWNLOAD'
                      if 'download' in kind or kind in {'backup'} else 'ADMIN' if kind == 'admin'
                      else 'REMOTE_ACCESS' if kind == 'remote' else 'READ')
            event_id = 'evt-'+sha(canonical([opaque, index]))[:24]
            raw = {'event_id': event_id, 'timestamp': (start+timedelta(seconds=index*interval)).isoformat(),
                'user': {'user_id': 'user-'+opaque, 'role': 'employee', 'department': 'controlled-lab', 'active': True},
                'device': {'device_id': 'device-'+opaque, 'managed': True, 'security_posture': 'healthy'},
                'network': {'ip': '192.0.2.'+str(1+(ordinal+index if kind.endswith('distributed') else ordinal)%250),
                            'location': 'controlled-lab', 'access_method': 'remote' if kind == 'remote' else 'office',
                            'location_anomaly': False},
                'resource': {'resource_id': 'resource-'+opaque+('-'+str(index) if kind == 'fanout' else ''),
                             'resource_type': 'document', 'sensitivity': 'internal', 'required_role': 'employee'},
                'action': action, 'auth_context': {'authentication_result': 'failure' if kind.startswith('failure') else 'success',
                    'mfa': 'success', 'failed_attempts': 1 if kind.startswith('failure') else 0, 'session_age_minutes': index},
                'behavior': {'new_device': False, 'unusual_time': False, 'request_rate': 'normal',
                    'download_volume_mb': (110+variant if kind == 'download' else 135+variant if kind == 'download_high'
                        else 150+variant if kind == 'backup' else 50+variant if kind == 'small_download'
                        else 2000+variant if kind == 'large_download' else 0),
                    'distinct_resources_10m': index+1 if kind == 'fanout' else 1,
                    'policy_exception_approved': False, 'policy_exception': None, 'event_text': None}}
            if kind == 'compromised_then_healthy' and index == 0:
                raw['device']['security_posture'] = 'compromised'
            for field, value in patch.items():
                _set(raw, field, value)
            events.append(SecurityEvent.model_validate(raw).model_dump(mode='json', exclude={'ground_truth'}))
        inputs.append({'case_id': case_id, 'session_id': session_id, 'tenant_id': 'controlled-lab', 'events': events})
        labels.append({'case_id': case_id, 'family_id': name, 'threat': threat,
                       'expected_rule_ids': sorted(RULES[d] for d in domains), 'variant': variant,
                       'label_source': 'predeclared_controlled_operation_not_detector_output'})
        if approved_deviations:
            operators.append({'case_id': case_id, 'issuer_group': name,
                'permitted_deviations': approved_deviations,
                'maximum_window_download_mb': sum(e['behavior']['download_volume_mb'] for e in events),
                'approval_source': 'simulated_operator_plan_not_real_organizational_approval'})
    return inputs, labels, operators


def prepare(directory, *, variants=3, seed=20261112):
    if directory.exists() or directory.is_symlink():
        raise ValueError('controlled_fresh_directory_required')
    inputs, labels, operators = build(variants=variants, seed=seed)
    data = {name: b''.join(canonical(row)+b'\n' for row in rows) for name, rows in (
        ('inputs.jsonl', inputs), ('labels.jsonl', labels), ('operator-plans.jsonl', operators))}
    data['NOTICE.md'] = (b'# Controlled signed-session regression fixtures\n\n'
        b'Authored for local functional tests under the repository MIT license. '\
        b'These are not enterprise logs, blind data or actual business approvals. '\
        b'The labels precede inference; input IDs are opaque and source clocks are virtual.\n')
    manifest = {'schema': 'f1-controlled-sessions-1', 'metric_unit': 'session_any_alert',
        'source_kind': 'authored_controlled_regression', 'independent_review': 'pending',
        'new_independent_evaluation': False, 'variants_per_family': variants, 'seed': seed,
        'family_count': len(specifications()), 'sessions': len(inputs),
        'normal': sum(not row['threat'] for row in labels), 'threat': sum(row['threat'] for row in labels),
        'time_mode': 'explicit_controlled_virtual_clock',
        'generator_sha256': sha(Path(__file__).read_bytes().replace(b'\r\n', b'\n')),
        'files': {name: sha(raw) for name, raw in data.items()}}
    raw = canonical(manifest)+b'\n'
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory.parent, prefix='.session-controls-') as temp:
        stage = Path(temp) / 'dataset'
        stage.mkdir()
        for name, body in data.items():
            (stage / name).write_bytes(body)
        (stage / 'manifest.json').write_bytes(raw)
        verify(stage, sha(raw))
        stage.rename(directory)
    return {'manifest_sha256': sha(raw), 'sessions': len(inputs), 'families': len(specifications()),
            'independent_review': 'pending', 'new_independent_evaluation': False}


def verify(directory, anchor):
    path = directory / 'manifest.json'
    if directory.is_symlink() or not path.is_file() or path.is_symlink() or path.stat().st_size > 65536:
        raise ValueError('controlled_manifest_file')
    raw = (directory / 'manifest.json').read_bytes()
    if sha(raw) != anchor:
        raise ValueError('controlled_manifest_anchor')
    manifest = json.loads(raw)
    if (manifest.get('schema') != 'f1-controlled-sessions-1' or manifest.get('independent_review') != 'pending'
            or manifest.get('new_independent_evaluation') is not False or set(manifest['files']) != set(FILES)
            or {p.name for p in directory.iterdir()} != {*FILES, 'manifest.json'}):
        raise ValueError('controlled_dataset_contract')
    for name, expected in manifest['files'].items():
        path = directory / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 16*1024**2 or sha(path.read_bytes()) != expected:
            raise ValueError('controlled_dataset_hash')
    inputs = [ControlledSession.model_validate_json(line) for line in (directory / 'inputs.jsonl').read_bytes().splitlines()]
    labels = [ControlledLabel.model_validate_json(line) for line in (directory / 'labels.jsonl').read_bytes().splitlines()]
    plans = [OperatorPlan.model_validate_json(line) for line in (directory / 'operator-plans.jsonl').read_bytes().splitlines()]
    identities = {row.case_id for row in inputs}
    if (len(identities) != len(inputs) or len({row.case_id for row in labels}) != len(labels)
            or {row.case_id for row in labels} != identities or len(inputs) != manifest['sessions']
            or len({row.case_id for row in plans}) != len(plans) or not {row.case_id for row in plans} <= identities
            or len({row.session_id for row in inputs}) != len(inputs)):
        raise ValueError('controlled_population_contract')
    users, devices = set(), set()
    for row in inputs:
        events = row.events
        user, device = events[0].user.user_id, events[0].device.device_id
        if (user in users or device in devices or len({e.event_id for e in events}) != len(events)
                or any(e.ground_truth is not None or e.timestamp.tzinfo is None or e.timestamp.utcoffset() is None
                       or e.user.user_id != user or e.device.device_id != device
                       for e in events) or any(a.timestamp >= b.timestamp for a, b in pairwise(events))):
            raise ValueError('controlled_session_identity_or_order')
        users.add(user)
        devices.add(device)
    if any(not set(row.expected_rule_ids) <= set(RULES.values()) or bool(row.expected_rule_ids) != row.threat for row in labels):
        raise ValueError('controlled_label_contract')
    counts = Counter(row.family_id for row in labels)
    if (sum(row.threat for row in labels) != manifest['threat']
            or sum(not row.threat for row in labels) != manifest['normal']
            or len(counts) != manifest['family_count']
            or any(value != manifest['variants_per_family'] for value in counts.values())):
        raise ValueError('controlled_label_support_contract')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--variants', type=int, default=3)
    parser.add_argument('--seed', type=int, default=20261112)
    args = parser.parse_args()
    print(json.dumps(prepare(args.directory, variants=args.variants, seed=args.seed)))


if __name__ == '__main__':
    main()
