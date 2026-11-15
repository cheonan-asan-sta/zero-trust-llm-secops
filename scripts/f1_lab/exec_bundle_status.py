"""Keyless package + isolated review integrity, never execution authorization."""

import os
import re
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.f1_lab.capture_backup import pinned, private_directory
from scripts.f1_lab.collector_status_bridge import MAX_REPORT, read_public, scope_hash
from scripts.f1_lab.exec_bundle_backup import (
    ExecutionRecoveryBundle,
    checkpoint_file,
    utc,
    validate_manifest,
)
from scripts.f1_lab.exec_bundle_snapshot import MAX_BODY
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical

SCHEMA = 'zt-exec-recovery-bundle-status-1'
REPORT_TTL = 60
COUNTERS = {'intents', 'sealed', 'indeterminate', 'worker_artifacts', 'broker_requests', 'app_entries',
            'encrypted_bytes'}
TIMES = {'snapshot_at', 'backup_at', 'restored_at'}


def validate(value, binding):
    require(type(binding) is str and re.fullmatch('[a-f0-9]{64}', binding), 'exec_bundle_status_scope')
    require(type(value) is dict and set(value) == {'schema', 'scope_sha256', 'checked_at', 'state',
            'values', 'automatic_activation_allowed', 'automatic_execution_allowed', 'authorization_asserted'}
            and value['schema'] == SCHEMA and value['scope_sha256'] == binding
            and value['state'] in {'verified', 'unavailable'}
            and all(value[k] is False for k in ('automatic_activation_allowed', 'automatic_execution_allowed',
                                               'authorization_asserted')), 'exec_bundle_status_shape')
    checked = utc(value['checked_at'])
    data = value['values']
    require(type(data) is dict and set(data) == (COUNTERS | TIMES if value['state'] == 'verified' else set()),
            'exec_bundle_status_values')
    if data:
        require(utc(data['snapshot_at']) <= utc(data['backup_at']) <= utc(data['restored_at']) <= checked,
                'exec_bundle_status_chronology')
        require(all(type(data[k]) is int and 0 <= data[k] <= 10000
                    for k in COUNTERS-{'app_entries', 'encrypted_bytes'})
                and type(data['app_entries']) is int and 0 <= data['app_entries'] <= 1100000
                and type(data['encrypted_bytes']) is int and 17 <= data['encrypted_bytes'] <= MAX_BODY+16
                and data['sealed']+data['indeterminate'] == data['intents']
                and data['worker_artifacts'] <= data['intents'], 'exec_bundle_status_counts')
    return checked


def report(scope, values=None, *, now=None):
    value = {'schema': SCHEMA, 'scope_sha256': scope_hash(scope),
             'checked_at': (datetime.now(UTC) if now is None else now).isoformat(),
             'state': 'unavailable' if values is None else 'verified', 'values': {} if values is None else values,
             'automatic_activation_allowed': False, 'automatic_execution_allowed': False,
             'authorization_asserted': False}
    validate(value, value['scope_sha256'])
    return value


def inspect(scope, package, checkpoint, checkpoint_sha256, review, receipt_sha256, service_pin, caller_pin):
    """Hash pinned encrypted bytes and revalidate the already restored snapshot.

    No key is supplied, no decryption or pin renewal is performed. The trusted
    external receipt was issued after the earlier authenticated decryption.
    """
    package, review = private_directory(package), private_directory(review)
    pin = checkpoint_file(checkpoint, checkpoint_sha256, scope)
    require({p.name for p in package.iterdir()} == {'manifest.json', 'payload.aesgcm'},
            'exec_bundle_status_package_inventory')
    manifest = decode(pinned(package/'manifest.json', pin['manifest_sha256'], 16384))
    validate_manifest(manifest, scope)
    require(all(manifest[k] == pin[k] for k in ('scope_sha256', 'snapshot_id', 'created_at',
                                               'snapshot_sha256', 'payload_sha256')),
            'exec_bundle_status_package_checkpoint')
    payload = pinned(package/'payload.aesgcm', pin['payload_sha256'], MAX_BODY+16)
    require(len(payload) == manifest['payload_bytes'], 'exec_bundle_status_payload_bytes')
    receipt = decode(pinned(review/'restore.json', receipt_sha256, 16384))
    summary = ExecutionRecoveryBundle(scope, service_pin, caller_pin).verify_review(
        review, receipt_sha256, checkpoint, checkpoint_sha256)
    require(summary['snapshot_sha256'] == pin['snapshot_sha256']
            and receipt['manifest_sha256'] == pin['manifest_sha256'], 'exec_bundle_status_review_package')
    inventory = decode(pinned(review/'inventory.json', receipt['inventory_sha256'], MAX_BODY))
    # Recheck current pins at completion as well as at the start of reconstruction.
    checked = datetime.now(UTC)
    service_pin.current(checked)
    caller_pin.current(checked)
    values = {k: summary[k] for k in COUNTERS-{'encrypted_bytes'}}
    values.update(encrypted_bytes=manifest['payload_bytes'],
                  snapshot_at=inventory['snapshot_metadata']['created_at'],
                  backup_at=manifest['created_at'], restored_at=receipt['restored_at'])
    return report(scope, values, now=checked)


def publish(path, value):
    path = Path(path)
    checked = validate(value, value['scope_sha256'])
    parent = path.parent.lstat()
    require(path.is_absolute() and not path.is_symlink() and not path.parent.is_symlink()
            and stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
            and not stat.S_IMODE(parent.st_mode) & 0o022, 'exec_bundle_status_public_parent')
    if path.exists():
        require(path.stat().st_uid == os.geteuid()
                and validate(read_public(path), value['scope_sha256']) <= checked,
                'exec_bundle_status_public_clock')
    raw = canonical(value)+b'\n'
    require(len(raw) <= MAX_REPORT, 'exec_bundle_status_public_bound')
    descriptor, temporary = tempfile.mkstemp(prefix='.exec-bundle-status-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            os.fchmod(stream.fileno(), 0o644)
            stream.flush()
            os.fsync(stream.fileno())
        require(not path.is_symlink(), 'exec_bundle_status_public_link')
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_profile(path):
    value = read_public(path)
    require(type(value) is dict and set(value) == {'schema', 'scope_sha256', 'status_file',
            'max_snapshot_age_seconds', 'max_restore_age_seconds'}
            and value['schema'] == 'zt-exec-bundle-metrics-profile-1'
            and type(value['scope_sha256']) is str and re.fullmatch('[a-f0-9]{64}', value['scope_sha256'])
            and type(value['status_file']) is str and 0 < len(value['status_file']) <= 4096
            and Path(value['status_file']).is_absolute(), 'exec_bundle_status_profile')
    for key, maximum in [('max_snapshot_age_seconds', 604800), ('max_restore_age_seconds', 2592000)]:
        require(type(value[key]) is int and 1 <= value[key] <= maximum, 'exec_bundle_status_profile_age')
    return value


def metrics(profile, *, now=None):
    now = datetime.now(UTC) if now is None else now
    rows = ['# TYPE secops_exec_bundle_bridge_enabled gauge', 'secops_exec_bundle_bridge_enabled 1']
    valid = False
    value = None
    try:
        value = read_public(profile['status_file'])
        checked = validate(value, profile['scope_sha256'])
        require(timedelta(0) <= now-checked < timedelta(seconds=REPORT_TTL), 'exec_bundle_status_expired')
        valid = value['state'] == 'verified'
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        pass
    rows.append(f'secops_exec_bundle_status_success {int(valid)}')
    if valid:
        data = value['values']
        for key in sorted(COUNTERS):
            rows.append(f'secops_exec_bundle_{key} {data[key]}')
        snapshot_age = (now-utc(data['snapshot_at'])).total_seconds()
        restore_age = (now-utc(data['restored_at'])).total_seconds()
        recent = snapshot_age <= profile['max_snapshot_age_seconds'] and restore_age <= profile['max_restore_age_seconds']
        rows.extend([f'secops_exec_bundle_snapshot_age_seconds {snapshot_age}',
                     f'secops_exec_bundle_restore_age_seconds {restore_age}',
                     f'secops_exec_bundle_recovery_recent {int(recent)}',
                     f"secops_exec_bundle_indeterminate_retained {int(data['indeterminate'] > 0)}"])
    return '\n'.join(rows)+'\n'
