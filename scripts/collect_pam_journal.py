"""Collect only local sudo PAM provenance with an authentication-purpose key."""

import argparse
import ctypes
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts.f1_lab.collector_freshness import CollectorScope
from scripts.f1_lab.collector_security import current_security_status
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.pam_journal import authority, build, micros, verify
from scripts.f1_lab.pam_journal_native import journal_rows, private_parent, unit_invocation
from scripts.f1_lab.shared_execution_evidence import PinnedServiceRegistry
from scripts.f1_lab.systemd_credential_reader import read_systemd_key

SAFE_FAILURES = {'native_source_'+name for name in (
    'pam_native_systemd', 'pam_manager_unavailable', 'pam_manager_shape', 'pam_manager_unit',
    'pam_manager_invocation', 'pam_authority_role', 'pam_authority_scope', 'pam_journal_timeout',
    'pam_journal_bytes', 'pam_journal_row_bytes', 'pam_journal_partial_row_bytes', 'pam_journal_partial_row',
    'pam_journal_truncated', 'pam_journal_exit', 'pam_capture_window', 'pam_population',
    'pam_record_order_or_window', 'pam_export_cursor', 'pam_collection_completion_time',
    'pam_trust_or_clock_changed', 'pam_invocation_changed', 'pam_private_output_parent',
    'service_registry_hash', 'service_registry_window', 'service_authority_separation')}


def collect(scope, pinned, key, *, lookback_seconds=60, clock=lambda: datetime.now(UTC)):
    require(type(lookback_seconds) is int and 1 <= lookback_seconds <= 600, 'pam_lookback')
    start = clock()
    registry = pinned.current(start)
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    authority(registry, scope, start, public_key=public)
    boot, invocation = unit_invocation(scope.unit)
    end_us, start_us = micros(start), micros(start-timedelta(seconds=lookback_seconds))
    rows = list(journal_rows(scope.unit, start_us, end_us))
    require(unit_invocation(scope.unit) == (boot, invocation), 'pam_invocation_changed')
    checked = clock()
    require(checked >= start and pinned.current(checked) == registry, 'pam_trust_or_clock_changed')
    capture = build(rows, scope, pinned, key, boot=boot, invocation=invocation,
        window_start_us=start_us, window_end_us=end_us, now=checked)
    verify(capture, scope, pinned, boot=boot, invocation=invocation, now=clock())
    finished = clock()
    require(checked <= finished < capture.expires_at and pinned.current(finished) == registry,
            'pam_collection_completion_time')
    authority(registry, scope, finished, public_key=public)
    return capture


def publish(capture, output):
    output = Path(output)
    private_parent(output.parent)
    require(not output.exists() and not output.is_symlink(), 'pam_fresh_output')
    output.mkdir(mode=0o700)
    raw = canonical(capture.model_dump(mode='json'))+b'\n'
    require(len(raw) <= 4*1024**2, 'pam_capture_bytes')
    descriptor = os.open(output/'capture.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    receipt = {'schema': 'pam-journal-acquisition-receipt-1', 'capture_sha256': hashlib.sha256(raw).hexdigest(),
        'records': len(capture.records), 'journal_rows_seen': capture.journal_rows_seen,
        'human_authenticated': False, 'authorization_asserted': False}
    descriptor = os.open(output/'receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(canonical(receipt)+b'\n')
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('tenant', 'server', 'unit', 'source', 'key-id', 'registry', 'registry-sha256', 'output'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--lookback-seconds', type=int, default=60)
    parser.add_argument('--systemd-credential', action='store_true')
    args = parser.parse_args()
    stage = 'scope'
    try:
        require(os.name == 'posix', 'pam_linux_only')
        libc = ctypes.CDLL(None, use_errno=True)
        require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0,
                'pam_nondumpable')
        scope = CollectorScope(tenant_id=args.tenant, server_id=args.server, unit=args.unit,
                               source_id=args.source, key_id=args.key_id)
        pinned = PinnedServiceRegistry(args.registry, args.registry_sha256)
        stage = 'credential'
        raw = read_systemd_key(credential_name='auth-journal-key') if args.systemd_credential else sys.stdin.buffer.read(33)
        require(len(raw) == 32, 'pam_key_size')
        key = Ed25519PrivateKey.from_private_bytes(raw)
        stage = 'native_collection'
        capture = collect(scope, pinned, key, lookback_seconds=args.lookback_seconds)
        stage = 'publication'
        receipt = publish(capture, Path(args.output))
        print(json.dumps({'completed': True, **receipt, 'worker_security': current_security_status(),
                          'private_key_written_to_output': False, 'raw_message_or_argv_in_capture': False,
                          'key_input_kind': 'systemd_memory_credential' if args.systemd_credential else 'stdin_pipe',
                          'dumpable': False}))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({'completed': False, 'failure_stage': stage,
                          'failure_code': str(error) if type(error) is ValueError and str(error) in SAFE_FAILURES else None,
                          'failure_category': ('io_denied' if isinstance(error, PermissionError) else
                            'timeout' if isinstance(error, subprocess.TimeoutExpired) else
                            'io' if isinstance(error, OSError) else 'validation'),
                          'human_authenticated': False, 'authorization_asserted': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
