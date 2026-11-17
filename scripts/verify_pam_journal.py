"""Keyless verification of one explicitly pinned PAM observation capture."""

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from scripts.f1_lab.collector_freshness import CollectorScope
from scripts.f1_lab.collector_security import current_security_status
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.pam_journal import PamCapture, verify
from scripts.f1_lab.shared_execution_evidence import PinnedServiceRegistry


def read_pinned(path, expected_sha256):
    require(os.name == 'posix', 'pam_pinned_file_linux')
    require(type(expected_sha256) is str and re.fullmatch('[a-f0-9]{64}', expected_sha256), 'pam_capture_pin')
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 4*1024**2,
                'pam_capture_file')
        raw = stream.read(4*1024**2+1)
        after = os.fstat(stream.fileno())
        require(len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == expected_sha256
            and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'pam_capture_changed')
    return PamCapture.model_validate(decode(raw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('tenant', 'server', 'unit', 'source', 'key-id', 'registry', 'registry-sha256',
                 'capture', 'capture-sha256', 'boot-id', 'invocation-id'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    try:
        scope = CollectorScope(tenant_id=args.tenant, server_id=args.server, unit=args.unit,
                               source_id=args.source, key_id=args.key_id)
        pinned = PinnedServiceRegistry(args.registry, args.registry_sha256)
        capture = read_pinned(args.capture, args.capture_sha256)
        verify(capture, scope, pinned, boot=args.boot_id, invocation=args.invocation_id)
        print(json.dumps({'completed': True,
            'state': 'verified_observation' if capture.records else 'verified_capture_no_pam_observations',
            'records': len(capture.records), 'rejections': capture.rejections.model_dump(),
            'window_start_us': capture.window_start_us, 'window_end_us': capture.window_end_us,
            'human_authenticated': False, 'process_lifetime_identity_verified': False,
            'authorization_asserted': False, 'automatic_enforcement_allowed': False,
            'worker_security': current_security_status()}))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        print(json.dumps({'completed': False, 'state': 'unavailable', 'human_authenticated': False,
                          'authorization_asserted': False, 'automatic_enforcement_allowed': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
