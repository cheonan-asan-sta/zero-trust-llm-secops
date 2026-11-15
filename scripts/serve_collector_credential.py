"""Bounded private Unix provider; assigned runtime key arrives only over stdin.

Use a trusted launcher and a dedicated service UID. The CLI does not retrieve
keys, issue authority, accept remote requests or persist private key material.
"""

import argparse
import ctypes
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

from scripts.f1_lab.collector_security import current_security_status
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.systemd_credentials import CredentialSocket


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True, type=Path)
    parser.add_argument('--allowed-uid', required=True, type=int)
    parser.add_argument('--maximum-connections', type=int, default=32)
    parser.add_argument('--lifetime-seconds', type=int, default=300)
    identity = parser.add_mutually_exclusive_group(required=True)
    identity.add_argument('--allowed-service-unit')
    identity.add_argument('--local-uid-only-fixture', action='store_true')
    args = parser.parse_args()
    stopped = threading.Event()
    try:
        require(os.name == 'posix' and 1 <= args.lifetime_seconds <= 600, 'provider_lifetime')
        # Per-process setting only; no host ptrace/audit policy changes.
        libc = ctypes.CDLL(None, use_errno=True)
        require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0,
                'provider_nondumpable')
        raw = sys.stdin.buffer.read(33)
        require(len(raw) == 32, 'provider_assigned_key_size')
        sys.stdin.close()
        for number in (signal.SIGTERM, signal.SIGINT):
            signal.signal(number, lambda *_: stopped.set())
        verifier = None
        if args.allowed_service_unit:
            from pydantic import TypeAdapter

            from scripts.f1_lab.credential_peer_service import peer_service
            from scripts.f1_lab.shared_execution_evidence import Unit

            allowed_unit = TypeAdapter(Unit).validate_python(args.allowed_service_unit)
            verifier = lambda connection: peer_service(connection, allowed_unit)
        with CredentialSocket(args.socket, lambda: raw, allowed_uid=args.allowed_uid,
                              maximum_connections=args.maximum_connections, peer_validator=verifier) as provider:
            print(json.dumps({'ready': True, 'worker_security': current_security_status(),
                              'peer_authorization_basis': 'systemd_main_process' if verifier else 'uid_only_local_fixture',
                              'private_key_persisted': False, 'dumpable': False}), flush=True)
            deadline = time.monotonic()+args.lifetime_seconds
            while not stopped.is_set() and provider.thread.is_alive() and time.monotonic() < deadline:
                stopped.wait(0.1)
            print(json.dumps({'completed': True, 'delivered': provider.delivered,
                              'rejected': provider.rejected, 'last_rejection_code': provider.last_rejection_code,
                              'last_rejection_phase': provider.last_rejection_phase,
                              'private_key_persisted': False}), flush=True)
        return 0
    except (ValueError, OSError, TypeError, RuntimeError):
        print(json.dumps({'ready': False, 'completed': False, 'private_key_persisted': False}), flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
