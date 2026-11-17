"""Local operator-only typed backup/review CLI. No launch or activation command."""

import argparse
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from cryptography.exceptions import InvalidSignature, InvalidTag

from app.services.policy_journal import JournalLimits
from app.services.zero_trust import POLICY_PATH, ZeroTrustOperations
from app.zero_trust_models import ZeroTrustPolicyBundle
from scripts.f1_lab.capture_archive import ArchiveScope
from scripts.f1_lab.capture_backup import private_file
from scripts.f1_lab.exec_bundle_backup import ExecutionRecoveryBundle
from scripts.f1_lab.exec_intent import ExecIntentJournal
from scripts.f1_lab.service_caller_identity import PinnedCallerRegistry
from scripts.f1_lab.shared_execution_evidence import PinnedServiceRegistry


class BrokerSnapshotSource:
    """Pre-existing DB fence only. No key, issue, dispatch or grant API."""

    def __init__(self, path, service_pin, caller_pin):
        self.path = Path(path)
        self.registry = caller_pin
        self.joiner = SimpleNamespace(registry=service_pin)

    @contextmanager
    def connect(self):
        private_file(self.path, 16*1024**2)
        con = sqlite3.connect(self.path.as_uri()+'?mode=rw', uri=True, timeout=5)
        try:
            con.execute('PRAGMA trusted_schema=OFF')
            with con:
                yield con
        finally:
            con.close()


class AppSnapshotSource:
    """Use the app's existing validation transaction, without initialization."""

    def __init__(self, path, policy):
        self.path = Path(path)
        self.journal_limits = JournalLimits()
        # Policy files are local administrator configuration, not credentials.
        with Path(policy).open('rb') as stream:
            raw = stream.read(1024*1024+1)
        if len(raw) > 1024*1024:
            raise ValueError('policy size')
        parsed = ZeroTrustPolicyBundle.model_validate_json(raw)
        self.policy_digest = hashlib.sha256(parsed.model_dump_json().encode()).hexdigest()

    def _transaction(self):
        private_file(self.path, 16*1024**2)
        return ZeroTrustOperations._transaction(self)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('backup', 'restore', 'verify'):
        command = commands.add_parser(name)
        for field in ('tenant', 'server', 'unit', 'source', 'registry-sha256', 'caller-registry-sha256'):
            command.add_argument('--'+field, required=True)
        for field in ('registry', 'caller-registry', 'checkpoint'):
            command.add_argument('--'+field, required=True, type=Path)
        command.add_argument('--caller-environment', choices=('oidc', 'local_oidc'), default='oidc')
        if name in {'backup', 'restore'}:
            command.add_argument('--key-file', required=True, type=Path)
            command.add_argument('--key-id', required=True)
            command.add_argument('--output', required=True, type=Path)
        if name == 'backup':
            for field in ('intents', 'broker-db', 'app-db'):
                command.add_argument('--'+field, required=True, type=Path)
            command.add_argument('--worker-directory', required=True, action='append', type=Path)
            command.add_argument('--app-policy', type=Path, default=POLICY_PATH)
        else:
            command.add_argument('--checkpoint-sha256', required=True)
        if name == 'restore':
            command.add_argument('--package', required=True, type=Path)
        if name == 'verify':
            command.add_argument('--review', required=True, type=Path)
            command.add_argument('--receipt-sha256', required=True)
    args = parser.parse_args()
    try:
        scope = ArchiveScope(tenant_id=args.tenant, server_id=args.server, unit=args.unit, source_id=args.source)
        service = PinnedServiceRegistry(args.registry, args.registry_sha256)
        caller = PinnedCallerRegistry(args.caller_registry, args.caller_registry_sha256,
                                      expected_environment=args.caller_environment)
        manager = ExecutionRecoveryBundle(scope, service, caller)
        if args.command == 'verify':
            result = manager.verify_review(args.review, args.receipt_sha256,
                                            args.checkpoint, args.checkpoint_sha256)
        else:
            key = private_file(args.key_file, 32)
            if args.command == 'restore':
                result = manager.restore(args.package, args.output, args.checkpoint,
                                          args.checkpoint_sha256, key, args.key_id)
            else:
                result = manager.backup(ExecIntentJournal(args.intents, service, caller),
                    BrokerSnapshotSource(args.broker_db, service, caller),
                    AppSnapshotSource(args.app_db, args.app_policy), args.worker_directory,
                    args.output, args.checkpoint, key, args.key_id)
        print(json.dumps(result))
        return 0
    except (ValueError, TypeError, KeyError, OSError, sqlite3.Error, RuntimeError, InvalidSignature, InvalidTag):
        # Do not dump tokens, private paths, signed raw state or recovery keys.
        print(json.dumps({'completed': False, 'state': 'unavailable',
                          'automatic_execution_allowed': False, 'automatic_activation_allowed': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
