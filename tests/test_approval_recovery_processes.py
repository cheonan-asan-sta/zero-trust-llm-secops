"""Independent processes contend for restored approval usage and replay lost replies."""

import json
import subprocess
import sys

import pytest

from app.services.behavior_context import BehaviorContextService
from app.services.behavior_context_store import BehaviorContextStore, ContextStoreUnavailable
from scripts import behavior_context_recovery
from tests import test_behavior_context_recovery as recovery_cases
from tests.test_behavior_context_recovery import (
    CONTEXT_NAME,
    access,
    backup,
    fresh_capture,
    restore,
    seed,
)

PROGRAM = """
import json, os, sys
from datetime import datetime
from pathlib import Path
from app.security import Principal, Role
from app.services.behavior_context import BehaviorContextService
from app.services.behavior_context_store import BehaviorContextStore
from app.services.trusted_signals import SignalVerifier
from app.services.zero_trust import ZeroTrustOperations
config = json.loads(sys.argv[1])
root = Path(config['root'])
operations = ZeroTrustOperations(root / 'app.sqlite3', signal_verifier=SignalVerifier(root / 'sources.json'))
service = BehaviorContextService(BehaviorContextStore(root / 'app-behavior-context.sqlite3'), operations)
principal = Principal('independent-reader', 'tenant-a', frozenset({Role.ANALYST}), 'api_key')
print('ready', flush=True)
input()
if config.get('uncommitted_revoke'):
    with service.store.transaction() as transaction:
        if config['uncommitted_revoke'] == 'hot':
            transaction._connection.execute('PRAGMA cache_size=1')
        transaction.put('revocation', 'tenant-a', 'interrupted-revocation',
                        {'target_kind': 'approval', 'target_id': 'approval-a',
                         'reason': 'Interrupted cancellation'}, principal.subject,
                        datetime.fromisoformat(config['now']))
        if config['uncommitted_revoke'] == 'hot':
            for index in range(3):
                transaction.put('capture', 'tenant-a', 'uncommitted-' + str(index),
                                {'padding': 'x' * 50000}, principal.subject,
                                datetime.fromisoformat(config['now']))
        os._exit(73)
result = service.evaluate(config['capture'], principal, now=datetime.fromisoformat(config['now']))
if config['exit']:
    os._exit(config['exit'])
print(json.dumps({k: result[k] for k in ('verdict', 'reason', 'duplicate')}), flush=True)
"""


@pytest.fixture
def recovery_context(tmp_path, monkeypatch):
    return recovery_cases.recovery_context.__wrapped__(tmp_path, monkeypatch)


def start(stage, lab, capture, *, exit_code=0, uncommitted_revoke=False):
    arguments = {'root': str(stage), 'capture': capture.id,
                 'now': lab.at(9).isoformat(), 'exit': exit_code,
                 'uncommitted_revoke': uncommitted_revoke}
    return subprocess.Popen([sys.executable, '-c', PROGRAM, json.dumps(arguments)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)


def finish(process):
    output, error = process.communicate('evaluate\n', timeout=30)
    assert not error, error
    return json.loads(output) if output else None


def test_restored_last_approval_use_is_atomic_between_independent_processes(
    recovery_context, tmp_path, monkeypatch,
):
    lab = recovery_context
    old, _ = seed(lab, max_uses=2)
    restored = restore(backup(lab, tmp_path, monkeypatch, full_state=True), lab)
    assert access(restored, old.session).status_code == 403
    captures = [fresh_capture(restored, lab, name, 7)
                for name in ('competing-first', 'competing-second')]
    processes = []
    try:
        for capture in captures:
            process = start(restored.stage, lab, capture)
            processes.append(process)
            assert process.stdout.readline().strip() == 'ready'
        # Release both after both databases have opened in separate interpreters.
        for process in processes:
            process.stdin.write('evaluate\n')
            process.stdin.flush()
        results = []
        for process in processes:
            output, error = process.communicate(timeout=30)
            assert process.returncode == 0 and not error, error
            results.append(json.loads(output))
        assert sorted(row['verdict'] for row in results) == ['normal', 'unknown']
        restored.service = BehaviorContextService(
            BehaviorContextStore(restored.stage / CONTEXT_NAME), restored.operations,
        )
        for capture, original in zip(captures, results, strict=True):
            replay = restored.service.evaluate(capture.id, lab.analyst, now=lab.at(9))
            assert replay['verdict'] == original['verdict'] and replay['duplicate']
        used = {entry['payload']['capture_id']
                for entry in restored.service.store.read('tenant-a')
                if entry['kind'] == 'evaluation' and entry['payload']['verdict'] == 'normal'}
        assert len(used) == 2
        assert access(restored, old.session).status_code == 403
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)


def test_committed_approval_use_survives_process_exit_before_caller_receives_reply(
    recovery_context, tmp_path, monkeypatch,
):
    lab = recovery_context
    old, _ = seed(lab, max_uses=2)
    restored = restore(backup(lab, tmp_path, monkeypatch), lab)
    capture = fresh_capture(restored, lab, 'lost-response', 7)
    process = start(restored.stage, lab, capture, exit_code=73)
    try:
        assert process.stdout.readline().strip() == 'ready'
        assert finish(process) is None
        assert process.returncode == 73
        # Discard the first result as a transport would; reopen and retry exactly.
        restored.service = BehaviorContextService(
            BehaviorContextStore(restored.stage / CONTEXT_NAME), restored.operations,
        )
        replay = restored.service.evaluate(capture.id, lab.analyst, now=lab.at(9))
        assert replay['verdict'] == 'normal' and replay['duplicate']
        following = fresh_capture(restored, lab, 'after-lost-response', 10)
        assert restored.service.evaluate(following.id, lab.analyst, now=lab.at(10))['verdict'] == 'unknown'
        assert access(restored, old.session).status_code == 403
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)


@pytest.mark.parametrize('journal', ['cold', 'hot'])
def test_process_death_during_revocation_requires_sqlite_recovery_before_snapshot(
    recovery_context, tmp_path, monkeypatch, journal,
):
    lab = recovery_context
    seed(lab, max_uses=2)
    restored = restore(backup(lab, tmp_path, monkeypatch), lab)
    capture = fresh_capture(restored, lab, 'before-interrupted-cancellation', 7)
    before = restored.service.store.read('tenant-a')
    pin = behavior_context_recovery.inspect(restored.stage)
    process = start(restored.stage, lab, capture, uncommitted_revoke=journal)
    try:
        assert process.stdout.readline().strip() == 'ready'
        assert finish(process) is None and process.returncode == 73
        with pytest.raises(ContextStoreUnavailable, match='sidecars'):
            behavior_context_recovery.inspect(restored.stage)
        # Let the actual application's writable SQLite open recover its journal.
        reopened = BehaviorContextStore(restored.stage / CONTEXT_NAME)
        assert reopened.read('tenant-a') == before
        assert behavior_context_recovery.verify_prefix(restored.stage, pin) == pin
        with reopened.transaction() as transaction:
            assert not transaction.revoked('approval', 'tenant-a', 'approval-a')
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
