"""Independent interpreters race and die across durable simulated execution."""

import json
import subprocess
import sys

import pytest

from app.services.behavior_context_store import BehaviorContextStore
from app.services.response_actions import ResponseService
from tests import test_response_actions as response_cases
from tests.test_response_actions import approved, command


@pytest.fixture
def response_lab(tmp_path, monkeypatch):
    return response_cases.response_lab.__wrapped__(tmp_path, monkeypatch)


PROGRAM = r"""
import json, os, sys
from datetime import datetime
from pathlib import Path
from app.response_models import ResponseCommand
from app.security import Principal, Role
from app.services.behavior_context_store import BehaviorContextStore, ContextTransaction
from app.services.response_actions import ResponseService
from app.services.trusted_signals import SignalVerifier
from app.services.zero_trust import ZeroTrustOperations
c = json.loads(sys.argv[1])
store = BehaviorContextStore(c['store'])
service = ResponseService(store, ZeroTrustOperations(Path(c['operations']), signal_verifier=SignalVerifier(Path(c['registry']))))
actor = Principal('context-admin', 'tenant-a', frozenset({Role.RESPONDER}), 'api_key')
if c['mode'] == 'before_commit':
    original = ContextTransaction.put
    def interrupted(self, kind, *args, **kwargs):
        result = original(self, kind, *args, **kwargs)
        if kind == 'response_result':
            os._exit(73)
        return result
    ContextTransaction.put = interrupted
print('ready', flush=True)
input()
result = service.execute(c['identifier'], ResponseCommand(**c['command']), actor, now=datetime.fromisoformat(c['now']))
if c['mode'] == 'lost_reply':
    os._exit(74)
print(json.dumps(result), flush=True)
"""


def start(e, view, mode="normal"):
    config = {
        "store": str(e.lab.store_path),
        "operations": str(e.lab.operations_path),
        "registry": str(e.lab.registry_path),
        "identifier": view["request_id"],
        "command": command(view).model_dump(mode="json"),
        "now": e.lab.at(5).isoformat(),
        "mode": mode,
    }
    return subprocess.Popen(
        [sys.executable, "-W", "ignore::DeprecationWarning", "-c", PROGRAM, json.dumps(config)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def cleanup(processes):
    for process in processes:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)


def test_concurrent_exact_retries_publish_one_result(response_lab):
    e = response_lab
    view = approved(e)
    processes = []
    try:
        for _ in range(2):
            process = start(e, view)
            processes.append(process)
            assert process.stdout.readline().strip() == "ready"
        for process in processes:
            process.stdin.write("execute\n")
            process.stdin.flush()
        results = []
        for process in processes:
            output, error = process.communicate(timeout=30)
            assert process.returncode == 0 and not error, error
            results.append(json.loads(output))
        assert sorted(row["duplicate"] for row in results) == [False, True]
        assert results[0]["result"] == results[1]["result"]
        assert sum(row["kind"] == "response_result" for row in e.lab.store.read("tenant-a")) == 1
    finally:
        cleanup(processes)


@pytest.mark.parametrize("mode,exit_code", [("before_commit", 73), ("lost_reply", 74)])
def test_process_death_rolls_back_or_recovers_exact_receipt(response_lab, mode, exit_code):
    e = response_lab
    view = approved(e)
    process = start(e, view, mode)
    try:
        assert process.stdout.readline().strip() == "ready"
        output, error = process.communicate("execute\n", timeout=30)
        assert process.returncode == exit_code and not output and not error
        reopened = ResponseService(BehaviorContextStore(e.lab.store_path), e.lab.operations)
        assert reopened.get(view["request_id"], e.requester)["status"] == (
            "APPROVED" if mode == "before_commit" else "EXECUTED"
        )
        retry = reopened.execute(view["request_id"], command(view), e.requester)
        assert retry["duplicate"] == (mode == "lost_reply")
        assert retry["result"]["effect_applied"] is False
        assert sum(row["kind"] == "response_result" for row in e.lab.store.read("tenant-a")) == 1
    finally:
        cleanup([process])
