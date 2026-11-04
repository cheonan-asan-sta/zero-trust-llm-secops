"""Real process/HTTP recovery across collector compaction and input generations."""

import http.client
import json
import os
import subprocess
import sys

import pytest
from test_observation_collector_process import (
    PRINCIPAL,
    ROOT,
    append_source,
    cli_metadata,
    collector_process,
    initial_session,
    receipt_if_present,
    run_cli,
    status,
    wait_acknowledged,
    wait_until,
)

pytest_plugins = ("test_observation_collector_process",)


def maintenance(lab, operation, *args):
    return run_cli(lab.directory, operation, "--base-url", lab.proxy.url,
                   *args, environment=lab.env)


def once(lab, *args):
    return maintenance(lab, "run", "--once", *args)


def append_exact(lab, event):
    with (lab.directory / "input.jsonl").open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")
        file.flush()
        os.fsync(file.fileno())


def append_managed(lab, event):
    return subprocess.run(
        [sys.executable, "-m", "scripts.continuous_signal_collector", "append", "--directory",
         str(lab.directory), "--base-url", lab.proxy.url], cwd=ROOT, env=lab.env, input=json.dumps(event),
        capture_output=True, text=True, timeout=15, check=False,
    )


def fault_cli(lab, operation, code):
    return subprocess.run(
        [sys.executable, "-c", code, str(lab.directory), lab.proxy.url, operation],
        cwd=ROOT, env=lab.env, capture_output=True, text=True, timeout=15, check=False,
    )


def assert_one_effect_and_http_denial(lab, token):
    while lab.service.process_one() is not None:
        pass
    history = lab.operations.history("process-session", PRINCIPAL)
    assert len(history) == 2 and history[-1].version == 2
    assert history[-1].status == "REVOKED"
    connection = http.client.HTTPConnection("127.0.0.1", lab.proxy.backend_port, timeout=5)
    try:
        connection.request("POST", "/zero-trust/protected-access", json.dumps({
            "session_id": "process-session", "resource_id": "zt-demo-documents", "action": "READ",
            "grant_token": token,
        }), {"Content-Type": "application/json"})
        response = connection.getresponse()
        result = json.loads(response.read())
        assert response.status == 403
        assert result["reason_code"] == "SESSION_NOT_AUTHORIZED"
        assert result["content"] is None
    finally:
        connection.close()


def test_compaction_keeps_lifetime_counts_and_duplicate_conflict_history_over_http(collector_lab):
    lab = collector_lab
    initial = initial_session(lab)
    event = append_source(lab, "maintenance-acknowledged")
    cli_metadata(once(lab))
    before = status(lab)
    assert before["acknowledged"] == 1
    cli_metadata(maintenance(lab, "compact", "--limit", "1"))
    compacted = status(lab)
    assert compacted["storage"]["retained"] == 0
    assert compacted["storage"]["compacted"] == 1
    for key in ("captured", "acknowledged", "pending", "offset"):
        assert compacted[key] == before[key]
    sent = len(lab.proxy.records())
    append_exact(lab, event)
    cli_metadata(once(lab))
    assert len(lab.proxy.records()) == sent
    assert status(lab)["captured"] == status(lab)["acknowledged"] == 1
    assert status(lab)["offset"] > before["offset"]
    # Reusing the compacted ID with a new logical payload must not disappear as
    # an innocent duplicate, advance the source, or send another HTTP request.
    conflict = event | {"observation": event["observation"] | {"active": True}}
    append_exact(lab, conflict)
    checkpoint = status(lab)["offset"]
    assert once(lab).returncode == 1
    assert status(lab)["offset"] == checkpoint
    assert len(lab.proxy.records()) == sent
    assert lab.inbox.metrics(PRINCIPAL.tenant_id)["total"] == 1
    assert_one_effect_and_http_denial(lab, initial.grant_token)


def test_compact_cli_commit_then_process_death_is_idempotent_after_restart(collector_lab):
    lab = collector_lab
    event = append_source(lab, "maintenance-commit-before-output", active=True,
                          authentication_result="success")
    cli_metadata(once(lab))
    code = """
import os,sys
from app.services.collector_spool import CollectorSpool
from scripts.continuous_signal_collector import main
original=CollectorSpool.compact
def compact(self,*args,**kwargs):
 original(self,*args,**kwargs)
 os._exit(73)
CollectorSpool.compact=compact
raise SystemExit(main([sys.argv[3],'--directory',sys.argv[1],'--base-url',sys.argv[2]]))
"""
    crashed = fault_cli(lab, "compact", code)
    assert crashed.returncode == 73
    after = status(lab)
    assert after["captured"] == after["acknowledged"] == 1
    assert after["storage"]["retained"] == 0 and after["storage"]["compacted"] == 1
    cli_metadata(maintenance(lab, "compact"))
    assert status(lab) == after
    sent = len(lab.proxy.records())
    append_exact(lab, event)
    cli_metadata(once(lab))
    assert len(lab.proxy.records()) == sent
    assert status(lab)["storage"]["compacted"] == 1


def test_pending_commit_with_lost_ack_survives_compaction_rotation_and_http_restart(collector_lab):
    lab = collector_lab
    initial = initial_session(lab)
    append_source(lab, "maintenance-unknown-delivery")
    lab.proxy.mode = "drop_ack"
    assert once(lab).returncode == 1
    assert lab.proxy.committed.is_set()
    assert receipt_if_present(lab, "maintenance-unknown-delivery") is not None
    before = status(lab)
    assert before["captured"] == before["pending"] == 1 and before["acknowledged"] == 0
    cli_metadata(maintenance(lab, "compact"))
    assert status(lab)["storage"]["retained"] == 1
    assert status(lab)["storage"]["compacted"] == 0
    cli_metadata(maintenance(lab, "rotate"))
    rotated = status(lab)
    assert rotated["input_generation"] == before["input_generation"] + 1
    assert rotated["offset"] == 0 and rotated["pending"] == 1
    assert (lab.directory / "input.jsonl").read_bytes() == b""
    lab.proxy.mode = "normal"
    with collector_process(lab.directory, lab.proxy.url, environment=lab.env):
        wait_acknowledged(lab, 1)
    transmitted = [record for record in lab.proxy.records()
                   if record["event_id"] == "maintenance-unknown-delivery"]
    assert len(transmitted) >= 2
    assert len({record["payload_sha256"] for record in transmitted}) == 1
    assert lab.inbox.metrics(PRINCIPAL.tenant_id)["total"] == 1
    cli_metadata(maintenance(lab, "compact"))
    assert status(lab)["storage"]["compacted"] == 1
    assert_one_effect_and_http_denial(lab, initial.grant_token)


@pytest.mark.parametrize("operation", ["compact", "rotate"])
def test_maintenance_refuses_a_live_sender_without_mutating_input_or_storage(collector_lab, operation):
    lab = collector_lab
    append_source(lab, "maintenance-active-sender", active=True, authentication_result="success")
    with collector_process(lab.directory, lab.proxy.url, environment=lab.env) as process:
        wait_acknowledged(lab, 1)
        before, source = status(lab), (lab.directory / "input.jsonl").read_bytes()
        assert maintenance(lab, operation).returncode == 1
        assert process.poll() is None
        assert status(lab) == before
        assert (lab.directory / "input.jsonl").read_bytes() == source


@pytest.mark.parametrize("partial", [False, True])
def test_rotation_refuses_uncaptured_or_partial_tail_without_losing_any_bytes(collector_lab, partial):
    lab = collector_lab
    append_source(lab, "maintenance-captured", active=True, authentication_result="success")
    cli_metadata(once(lab))
    if partial:
        with (lab.directory / "input.jsonl").open("ab") as file:
            file.write(b'{"event_id":"unfinished"')
    else:
        append_source(lab, "maintenance-not-captured")
    before, source = status(lab), (lab.directory / "input.jsonl").read_bytes()
    assert maintenance(lab, "rotate").returncode == 1
    assert status(lab) == before
    assert (lab.directory / "input.jsonl").read_bytes() == source
    assert not (lab.directory / "input.rotation.json").exists()
    assert not list(lab.directory.glob("input.sealed.*.jsonl"))


@pytest.mark.parametrize("boundary", ["journal_publish", "sealed_rename", "sqlite_commit", "sealed_delete"])
def test_rotation_process_death_recovers_generation_before_accepting_new_input(collector_lab, boundary):
    lab = collector_lab
    event = append_source(lab, "maintenance-before-rotation", active=True,
                          authentication_result="success")
    cli_metadata(once(lab))
    original = status(lab)
    code = """
import os,sys
from pathlib import Path
from app.services.collector_spool import CollectorSpool
from scripts import collector_input as feed
from scripts.continuous_signal_collector import main
boundary=BOUNDARY
replace=feed.os.replace
def stop_replace(source,target):
 result=replace(source,target)
 name=Path(target).name
 if (boundary=='journal_publish' and name=='input.rotation.json') or (boundary=='sealed_rename' and name.startswith('input.sealed.')):
  os._exit(73)
 return result
feed.os.replace=stop_replace
rotate=CollectorSpool.rotate_input
def stop_rotate(self,*args,**kwargs):
 result=rotate(self,*args,**kwargs)
 if boundary=='sqlite_commit':os._exit(73)
 return result
CollectorSpool.rotate_input=stop_rotate
unlink=Path.unlink
def stop_unlink(self,*args,**kwargs):
 result=unlink(self,*args,**kwargs)
 if boundary=='sealed_delete' and self.name.startswith('input.sealed.'):os._exit(73)
 return result
Path.unlink=stop_unlink
raise SystemExit(main([sys.argv[3],'--directory',sys.argv[1],'--base-url',sys.argv[2]]))
""".replace("BOUNDARY", repr(boundary))
    assert fault_cli(lab, "rotate", code).returncode == 73
    assert (lab.directory / "input.rotation.json").exists()
    # A managed writer must retain and retry its event, rather than writing into
    # an unknown generation while a published rotation remains unfinished.
    next_event = event | {"event_id": "maintenance-after-rotation"}
    assert append_managed(lab, next_event).returncode != 0
    cli_metadata(once(lab))
    recovered = status(lab)
    assert recovered["input_generation"] == original["input_generation"] + 1
    assert recovered["offset"] == 0
    assert recovered["captured"] == recovered["acknowledged"] == 1
    assert not recovered["input_rotation_pending"]
    assert not (lab.directory / "input.rotation.json").exists()
    assert not list(lab.directory.glob("input.sealed.*.jsonl"))
    cli_metadata(append_managed(lab, next_event))
    cli_metadata(once(lab))
    assert status(lab)["captured"] == status(lab)["acknowledged"] == 2
    assert status(lab)["input_generation"] == recovered["input_generation"]
    assert lab.inbox.metrics(PRINCIPAL.tenant_id)["total"] == 2


def test_automatic_rotation_allows_next_generation_without_reinitializing_identity(collector_lab):
    lab = collector_lab
    first = append_source(lab, "maintenance-auto-first", active=True, authentication_result="success")
    private = (lab.directory / "private.pem").stat()
    cli_metadata(once(lab, "--rotate-bytes", "1"))
    cli_metadata(once(lab, "--rotate-bytes", "1"))
    wait_until(lambda: status(lab)["input_generation"] == 1)
    assert (lab.directory / "input.jsonl").read_bytes() == b""
    assert status(lab)["captured"] == status(lab)["acknowledged"] == 1
    next_event = first | {"event_id": "maintenance-auto-second"}
    cli_metadata(append_managed(lab, next_event))
    cli_metadata(once(lab, "--rotate-bytes", "1"))
    cli_metadata(once(lab, "--rotate-bytes", "1"))
    assert status(lab)["input_generation"] == 2
    assert status(lab)["captured"] == status(lab)["acknowledged"] == 2
    assert (lab.directory / "private.pem").stat().st_mtime_ns == private.st_mtime_ns
    assert lab.inbox.metrics(PRINCIPAL.tenant_id)["total"] == 2
