"""Prove a quiesced login queue and audit pair can restart without their original files."""

import argparse
import hashlib
import json
import os
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
from contextlib import closing, contextmanager, nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from unittest.mock import patch

import httpx

from app import config, login_queue_api, security
from app.config import Settings
from app.services.sqlite_audit import SQLiteAuditStore
from scripts import login_queue_activation as activation
from scripts import login_queue_backup
from scripts.evaluate_local_remote_holdout import write
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.keycloak_login_evidence import KeycloakLoginAnalysisCollector
from scripts.login_delivery_spool import LoginRetryPolicy
from scripts.run_login_queue_recovery import FIELDS, events, flagged

TENANT = "login-restore-lab"
COLLECTOR = "restore-lab-collector"
OPERATOR = "restore-lab-operator"
QUEUE = "login-queue.sqlite3"
AUDIT = "analysis-audit.sqlite3"


def digest(value):
    return hashlib.sha256(value).hexdigest()


def serve(root, port):
    import uvicorn

    settings = Settings.model_validate_json((root / "settings.json").read_bytes())

    def fixture_settings():
        return settings

    config.get_settings = fixture_settings
    security.get_settings = fixture_settings
    login_queue_api.get_settings = fixture_settings
    # A fresh process imports the service with only the selected paths configured.
    from app.main import app

    uvicorn.run(app, host="127.0.0.1", port=port, access_log=False, log_level="warning")


@contextmanager
def service(root, port, collector_key, reviewer_key, *, control=None):
    origin = f"http://127.0.0.1:{port}"
    accounts = root / "accounts.json"
    profile = root / "queue-profile.json"
    write(accounts, {"schema": "api-key-accounts-1", "accounts": [{
        "sha256": digest(reviewer_key.encode()), "tenant_id": TENANT, "subject": OPERATOR,
        "roles": ["responder"],
    }]})
    write(profile, {
        "queue_file": str(root / QUEUE), "analysis_origin": origin,
        "tenant_id": TENANT, "collector_subject": COLLECTOR,
    })
    settings = Settings(
        _env_file=None, app_environment="test", analyzer_mode="rule", auth_mode="api_key",
        api_key_sha256=digest(collector_key.encode()), api_key_tenant_id=TENANT,
        api_key_subject=COLLECTOR, api_key_roles="analyst", api_key_accounts_path=accounts,
        dashboard_login_queue_profile=profile, audit_backend="sqlite", audit_db_path=root / AUDIT,
        audit_log_path=root / "unused-audit.jsonl", case_log_path=root / "cases.jsonl",
        outbox_log_path=root / "outbox.jsonl", zero_trust_db_path=root / "sessions.sqlite3",
        allowed_hosts="127.0.0.1",
    )
    # Settings JSON masks SecretStr values; this file contains only a disposable key hash.
    payload = settings.model_dump(mode="json", exclude={"openai_api_key"})
    payload["api_key_sha256"] = digest(collector_key.encode())
    write(root / "settings.json", payload)
    command = [sys.executable, "-m", "scripts.run_login_queue_restore",
               "--serve-fixture", str(root), str(port)]
    env = None
    if control:
        command = [sys.executable, "-m", "scripts.login_queue_activation", str(control),
                   "serve-api", "--port", str(port)]
        env = {**os.environ, **{k.upper(): str(v) for k, v in payload.items() if v is not None}}
    with (root / "service.log").open("wb") as log, subprocess.Popen(
        command,
        stdout=log, stderr=subprocess.STDOUT, env=env,
    ) as process:
        try:
            with (
                httpx.Client(base_url=origin, headers={"X-API-Key": collector_key}, timeout=8, trust_env=False) as collector,
                httpx.Client(base_url=origin, headers={"X-API-Key": reviewer_key}, timeout=8, trust_env=False) as reviewer,
            ):
                deadline = monotonic() + 20
                while monotonic() < deadline and process.poll() is None:
                    try:
                        identity = collector.get("/auth/me", timeout=1)
                        if identity.is_success:
                            assert identity.json()["subject"] == COLLECTOR
                            break
                    except httpx.TransportError:
                        pass
                    sleep(0.1)
                else:
                    raise RuntimeError("Isolated login API could not start: " + (root / "service.log").read_text(
                        encoding="utf-8", errors="replace",
                    )[-2000:])
                yield collector, reviewer, process.pid
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)


def snapshot_pair(source, backup):
    fingerprints = {}
    for name in (QUEUE, AUDIT):
        target = backup / name
        with (
            closing(sqlite3.connect((source / name).as_uri() + "?mode=ro", uri=True)) as old,
            closing(sqlite3.connect(target)) as copy,
        ):
            old.backup(copy)
            assert copy.execute("PRAGMA quick_check").fetchone() == ("ok",)
        fingerprints[name] = digest(target.read_bytes())
    return fingerprints


def restore_pair(backup, target, fingerprints):
    for name, expected in fingerprints.items():
        if digest((backup / name).read_bytes()) != expected:
            raise ValueError("Login restore snapshot digest mismatch")
    for name, expected in fingerprints.items():
        shutil.copyfile(backup / name, target / name)
        if digest((target / name).read_bytes()) != expected:
            raise ValueError("Restored login database digest mismatch")


def sender(client, root, control=None):
    options = {
        "settings": None, "authority": None, "registry": None, "gateway_id": "restore-fixture",
        "source_id": "restore-fixture", "key_id": "unused", "signing_key": None,
        "retry_policy": LoginRetryPolicy(base_delay=0.15, max_delay=0.3, success_interval=0),
    }
    if control:
        return activation.managed_collector(control, client, **options)
    return nullcontext(KeycloakLoginAnalysisCollector(
        client, spool_path=root / QUEUE, tenant_id=TENANT, collector_subject=COLLECTOR, **options,
    ))


def view(reviewer):
    response = reviewer.get("/dashboard/login-queue")
    response.raise_for_status()
    return response.json()


def approval(reviewer, review, event_id):
    row = next(row for row in review["held"] if row["event_id"] == event_id)
    return reviewer.post("/dashboard/login-queue/approvals", headers={
        "If-Match": row["etag"], "X-Review-Identity": review["identity"],
    }, json={"event_id": event_id, "hold_id": row["hold_id"], "note": "로컬 복구 확인"})


def online_restore_fixture(source, backup, collector, api, outcomes, unconfirmed, queued):
    from scripts.f1_lab.capture_backup import fresh_file, sha

    scope = {"origin": str(api.base_url), "tenant_id": TENANT, "collector_subject": COLLECTOR}
    key_file = backup / "key"
    fresh_file(key_file, secrets.token_bytes(32))
    producer = login_queue_backup.copy_database
    for name in (QUEUE, AUDIT):
        with closing(sqlite3.connect(source / name)) as active:
            assert active.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)

    def copy_during_writes(src, target):
        producer(src, target)
        if src != source / QUEUE:
            return
        # Interleave writes while the real API and collector are still live,
        # after the queue image has cut but before the audit image starts.
        outcomes[unconfirmed.event_id] = outcomes[queued.event_id] = "ready"
        deadline = monotonic() + 6
        with collector.replaying(interval=0.05):
            while collector.spool.counts()["pending"] and monotonic() < deadline:
                sleep(0.05)
        assert collector.spool.counts() == {"held": 1, "pending": 0}
        assert SQLiteAuditStore.open_existing(source / AUDIT).integrity()["verified_lines"] == 7

    document = backup / "online-backup.bin"
    with patch.object(login_queue_backup, "copy_database", copy_during_writes):
        summary = login_queue_backup.backup(source / QUEUE, source / AUDIT, document, key_file, **scope)
    package_pin = summary["package_sha256"]
    assert b"SQLite format 3" not in document.read_bytes()
    corrupt = backup / "bad-authentication.bin"
    raw = document.read_bytes()
    wrong = raw[:-1] + bytes([raw[-1] ^ 1])
    fresh_file(corrupt, wrong)
    rejected = backup / "invalid-target"
    for candidate, pin, binding in (
        (document, "0" * 64, scope), (corrupt, sha(wrong), scope),
        (document, package_pin, {**scope, "tenant_id": "another-tenant"}),
    ):
        try:
            login_queue_backup.restore(candidate, pin, rejected, key_file, **binding)
        except ValueError:
            assert not rejected.exists()
        else:
            raise AssertionError("An invalid online package was accepted")
    with TemporaryDirectory(dir=backup) as temporary:
        mismatched = Path(temporary)
        producer(source / QUEUE, mismatched / QUEUE)
        SQLiteAuditStore(mismatched / AUDIT)
        try:
            login_queue_backup.validate_pair(mismatched, **scope)
        except ValueError as error:
            assert "completion has no matching analysis audit" in str(error)
        else:
            raise AssertionError("A newer queue and older audit formed an invalid pair")
    return document, package_pin, key_file, scope


@contextmanager
def rejected_transition(message, error_type=activation.ActivationConflict):
    try:
        yield
    except error_type as error:
        assert message in str(error)
    else:
        raise AssertionError(f"Expected activation rejection: {message}")


def exercise(root, *, online=False, managed=False):
    keys = (secrets.token_urlsafe(32), secrets.token_urlsafe(32))
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]

    backup = root / "snapshot"
    backup.mkdir(mode=0o700)
    restored = root / "restored"
    control = root / "activation" if managed else None
    cases = list(events(4))
    completed, unconfirmed, held, queued = (event for event, _ in cases)
    outcomes = {event.event_id: "hold" for event in (completed, unconfirmed, held)}
    outcomes[queued.event_id] = "unavailable"
    expected, sent_bodies = {}, {}
    before, after = counts(), counts()
    state_counts = {"held": 1, "pending": 2}

    with TemporaryDirectory(prefix="original-", dir=root) as original:
        source = Path(original)
        with service(source, port, *keys) as (api, reviewer, original_pid):
            def forward(request):
                event_id = json.loads(request.content)["event"]["event_id"]
                sent_bodies[event_id] = json.loads(request.content)
                outcome = outcomes[event_id]
                if outcome == "hold":
                    return httpx.Response(403)
                if outcome == "unavailable":
                    return httpx.Response(503)
                answer = api.post("/analysis/login-delivery", content=request.content,
                                  headers={"Content-Type": "application/json"})
                answer.raise_for_status()
                if outcome == "drop_receipt":
                    raise httpx.ReadError("Controlled loss after durable API commit", request=request)
                return answer

            for event, truth in cases:
                answer = api.post("/analysis", json=event.analysis_payload())
                answer.raise_for_status()
                expected[event.event_id] = answer.json()
                record(before, truth, flagged(answer.json()))

            with (
                httpx.Client(base_url=api.base_url, transport=httpx.MockTransport(forward)) as transport,
                sender(transport, source) as collector,
            ):
                for event in (completed, unconfirmed, held):
                    try:
                        collector.submit(event, None)
                    except httpx.HTTPStatusError as error:
                        assert error.response.status_code == 403
                    else:
                        raise AssertionError("Permanent local failure did not hold the event")
                for event, mode in [(completed, "ready"), (unconfirmed, "drop_receipt")]:
                    reviewed = approval(reviewer, view(reviewer)["review"], event.event_id)
                    assert reviewed.status_code == 200 and not reviewed.json()["duplicate"]
                    outcomes[event.event_id] = mode
                    assert collector.flush_pending(limit=1) == (1 if mode == "ready" else 0)

                # Keep the unconfirmed row pending behind its retry delay while the
                # outage row is enqueued as it would be during the shared backoff.
                assert collector.spool.next_attempt() is not None
                assert collector.submit(queued, None).evidence_state == "queued"
                assert collector.spool.counts() == state_counts
                original_view = view(reviewer)
                original_audit = SQLiteAuditStore(source / AUDIT).integrity()
                assert original_audit["ok"] and original_audit["verified_lines"] == 6
                prior = next(row for row in original_view["review"]["history"] if row["outcome"] == "delivered")
                original_detail = reviewer.get(f"/dashboard/login-queue/deliveries/{prior['analysis_id']}")
                original_detail.raise_for_status()
                if online:
                    package = online_restore_fixture(source, backup, collector, api, outcomes, unconfirmed, queued)

        if control:
            document, pin, key_file, scope = package
            control.mkdir(mode=0o700)
            activation.initialize(control, source / QUEUE, source / AUDIT, **scope)
            login_queue_backup.restore(document, pin, restored, key_file, **scope)
            decision = activation.approve(control, document, pin, restored, key_file, note="Review recovery pair")
            before_selection = activation.status(control)
            assert len(before_selection["generations"]) == 1
            predecessor_config = root / "old-service-config"
            predecessor_config.mkdir()
            with service(predecessor_config, port, *keys, control=control), rejected_transition("active.lock"):
                activation.activate(control, decision, document, key_file)
            with httpx.Client(base_url=scope["origin"], trust_env=False) as transport, sender(transport, source, control):
                with rejected_transition("sender.lock"), sender(transport, source, control):
                    raise AssertionError("Second sender started")
                with rejected_transition("active.lock"):
                    activation.activate(control, decision, document, key_file)
            with rejected_transition("Predecessor differs"):
                activation.activate(control, decision, document, key_file)
            assert activation.status(control) == before_selection
            assert (source / QUEUE).is_file() and (source / AUDIT).is_file()
        elif not online:
            fingerprints = snapshot_pair(source, backup)

    assert not source.exists()
    if online:
        document, package_pin, key_file, scope = package
        if not managed:
            restored_package = login_queue_backup.restore(document, package_pin, restored, key_file, **scope)
            assert restored_package["restored_databases"] == 2
        assert (restored / "RESTORE_READY").read_text(encoding="ascii").strip() == package_pin
        try:
            login_queue_backup.restore(document, package_pin, restored, key_file, **scope)
        except FileExistsError:
            assert (restored / "RESTORE_READY").read_text(encoding="ascii").strip() == package_pin
        else:
            raise AssertionError("An existing restore candidate was replaced")
        verified = login_queue_backup.verify_candidate(document, package_pin, restored, key_file, **scope)
        assert verified["verified_databases"] == 2
        tampered = backup / "tampered-candidate"
        login_queue_backup.restore(document, package_pin, tampered, key_file, **scope)
        altered = tampered / QUEUE
        raw = altered.read_bytes()
        altered.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        try:
            login_queue_backup.verify_candidate(document, package_pin, tampered, key_file, **scope)
        except ValueError as error:
            assert "differs from the authenticated backup" in str(error)
        else:
            raise AssertionError("A candidate with a valid ready marker but modified DB was accepted")
    else:
        restored.mkdir()
        try:
            restore_pair(backup, restored, {**fingerprints, AUDIT: "0" * 64})
        except ValueError:
            assert not any(restored.iterdir())
        else:
            raise AssertionError("Invalid audit digest was accepted")
        restore_pair(backup, restored, fingerprints)

    if control:
        with rejected_transition("missing or incomplete"):
            activation.activate(control, decision, document, key_file)
        source.mkdir()
        orphaned_wal = source / (AUDIT + "-wal")
        orphaned_wal.touch()
        with rejected_transition("still has SQLite sidecars"):
            activation.activate(control, decision, document, key_file, allow_missing=True)
        orphaned_wal.unlink()
        source.rmdir()
        altered = restored / QUEUE
        raw = altered.read_bytes()
        altered.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with rejected_transition("differs from the authenticated backup", ValueError):
            activation.activate(control, decision, document, key_file, allow_missing=True)
        altered.write_bytes(raw)
        assert activation.status(control) == before_selection
        stale = activation.approve(control, document, package_pin, restored, key_file, note="Another review")
        assert activation.activate(control, decision, document, key_file, allow_missing=True) == 2
        with rejected_transition("former generation"):
            activation.activate(control, stale, document, key_file, allow_missing=True)
        selected = activation.status(control)
        assert selected["generations"][-1]["approval_id"] == decision
        assert selected["generations"][-1]["predecessor_state"] == "unavailable"
        assert selected["approvals"][0]["approved_uid"] == selected["generations"][-1]["activated_uid"]

    # The managed API and collector must use the selected pair, even when the
    # fixture settings point at a directory that contains neither database.
    fixture = root / "new-service-config" if managed else restored
    fixture.mkdir(exist_ok=True)
    with (
        service(fixture, port, *keys, control=control) as (api, reviewer, restored_pid),
        sender(api, source if managed else restored, control) as collector,
    ):
        assert original_pid != restored_pid
        audit = SQLiteAuditStore(restored / AUDIT)
        restored_view = view(reviewer)
        restored_audit_rows = original_audit["verified_lines"] + int(online)
        assert collector.spool.counts() == state_counts
        assert audit.integrity() == {**original_audit, "verified_lines": restored_audit_rows}
        assert restored_view["queue"] == original_view["queue"]
        assert restored_view["review"]["history"] == original_view["review"]["history"]
        assert restored_view["review"]["held"][0]["hold_id"] == original_view["review"]["held"][0]["hold_id"]
        assert approval(reviewer, original_view["review"], held.event_id).status_code == 412
        detail_path = f"/dashboard/login-queue/deliveries/{prior['analysis_id']}"
        assert reviewer.get(detail_path).json() == original_detail.json()

        deadline = monotonic() + 8
        with collector.replaying(interval=0.05):
            while collector.spool.counts()["pending"] and monotonic() < deadline:
                sleep(0.05)
            assert collector.spool.counts() == {"held": 1, "pending": 0}
            if online:
                assert audit.integrity()["verified_lines"] == restored_audit_rows
            remaining = view(reviewer)["review"]
            response = approval(reviewer, remaining, held.event_id)
            assert response.status_code == 200 and not response.json()["duplicate"]
            assert approval(reviewer, remaining, held.event_id).json()["duplicate"]
            while collector.spool.counts()["pending"] and monotonic() < deadline:
                sleep(0.05)
        assert collector.spool.counts() == {"held": 0, "pending": 0}
        final = view(reviewer)["review"]["history"]
        replay = [row for row in final if row["event_id"] == unconfirmed.event_id]
        assert [entry["outcome"] for entry in replay] == ["delivered", "deferred", "approved"]
        assert replay[0]["duplicate"] and replay[-1]["actor"] == OPERATOR

        for event, truth in cases:
            body = sent_bodies.get(event.event_id, {
                "event": event.analysis_payload(), "tenant_id": TENANT, "collector_subject": COLLECTOR,
            })
            receipt = api.post("/analysis/login-delivery", json=body)
            receipt.raise_for_status()
            outcome = receipt.json()
            result = outcome["result"]
            assert outcome["duplicate"] and all(result[field] == expected[event.event_id][field] for field in FIELDS)
            record(after, truth, flagged(result))
        assert audit.integrity()["ok"] and audit.integrity()["verified_lines"] == 8
        assert before == after == {"tp": 2, "fp": 0, "fn": 0, "tn": 2, "inference_errors": 0}

    if control:
        fresh_package = backup / "fresh-quiesced.bin"
        fresh_pin = login_queue_backup.backup(restored / QUEUE, restored / AUDIT, fresh_package, key_file, **scope)[
            "package_sha256"
        ]
        next_target = root / "another-restored"
        login_queue_backup.restore(fresh_package, fresh_pin, next_target, key_file, **scope)
        approved = activation.approve(control, fresh_package, fresh_pin, next_target, key_file, note="Fresh quiesced pair")
        assert activation.activate(control, approved, fresh_package, key_file) == 3
        assert activation.status(control)["generations"][-1]["predecessor_state"] == "verified_identical"
        assert (restored / QUEUE).is_file() and (restored / AUDIT).is_file()
        assert SQLiteAuditStore.open_existing(next_target / AUDIT).integrity()["verified_lines"] == 8

    return {
        "scope": "different loopback API processes; original disposable directory removed; no external host",
        "source_files_absent": True,
        "snapshot_sqlite_quick_check_passed": 2,
        "mismatched_snapshot_blocked_before_restore": True,
        **({
            "online_encrypted_package_sha256": package[1],
            "wal_sources_copied_as_standalone_databases": True,
            "live_audit_commit_between_queue_and_audit_copies": True,
            "between_copy_commit_reused_without_new_audit": True,
            "wrong_pin_modified_ciphertext_wrong_scope_rejected": True,
            "newer_queue_with_older_audit_rejected": True,
            "restore_ready_only_for_valid_pair": True,
            "existing_restore_candidate_not_replaced": True,
            "candidate_with_ready_marker_and_modified_database_rejected": True,
        } if online else {"snapshot_hashes": fingerprints}),
        **({
            "candidate_approval_did_not_change_active_paths": True,
            "running_managed_api_or_sender_prevented_activation": True,
            "second_managed_sender_rejected": True,
            "diverged_predecessor_rejected": True,
            "missing_predecessor_required_explicit_confirmation": True,
            "orphaned_predecessor_wal_prevented_activation": True,
            "post_approval_candidate_change_rejected": True,
            "old_generation_approval_rejected": True,
            "active_api_and_sender_followed_restored_pair": True,
            "fresh_identical_cutover_preserved_predecessor_files": True,
            "approval_and_activation_os_uid_recorded": True,
            "activated_generations": [2, 3],
        } if managed else {}),
        "initial_queue_counts": state_counts,
        "pre_restore_audit_records_including_baselines": restored_audit_rows,
        "final_audit_records_including_baselines": 8,
        "restored_delivery_records": 4,
        "restored_prior_audit_detail_matched": True,
        "unconfirmed_commit_reused": True,
        "old_hold_review_rejected": True,
        "new_hold_approval_deduplicated": True,
        "duplicate_analysis_or_audit_records": 0,
        "before": metrics(before),
        "after": metrics(after),
        "aws_calls": 0,
        "paid_api_calls": 0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--online", action="store_true", help="verify the authenticated online backup and restore")
    parser.add_argument("--activation", action="store_true", help="also verify operator-controlled activation")
    parser.add_argument("--serve-fixture", nargs=2, metavar=("DIRECTORY", "PORT"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.serve_fixture:
        directory, port = args.serve_fixture
        serve(Path(directory), int(port))
        return
    if args.output is None:
        parser.error("output is required")
    with TemporaryDirectory(prefix="zt-login-restore-") as temporary:
        report = exercise(Path(temporary), online=args.online or args.activation, managed=args.activation)
    write(args.output, report)
    print(json.dumps(report))


if __name__ == "__main__":
    main()
