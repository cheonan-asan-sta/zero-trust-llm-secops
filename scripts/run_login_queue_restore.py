"""Prove a quiesced login queue and audit pair can restart without their original files."""

import argparse
import hashlib
import json
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
from contextlib import closing, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, sleep

import httpx

from app import config, login_queue_api, security
from app.config import Settings
from app.services.sqlite_audit import SQLiteAuditStore
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
    # A fresh process imports the service with only the restored paths configured.
    from app.main import app

    uvicorn.run(app, host="127.0.0.1", port=port, access_log=False, log_level="warning")


@contextmanager
def service(root, port, collector_key, reviewer_key):
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
    with (root / "service.log").open("wb") as log, subprocess.Popen(
        [sys.executable, "-m", "scripts.run_login_queue_restore",
         "--serve-fixture", str(root), str(port)],
        stdout=log, stderr=subprocess.STDOUT,
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


def sender(client, root):
    return KeycloakLoginAnalysisCollector(
        client, settings=None, authority=None, registry=None, gateway_id="restore-fixture",
        source_id="restore-fixture", key_id="unused", signing_key=None, spool_path=root / QUEUE,
        tenant_id=TENANT, collector_subject=COLLECTOR,
        retry_policy=LoginRetryPolicy(base_delay=0.15, max_delay=0.3, success_interval=0),
    )


def view(reviewer):
    response = reviewer.get("/dashboard/login-queue")
    response.raise_for_status()
    return response.json()


def approval(reviewer, review, event_id):
    row = next(row for row in review["held"] if row["event_id"] == event_id)
    return reviewer.post("/dashboard/login-queue/approvals", headers={
        "If-Match": row["etag"], "X-Review-Identity": review["identity"],
    }, json={"event_id": event_id, "hold_id": row["hold_id"], "note": "로컬 복구 확인"})


def exercise(root):
    keys = (secrets.token_urlsafe(32), secrets.token_urlsafe(32))
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]

    backup = root / "snapshot"
    backup.mkdir()
    cases = list(events(4))
    completed, unconfirmed, held, queued = (event for event, _ in cases)
    outcomes = {event.event_id: "hold" for event in (completed, unconfirmed, held)}
    outcomes[queued.event_id] = "unavailable"
    expected, sent_bodies = {}, {}
    before, after = counts(), counts()
    state_counts = {"held": 1, "pending": 2}

    # Both writers are stopped before forming this pair of SQLite backup files.
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

            with httpx.Client(base_url=api.base_url, transport=httpx.MockTransport(forward)) as transport:
                collector = sender(transport, source)
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

        fingerprints = snapshot_pair(source, backup)

    assert not source.exists()
    restored = root / "restored"
    restored.mkdir()
    try:
        restore_pair(backup, restored, {**fingerprints, AUDIT: "0" * 64})
    except ValueError:
        assert not any(restored.iterdir())
    else:
        raise AssertionError("Invalid audit digest was accepted")
    restore_pair(backup, restored, fingerprints)
    with service(restored, port, *keys) as (api, reviewer, restored_pid):
        assert original_pid != restored_pid
        collector = sender(api, restored)
        audit = SQLiteAuditStore(restored / AUDIT)
        restored_view = view(reviewer)
        assert collector.spool.counts() == state_counts and audit.integrity() == original_audit
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

    return {
        "scope": "different loopback API processes; original disposable directory removed; no external host",
        "source_files_absent": True,
        "snapshot_sqlite_quick_check_passed": 2,
        "mismatched_snapshot_blocked_before_restore": True,
        "snapshot_hashes": fingerprints,
        "initial_queue_counts": state_counts,
        "pre_restore_audit_records_including_baselines": 6,
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
    parser.add_argument("--serve-fixture", nargs=2, metavar=("DIRECTORY", "PORT"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.serve_fixture:
        directory, port = args.serve_fixture
        serve(Path(directory), int(port))
        return
    if args.output is None:
        parser.error("output is required")
    with TemporaryDirectory(prefix="zt-login-restore-") as temporary:
        report = exercise(Path(temporary))
    write(args.output, report)
    print(json.dumps(report))


if __name__ == "__main__":
    main()
