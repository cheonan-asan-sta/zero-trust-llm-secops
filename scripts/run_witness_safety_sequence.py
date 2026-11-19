"""Bounded synthetic action sequences for witness safety, never detection F1.

Seeds control action order/counts, not cryptographic keys, UUIDs or timestamps.
All audit data/keys/directories are test-owned. No provider/cloud/Docker call,
app activation, production source, OS clock change or actual eight-hour soak.
"""

import argparse
import asyncio
import json
import os
import random
import secrets
import sqlite3
import subprocess
import tempfile
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.models import AnalysisResult
from app.scenarios import synthetic_events
from app.services import audit_witness as witness
from app.services import audit_witness_observer as observer
from app.services import audit_witness_observer_backup as backup
from app.services.audit_transfer import AuditTransferError, canonical, require
from app.services.policy import response_preview
from app.services.sqlite_audit import SQLiteAuditStore
from scripts.local_process_runtime import direct_python

ACTIONS = ("append", "cycle", "lost_before", "lost_after", "audit_rollback",
           "control_rollback", "backup_handoff", "restore_resume", "freshness")


class InjectedLoss(OSError):
    pass


def run(directory, *, seed=20261120, rounds=1, delay_seconds=0, max_seconds=None):
    require(type(seed) is int and 0 <= seed < 2**32 and type(rounds) is int and 1 <= rounds <= 32,
            "witness_sequence_seed_rounds")
    require(type(delay_seconds) in {int, float} and 0 <= delay_seconds <= 60
            and (max_seconds is None or (type(max_seconds) is int and 1 <= max_seconds <= 7200)),
            "witness_sequence_duration")
    output = Path(directory).absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    started, trace, rng = time.monotonic(), [], random.Random(seed)
    deadline = None if max_seconds is None else started + max_seconds
    common = {"schema": "local-witness-safety-sequence-1", "seed": seed, "rounds": rounds,
              "started_at": datetime.now(UTC).isoformat(),
              "delay_seconds": delay_seconds, "max_seconds": max_seconds,
              "all_audit_data_synthetic": True, "independent_acceptance": False,
              "detection_metrics_changed": False, "paid_api_calls": 0, "real_8h_soak": False,
              "independent_storage_verified": False, "automatic_activation_allowed": False}
    last_action = None

    def write_json(name, value):
        # These are test progress artifacts, never trusted admission documents.
        with (output / name).open("wb") as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

    try:
        # Reports may be on a Windows shared mount; private SQLite/key fixtures
        # must use the platform's native temporary filesystem and its controls.
        with tempfile.TemporaryDirectory(prefix="private-sequence-") as temporary:
            root = Path(temporary)
            source = SQLiteAuditStore(root / "audit.sqlite3")
            source_rows = 0

            def append(count):
                nonlocal source_rows
                for _ in range(count):
                    source_rows += 1
                    event = synthetic_events()[0].model_copy(update={"event_id": f"sequence-{source_rows}"})
                    assessment = RuleBasedAnalyzer().assess(event)
                    record = AnalysisResult(event_id=event.event_id, analyzer="rule", assessment=assessment,
                                            policy_decision=response_preview(assessment, event), latency_ms=1)
                    asyncio.run(source.save(record))

            append(1)
            initial_audit = source.path.read_bytes()
            signer, control = root / "witness", root / "control"
            key_pin = witness.initialize(signer, source.path, "safety-sequence")["public_key_sha256"]
            first = witness.observe(signer, source.path, key_pin, expected_receipt=witness.GENESIS)
            minimum = first["receipt_sha256"]  # Held by this parent, outside all control DBs.
            profile_pin = observer.initialize(control, signer, source.path, key_pin,
                                              expected_receipt=minimum, interval_seconds=1,
                                              max_age_seconds=3600, capacity_warning=0)["profile_sha256"]
            initial_control = (control / "observer.sqlite3").read_bytes()
            receipts, anchors, observed_rows, handoffs, packages = 1, 0, 1, 0, 0
            recovery_key = secrets.token_bytes(32)
            binary, environment = direct_python(dict(os.environ, AWS_EC2_METADATA_DISABLED="true"))

            def accepted(result, *, replayed=None):
                nonlocal minimum, receipts, anchors, observed_rows
                current = witness.status(signer, key_pin, minimum_receipt=result["receipt_sha256"])
                body = current["receipt"]["body"]
                require(current["receipt_sha256"] == result["receipt_sha256"]
                        and body["previous_receipt"] == minimum and body["number"] == receipts + 1
                        and body["head"]["seq"] == source_rows, "witness_sequence_receipt_model")
                if replayed is not None:
                    require(result["recovered"] is replayed, "witness_sequence_recovery_kind")
                minimum, receipts, anchors, observed_rows = result["receipt_sha256"], receipts + 1, anchors + 1, source_rows

            def cycle():
                accepted(observer.cycle(control, profile_pin, minimum_receipt=minimum), replayed=False)

            def recover_cli(replayed):
                result = subprocess.run([binary, "-m", "scripts.audit_witness_observer", "cycle",
                                         "--directory", str(control), "--profile-sha256", profile_pin,
                                         "--minimum-receipt", minimum], env=environment,
                                        capture_output=True, text=True, timeout=30, check=False)
                require(result.returncode == 0, "witness_sequence_cli_recovery_failed")
                accepted(json.loads(result.stdout), replayed=replayed)

            def lose(after):
                actual = witness.observe

                def injected(*args, **kwargs):
                    if after:
                        actual(*args, **kwargs)
                    raise InjectedLoss("test-owned observation response loss")

                witness.observe = injected
                try:
                    try:
                        observer.cycle(control, profile_pin, minimum_receipt=minimum)
                    except InjectedLoss:
                        pass
                    else:
                        raise AuditTransferError("witness_sequence_loss_not_reached")
                finally:
                    witness.observe = actual
                with closing(sqlite3.connect(control / "observer.sqlite3")) as con:
                    pending_id = json.loads(con.execute("SELECT payload FROM pending").fetchone()[0])["observation_id"]
                recover_cli(after)
                current = witness.status(signer, key_pin, minimum_receipt=minimum)
                require(current["receipt"]["body"]["observation_id"] == pending_id,
                        "witness_sequence_pending_id_changed")

            def handoff(interrupt):
                nonlocal control, handoffs, packages
                packages += 1
                package = root / f"snapshot-{packages}.aesgcm"
                saved = backup.backup(control, profile_pin, minimum, package, recovery_key)
                target = root / f"review-{packages}"
                before = (signer / "journal.sqlite3").read_bytes()
                if interrupt:
                    actual = observer._write

                    def injected(path, raw):
                        result = actual(path, raw)
                        if path == target / "lease.sqlite3":
                            raise InjectedLoss("test-owned restore response loss")
                        return result

                    observer._write = injected
                    try:
                        try:
                            backup.restore(package, target, saved["backup_sha256"], profile_pin, minimum, recovery_key)
                        except InjectedLoss:
                            pass
                        else:
                            raise AuditTransferError("witness_sequence_restore_loss_not_reached")
                    finally:
                        observer._write = actual
                    try:
                        observer.status(target, profile_pin, minimum_receipt=minimum)
                    except AuditTransferError:
                        pass
                    else:
                        raise AuditTransferError("witness_sequence_partial_candidate_admitted")
                    restored = backup.restore(package, target, saved["backup_sha256"], profile_pin,
                                              minimum, recovery_key, resume=True)
                    require(restored["resumed"] is True, "witness_sequence_resume_not_used")
                else:
                    restored = backup.restore(package, target, saved["backup_sha256"], profile_pin, minimum, recovery_key)
                proof = backup.inspect_restore(package, target, saved["backup_sha256"],
                                               restored["restore_receipt_sha256"], profile_pin, minimum)
                require(proof["current_scope"]["anchor_count"] == anchors
                        and proof["signed_snapshot_minimum_present"]
                        and (signer / "journal.sqlite3").read_bytes() == before,
                        "witness_sequence_handoff_changed_history")
                # Only this fixture variable changes. No app/system service is activated.
                control, handoffs = target, handoffs + 1

            def invariant():
                state = observer.status(control, profile_pin, minimum_receipt=minimum)
                require(state["receipt_sha256"] == minimum and state["anchor_count"] == anchors
                        and not state["pending"] and state["state"] in {"healthy", "unobserved"}
                        and state["unobserved_rows"] == source_rows - observed_rows
                        and not state["independent_storage_verified"]
                        and not state["automatic_activation_allowed"], "witness_sequence_control_model")
                require(source.integrity()["verified_lines"] == source_rows, "witness_sequence_audit_model")
                return state

            stopped_at_deadline = stopped_by_operator = False

            def should_stop():
                nonlocal stopped_at_deadline, stopped_by_operator
                stopped_at_deadline = stopped_at_deadline or (deadline is not None and time.monotonic() >= deadline)
                stopped_by_operator = stopped_by_operator or (output / "stop.request").exists()
                return stopped_at_deadline or stopped_by_operator

            for round_index in range(rounds):
                actions = list(ACTIONS)
                rng.shuffle(actions)
                for action in actions:
                    if should_stop():
                        break
                    last_action = action
                    if action == "append":
                        append(rng.randint(1, 3))
                    elif action == "cycle":
                        cycle()
                    elif action in {"lost_before", "lost_after"}:
                        lose(action == "lost_after")
                    elif action == "audit_rollback":
                        append(1)
                        cycle()
                        held = source.path.read_bytes()
                        before = (signer / "journal.sqlite3").read_bytes()
                        source.path.write_bytes(initial_audit)
                        try:
                            require(observer.status(control, profile_pin, minimum_receipt=minimum)["state"] == "unavailable",
                                    "witness_sequence_audit_rollback_not_red")
                            try:
                                observer.cycle(control, profile_pin, minimum_receipt=minimum)
                            except AuditTransferError:
                                pass
                            else:
                                raise AuditTransferError("witness_sequence_audit_rollback_signed")
                            require((signer / "journal.sqlite3").read_bytes() == before,
                                    "witness_sequence_audit_rollback_journal_changed")
                        finally:
                            source.path.write_bytes(held)
                        recover_cli(False)
                    elif action == "control_rollback":
                        if anchors == 0:
                            cycle()
                        held = (control / "observer.sqlite3").read_bytes()
                        before = (signer / "journal.sqlite3").read_bytes()
                        (control / "observer.sqlite3").write_bytes(initial_control)
                        try:
                            try:
                                observer.cycle(control, profile_pin, minimum_receipt=minimum)
                            except AuditTransferError:
                                pass
                            else:
                                raise AuditTransferError("witness_sequence_control_rollback_admitted")
                            require((signer / "journal.sqlite3").read_bytes() == before,
                                    "witness_sequence_control_rollback_journal_changed")
                        finally:
                            (control / "observer.sqlite3").write_bytes(held)
                    elif action in {"backup_handoff", "restore_resume"}:
                        handoff(action == "restore_resume")
                    else:
                        live = observer.status(control, profile_pin, minimum_receipt=minimum)
                        later = datetime.fromisoformat(live["observed_at"]) + timedelta(seconds=3601)
                        require(observer.status(control, profile_pin, minimum_receipt=minimum, now=later)["state"] == "stale"
                                and observer.status(control, profile_pin, minimum_receipt=minimum, offline=True)["healthy"] is False,
                                "witness_sequence_freshness_refreshed")
                    state = invariant()
                    trace.append({"step": len(trace) + 1, "round": round_index + 1, "action": action,
                                  "source_rows": source_rows, "observed_rows": observed_rows,
                                  "receipts": receipts, "anchors": anchors, "handoffs": handoffs,
                                  "state": state["state"], "minimum_receipt": minimum,
                                  "elapsed_seconds": round(time.monotonic() - started, 3), "passed": True})
                    with (output / "trace.jsonl").open("ab") as stream:
                        stream.write(canonical(trace[-1]) + b"\n")
                        stream.flush()
                        os.fsync(stream.fileno())
                    write_json("progress.json", {**common, "completed": False, "last": trace[-1]})
                    if delay_seconds:
                        until = time.monotonic() + delay_seconds
                        while time.monotonic() < until and not should_stop():
                            time.sleep(min(1, max(0, until - time.monotonic())))
                if should_stop():
                    break
            final = invariant()
            result = {**common, "completed": len(trace) == rounds * len(ACTIONS)
                      and not (stopped_at_deadline or stopped_by_operator),
                      "stopped_at_deadline": stopped_at_deadline, "stopped_by_operator": stopped_by_operator,
                      "steps": len(trace), "source_rows": source_rows, "observed_rows": observed_rows,
                      "receipts": receipts, "anchors": anchors, "handoffs": handoffs,
                      "final_state": final["state"], "elapsed_seconds": round(time.monotonic() - started, 3)}
        # Cleanup is part of success. Do not publish completed=true while a
        # Windows handle can still prevent fixture/key/DB removal.
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        result["finished_at"] = datetime.now(UTC).isoformat()
        write_json("report.json", result)
        return result
    except Exception as error:
        write_json("failure.json", {**common, "completed": False, "last_action": last_action,
                                    "completed_steps": len(trace), "error_type": type(error).__name__,
                                    "elapsed_seconds": round(time.monotonic() - started, 3)})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--seed", type=int, default=20261120)
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--delay-seconds", type=float, default=0)
    parser.add_argument("--max-seconds", type=int)
    args = parser.parse_args()
    result = run(args.directory, seed=args.seed, rounds=args.rounds,
                 delay_seconds=args.delay_seconds, max_seconds=args.max_seconds)
    print(json.dumps(result))
    return 0 if result["completed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
