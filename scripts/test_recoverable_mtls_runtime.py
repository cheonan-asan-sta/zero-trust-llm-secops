"""Exercise the application cutover in Docker with real restore process exits."""

import argparse
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from scripts.continuous_mtls_runtime import RuntimeFailure
from scripts.mtls_app_recovery import WRITERS
from scripts.recoverable_mtls_runtime import RecoverableRuntime
from scripts.test_continuous_mtls_runtime import Checks

RESTORE_EXITS = (
    """import os
from scripts import app_state_recovery as storage, mtls_app_recovery as manager
original = storage.atomic
def interrupt(path, data):
    if path.name == 'integration-outbox.jsonl' and path.parent.parent.name.startswith('app-restore-'):
        os._exit(73)
    original(path, data)
storage.atomic = interrupt
manager.restore()
""",
    """import os
from scripts import mtls_app_recovery as manager
original = manager.atomic
def interrupt(path, data):
    if path.name == 'phase.json':
        os._exit(73)
    original(path, data)
manager.atomic = interrupt
manager.restore()
""",
)

READ_STATE = """import json,sys
from pathlib import Path
from scripts.app_state_recovery import inspect_state, operations, read_file, sha
path = Path(sys.argv[1])
state = inspect_state(path)['state']
with operations(path)._transaction() as transaction:
    consumed = sum(entry['kind'] == 'access' and entry.get('allowed') is True for entry in transaction[1])
print(json.dumps({'logs': state['jsonl'], 'consumed': consumed, 'registry': sha(read_file('/signals/sources.json', 1024**2)),
                  'behavior_context': state['behavior_context'],
                  'inbox': {key: value for key, value in state['tables'].items() if key.startswith('signal_inbox')}}))
"""


class RecoveryChecks(Checks):
    def __init__(self, directory):
        super().__init__(directory, runtime_class=RecoverableRuntime)
        self.report["schema"] = "recoverable-mtls-verification-1"

    def read_state(self, path):
        return json.loads(self.runtime.execute("app", ["python", "-c", READ_STATE, path]))

    def backup_id(self):
        return self.runtime._container_job(
            ["-c", "from pathlib import Path; print(Path('/authority/backup.json').read_text())"],
            [("recovery-authority", "/authority", True)],
        )

    def rejected(self, operation, expected):
        try:
            operation()
        except RuntimeFailure as exc:
            self.require(str(exc) == expected, expected + "_wrong_failure")
        else:
            raise RuntimeFailure(expected + "_unexpected_success")

    def interrupted_restore(self, program, label):
        runtime = self.runtime
        original = runtime.recovery_job
        with patch.object(runtime, "recovery_job", lambda: original(["-c", program])):
            self.rejected(runtime.recover, "runtime_command_failed_73")
        self.require(runtime.phase() == {"phase": "maintenance"}, "failed_restore_published")
        self.require(all(not self.inspect(role)["State"]["Running"] for role in WRITERS), "writer_not_stopped")
        self.rejected(runtime.up, "mtls_recovery_requires_resume")
        self.add(label, exit_code=73, stopped=list(WRITERS), startup_blocked=True)

    def verify_mounts(self):
        runtime = self.runtime
        volumes = runtime.state["volumes"]
        for role in WRITERS:
            mounts = {row.get("Name"): row for row in self.inspect(role)["Mounts"]}
            self.require(volumes["data"] not in mounts and volumes["recovery-authority"] not in mounts
                         and mounts[volumes["recovery-public"]]["RW"] is False, "recovered_writer_scope")
            if role != "collector":
                self.require(mounts[volumes["recovered-data"]]["Destination"] == "/data"
                             and mounts[volumes["registry"]]["RW"] is False, "recovered_app_mount")
        self.add("approved_copy_mounted_without_original_data_or_backup_keys", writers=list(WRITERS))

    def wait_for_writers(self):
        runtime = self.runtime
        self.wait(lambda: all(runtime.status()["services"][role]["running"] for role in WRITERS),
                  "writers_not_running")
        self.wait(lambda: runtime.probe({"profile": "core", "path": "/health/live"})["status"] == 200,
                  "app_not_ready")

    def run(self):
        runtime = self.runtime
        runtime.up()
        self.report["source_commit"] = runtime.state["source_commit"]
        self.report["release_sha256"] = runtime.state["release"]["sha256"]
        self.require(runtime.state["release_image_payload_verified"], "image_payload_unverified")
        runtime.compose("stop", "app", "worker", "watchdog")
        runtime._container_job(
            ["-c", ("import json; from pathlib import Path; "
                    "from scripts.app_storage_fixture import seed_logs,seed_behavior_context; "
                    "p=Path('/source'); seed_behavior_context(p); print(json.dumps(seed_logs(p)))")],
            [("data", "/source", False)],
        )
        runtime.up()
        consumed = self.mint("restore-consumed")
        self.access(consumed, True, "pre_restore_grant_consumed_over_mtls")
        self.append("app-restore-inbox-history", active=True)
        self.wait(lambda: self.completed("app-restore-inbox-history"), "source_inbox_not_completed")
        receipt = self.receipt("app-restore-inbox-history")["body"]
        before = self.read_state("/data")
        self.require(before["consumed"] == 1 and before["inbox"] and before["logs"]
                     and before["behavior_context"]["records"] == 4, "source_history_missing")
        old = self.mint("restore-old")
        history = self.history(old[0])
        self.require(history[-1]["status"] == "ACTIVE", "source_session_inactive")

        self.interrupted_restore(RESTORE_EXITS[0], "restore_process_exit_during_jsonl_staging")
        backup = self.backup_id()
        runtime.compose("start", "app")
        self.wait(lambda: "MTLS_APP_RECOVERY_DENIED" in runtime.compose("logs", "--no-color", "app"),
                  "original_entrypoint_started_during_maintenance")
        self.add("direct_original_container_restart_refuses_maintenance")
        self.runtime = RecoverableRuntime(runtime.directory)
        self.interrupted_restore(RESTORE_EXITS[1], "restore_process_exit_before_approval")
        self.require(self.backup_id() == backup, "backup_changed_on_first_retry")

        self.runtime = runtime = RecoverableRuntime(runtime.directory)
        approved = runtime.recover()["recovery"]
        self.require(approved["phase"] == "approved" and self.backup_id() == backup, "backup_not_reused")
        self.add("fresh_runner_resumes_with_same_encrypted_backup")
        self.verify_mounts()
        after = self.history(old[0])
        self.require(after[:-1] == history and after[-1]["status"] == "REVOKED"
                     and after[-1]["version"] == history[-1]["version"] + 1, "session_history_not_preserved")
        self.require(self.receipt("app-restore-inbox-history")["body"] == receipt
                     and self.read_state("/data/active") == before, "application_history_not_preserved")
        self.add("session_inbox_registry_context_and_three_jsonl_histories_preserved",
                 session_versions=len(after), consumed_grants=before["consumed"],
                 jsonl_files=len(before["logs"]["files"]), inbox_tables=len(before["inbox"]),
                 context_records=before["behavior_context"]["records"])
        self.access(old, False, "pre_restore_unconsumed_token_returns_403")
        self.access(consumed, False, "pre_restore_consumed_token_returns_403")

        runtime.compose("restart", *WRITERS)
        self.wait_for_writers()
        self.require(runtime.phase() == approved and self.read_state("/data/active") == before
                     and self.history(old[0]) == after, "history_changed_on_restart")
        self.access(old, False, "pre_restore_token_stays_denied_after_writer_restart")
        fresh = self.mint("restore-fresh")
        self.access(fresh, True, "post_restore_fresh_grant_returns_200")
        self.require(runtime.recover()["recovery"] == approved, "approved_copy_replayed")
        self.access(fresh, False, "post_restore_consumption_survives_repeated_recover")
        self.append("app-restore-new-input", active=True)
        self.wait(lambda: self.completed("app-restore-new-input"), "restored_inbox_not_processing")
        self.add("restarted_collector_and_worker_process_new_input")
        self.report["completed"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    checks = RecoveryChecks(parser.parse_args().directory)
    try:
        checks.run()
    except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        checks.report["failure"] = str(exc) if isinstance(exc, RuntimeFailure) else type(exc).__name__
        if isinstance(exc, subprocess.TimeoutExpired):
            # Arguments and captured output may contain credentials or telemetry.
            argv = exc.cmd if isinstance(exc.cmd, (list, tuple)) else []
            checks.report["timeout"] = {
                "seconds": exc.timeout,
                "operation": next((name for name in ("build", "pull", "compose", "exec", "run")
                                   if name in argv[:6]), "unknown"),
                "helper_mode": next((name for name in ("probe", "mint", "append")
                                     if name in argv[-3:]), None),
                "after_check": checks.report["checks"][-1]["label"] if checks.report["checks"] else None,
            }
    finally:
        try:
            checks.cleanup()
        except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            checks.report.update(completed=False, cleanup_failed=True)
            checks.save()
    print(json.dumps({"completed": checks.report["completed"], "checks": len(checks.report["checks"]),
                      "failure": checks.report.get("failure")}))
    return 0 if checks.report["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
