"""Free, isolated Docker maintenance-recovery experiment; no host ports or cloud."""

import argparse
import hashlib
import json
import secrets
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from scripts.app_state_recovery import ROOT, app_digest, canonical, require, sha

SOURCE_FILES = ("scripts/app_state_recovery.py", "scripts/app_recovery_fixture.py",
                "scripts/serve_recovered_app.py", "scripts/test_app_recovery_runtime.py",
                "scripts/app_storage_contract.py", "scripts/app_storage_fixture.py")


def fingerprint():
    return {"application": app_digest(), "scripts": {
        name: sha((ROOT / name).read_bytes().replace(b"\r\n", b"\n")) for name in SOURCE_FILES}}


class Lab:
    def __init__(self, image, *, full_state=False):
        self.full_state = full_state
        self.image = self.command("image", "inspect", image)[0]["Id"]
        self.owner = "app-recovery-" + secrets.token_hex(6)
        self.volumes = {name: self.owner + "-" + name for name in ("data", "control", "public", "backups", "restores")}
        self.containers = []
        self.writers = []
        self.timings = {}
        self.checks = {}
        self.api_key = secrets.token_urlsafe(32)

    @staticmethod
    def run(*args, input=None, ok=True):
        result = subprocess.run(["docker", *args], input=input, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=120, check=False)
        if ok and result.returncode:
            # Docker/application stderr may include sensitive artifacts: never echo it.
            raise RuntimeError("docker_operation_failed")
        return result

    @classmethod
    def command(cls, *args):
        return json.loads(cls.run(*args).stdout)

    def common(self, name, mounts):
        args = ["--name", name, "--label", "secops.app-recovery=" + self.owner,
                "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--memory", "256m", "--cpus", "1", "--pids-limit", "128", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
                "-e", "APP_ENVIRONMENT=test", "-e", "ANALYZER_MODE=rule", "-e", "PYTHONDONTWRITEBYTECODE=1"]
        for volume, target, readonly in mounts:
            args += ["--mount", "type=volume,source=" + self.volumes[volume] + ",target=" + target + (",readonly" if readonly else "")]
        return args

    def job(self, code, *, stopped=True, ok=True):
        if stopped:
            self.fence()
        name = self.owner + "-job-" + secrets.token_hex(4)
        self.containers.append(name)
        args = self.common(name, [(key, "/lab/" + key, False) for key in self.volumes])
        # Override the base image's /data VOLUME with a bounded tmpfs.
        args += ["--tmpfs", "/data:rw,nosuid,nodev,size=1m", "--user", "10001:10001"]
        result = self.run("run", "--rm", *args, self.image, "python", "-c", code, ok=ok)
        return result

    def invoke(self, operation, backup=None, denied=None):
        code = ("import json; from scripts.app_state_recovery import Store; from pathlib import Path; "
                "s=Store(Path('/lab')); print(json.dumps(s." + operation +
                ("(" + repr(backup) + ")" if backup else
                 "(full_state=True)" if operation == "initialize" and self.full_state else "()") + "))")
        if denied:
            code = ("import sys,json; from scripts.app_state_recovery import RecoveryError\ntry:\n    " + code +
                    "\nexcept RecoveryError as error:\n    print(json.dumps({'denied':str(error)})); sys.exit(3)")
        started = time.perf_counter()
        result = self.job(code, ok=not denied)
        self.timings[operation] = round(time.perf_counter() - started, 4)
        if denied:
            require(result.returncode == 3 and json.loads(result.stdout) == {"denied": denied}, "wrong_recovery_denial")
            return None
        return json.loads(result.stdout)

    def fence(self):
        # Scope is this lab's complete writer inventory, not arbitrary host workloads.
        for ident, expected_mounts in self.writers:
            item = self.command("inspect", ident)[0]
            require(item["Id"] == ident and item["Config"]["Labels"]["secops.app-recovery"] == self.owner,
                    "writer_identity")
            actual = {row["Name"] for row in item["Mounts"] if row["Type"] == "volume"}
            require(actual == expected_mounts and not item["State"]["Running"], "writer_not_fenced")

    def start(self, *, restore_id=None, wrong_storage=False):
        name = self.owner + ("-restored-" + secrets.token_hex(3) if restore_id else "-source")
        data = "/recovered/" + restore_id if restore_id else "/lab/data"
        mounts = [("restores", "/recovered", False), ("public", "/public", True)] if restore_id else [("data", data, False)]
        args = self.common(name, mounts)
        env = {"AUTH_MODE": "api_key", "API_KEY_SHA256": hashlib.sha256(self.api_key.encode()).hexdigest(),
               "API_KEY_SUBJECT": "recovery-test", "API_KEY_TENANT_ID": "recovery-tenant", "API_KEY_ROLES": "admin",
               "ZERO_TRUST_DB_PATH": data + "/app.sqlite3", "TRUSTED_SIGNAL_SOURCES_PATH": data + "/sources.json",
               "AUDIT_LOG_PATH": "/tmp/audit.jsonl", "CASE_LOG_PATH": "/tmp/cases.jsonl", "OUTBOX_LOG_PATH": "/tmp/outbox.jsonl"}
        if self.full_state:
            env.update(AUDIT_BACKEND="jsonl", AUDIT_LOG_PATH=data + "/audit.jsonl",
                       CASE_LOG_PATH=data + "/cases.jsonl", OUTBOX_LOG_PATH=data + "/integration-outbox.jsonl")
        if wrong_storage:
            env["OUTBOX_LOG_PATH"] = "/tmp/outbox.jsonl"
        for key, value in env.items():
            args += ["-e", key + "=" + value]
        args += ["--tmpfs", "/data:rw,nosuid,nodev,size=1m", "--user", "10001:10001"]
        command = (["python", "-m", "scripts.serve_recovered_app", "--data", data, "--public", "/public"]
                   if restore_id else ["uvicorn", "app.main:app", "--host", "127.0.0.1", "--no-access-log"])
        self.containers.append(name)
        ident = self.run("run", "-d", *args, self.image, *command).stdout.strip()
        self.writers.append((ident, {self.volumes[key] for key, _, _ in mounts}))
        return ident

    def ready(self, ident):
        started = time.monotonic()
        while time.monotonic() - started < 30:
            result = self.run("exec", ident, "python", "-c",
                "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live',timeout=1)", ok=False)
            if result.returncode == 0:
                return
            require(self.command("inspect", ident)[0]["State"]["Running"], "workload_start_failed")
            time.sleep(.2)
        raise RuntimeError("workload_start_deadline")

    def cleanup(self):
        for name in reversed(self.containers):
            # Random names and labels both must match before deleting any existing object.
            result = self.run("inspect", name, ok=False)
            if result.returncode == 0:
                item = json.loads(result.stdout)[0]
                require(item["Config"]["Labels"].get("secops.app-recovery") == self.owner, "cleanup_owner")
                self.run("rm", "-f", item["Id"])
        for volume in self.volumes.values():
            result = self.run("volume", "inspect", volume, ok=False)
            if result.returncode == 0:
                require(json.loads(result.stdout)[0]["Labels"].get("secops.app-recovery") == self.owner, "cleanup_volume_owner")
                self.run("volume", "rm", volume)
        containers = self.run("ps", "-aq", "--filter", "label=secops.app-recovery=" + self.owner).stdout.split()
        volumes = self.run("volume", "ls", "-q", "--filter", "label=secops.app-recovery=" + self.owner).stdout.split()
        return {"containers": len(containers), "volumes": len(volumes)}

    def experiment(self):
        for volume in self.volumes.values():
            self.run("volume", "create", "--label", "secops.app-recovery=" + self.owner, volume)
        name = self.owner + "-init"
        self.containers.append(name)
        args = self.common(name, [(key, "/lab/" + key, False) for key in self.volumes])
        self.run("run", "--rm", *args, "--user", "0:0", "--cap-add", "CHOWN", "--tmpfs", "/data:size=1m",
            self.image, "python", "-c", "import os; from pathlib import Path; "
            "[os.chown(p,10001,10001) for p in Path('/lab').iterdir()]")
        actual = json.loads(self.job("import json; from scripts.test_app_recovery_runtime import fingerprint; print(json.dumps(fingerprint()))").stdout)
        require(actual == fingerprint(), "image_source_mismatch")
        self.checks["image_source_matches"] = True
        self.job("from pathlib import Path; from scripts.app_recovery_fixture import prepare; prepare(Path('/lab/data'))")
        if self.full_state:
            self.job("from pathlib import Path; import json; from scripts.app_storage_fixture import seed_logs; "
                "p=Path('/lab/data'); expected=seed_logs(p); f=json.loads((p/'fixture.json').read_bytes()); "
                "f['jsonl']=expected; (p/'fixture.json').write_text(json.dumps(f))")
        self.invoke("initialize")
        source = self.start()
        self.ready(source)
        try:
            self.invoke("checkpoint")
        except RuntimeError as error:
            require(str(error) == "writer_not_fenced", "unexpected_fence_failure")
            self.checks["running_source_refused"] = True
        else:
            raise RuntimeError("live_writer_not_rejected")
        self.run("stop", source)
        self.invoke("checkpoint")
        backup = self.invoke("backup")
        # A private, temporary unfenced control proves that TTL alone cannot pass the test.
        control = self.job("from pathlib import Path; import tempfile,json; from datetime import datetime,timedelta; "
            "from scripts.app_state_recovery import snapshot,operations,require; from scripts.app_recovery_fixture import access; "
            "t=tempfile.TemporaryDirectory(); p=Path(t.name)/'control'; snapshot(Path('/lab/data'),p); "
            "f=json.loads(Path('/lab/data/fixture.json').read_bytes()); "
            "require(access(operations(p),'pending',f['tokens']['pending'],datetime.fromisoformat(f['now'])+timedelta(seconds=1)).allowed,'negative_control')")
        self.checks["unfenced_control_still_allows"] = control.returncode == 0
        # Demonstrate rejection of a state that predates a newly consumed grant.
        self.job("import json; from pathlib import Path; from datetime import datetime; "
            "from scripts.app_state_recovery import operations,require; from scripts.app_recovery_fixture import access; "
            "f=json.loads(Path('/lab/data/fixture.json').read_bytes()); "
            "require(access(operations(Path('/lab/data')),'pending',f['tokens']['pending'],datetime.fromisoformat(f['now'])).allowed,'consume')")
        self.checks["changed_source_backup_refused"] = self.invoke("backup", denied="source_advanced_since_checkpoint") is None
        fault = self.job("""import json
from pathlib import Path
from scripts import app_state_recovery as r
original=r.atomic
def fail(path,body):
    if path.name=='checkpoint.json': raise OSError('synthetic publication failure')
    original(path,body)
r.atomic=fail
try: r.Store(Path('/lab')).checkpoint()
except OSError: print(json.dumps({'checkpoint_write_failed':True}))
else: raise RuntimeError('fault_not_injected')
""")
        self.checks["checkpoint_write_failure_injected"] = json.loads(fault.stdout)["checkpoint_write_failed"]
        self.checks["incomplete_checkpoint_refuses_old_restore"] = self.invoke("restore", backup["backup_id"],
            denied="checkpoint_publication_incomplete") is None
        self.checks["incomplete_checkpoint_refuses_backup"] = self.invoke("backup",
            denied="checkpoint_publication_incomplete") is None
        self.invoke("checkpoint")
        self.checks["old_backup_refused"] = self.invoke("restore", backup["backup_id"], denied="backup_stale_or_foreign") is None
        backup = self.invoke("backup")
        self.job("from pathlib import Path; import json; p=next(Path('/lab/backups').glob('" + backup["backup_id"] + ".sealed')); "
            "v=json.loads(p.read_bytes()); p.with_suffix('.original').write_bytes(p.read_bytes()); "
            "v['manifest']['generation']+=1; p.write_text(json.dumps(v))")
        self.checks["tampered_backup_refused"] = self.invoke("restore", backup["backup_id"], denied="artifact_authentication_failed") is None
        self.job("from pathlib import Path; p=Path('/lab/backups/" + backup["backup_id"] + ".sealed'); "
                 "p.write_bytes(p.with_suffix('.original').read_bytes())")
        # Kill and remove the old application before destroying its actual DB files.
        self.run("rm", source)
        self.writers = []
        self.job("from pathlib import Path; p=Path('/lab/data'); "
            "[(p/name).unlink(missing_ok=True) for name in ('app.sqlite3','app.sqlite3-wal','app.sqlite3-shm','sources.json')" +
            ("+('storage.json','audit.jsonl','cases.jsonl','integration-outbox.jsonl')" if self.full_state else "") + "]; "
            "assert not (p/'app.sqlite3').exists()")
        self.checks["original_database_destroyed"] = True
        outage = time.perf_counter()
        restored = self.invoke("restore", backup["backup_id"])
        stage = "/lab/restores/" + restored["restore_id"]
        if self.full_state:
            fault = self.job("""import os
from pathlib import Path
from scripts import app_state_recovery as r
original=r.atomic
def fail(path,raw):
    if path.name=='integration-outbox.jsonl': os._exit(73)
    original(path,raw)
r.atomic=fail
r.Store(Path('/lab')).restore(""" + repr(backup["backup_id"]) + ")", ok=False)
            self.checks["full_storage_mid_restore_process_exit"] = fault.returncode == 73
            denied = self.job("from pathlib import Path; from scripts.app_state_recovery import verify_admission; "
                "verify_admission(Path('" + stage + "'),Path('/lab/public'))", ok=False)
            self.checks["full_storage_interrupted_restore_fences_previous_copy"] = denied.returncode != 0
            restored = self.invoke("restore", backup["backup_id"])
            stage = "/lab/restores/" + restored["restore_id"]
            result = self.job("import json; from pathlib import Path; from scripts.app_storage_contract import inspect; "
                "from scripts.app_state_recovery import require; p=Path('" + stage + "'); "
                "f=json.loads(Path('/lab/data/fixture.json').read_bytes()); "
                "require(inspect(p)==f['jsonl'],'full_storage_state_changed'); print(json.dumps({'preserved':True}))")
            self.checks["full_storage_bytes_heads_and_delivery_state_preserved"] = json.loads(result.stdout)["preserved"]
            wrong = self.start(restore_id=restored["restore_id"], wrong_storage=True)
            self.run("wait", wrong)
            self.checks["full_storage_wrong_path_denied_before_http"] = self.command("inspect", wrong)[0]["State"]["ExitCode"] != 0
        result = self.job("import json; from pathlib import Path; from scripts.app_recovery_fixture import verify; "
            "print(json.dumps(verify(Path('" + stage + "'),Path('/lab/data'))))")
        self.checks["fixed_clock_old_grants_denied"] = json.loads(result.stdout)["old_grants_denied"] == 3
        payload = json.loads(self.job("from pathlib import Path; print(Path('/lab/data/fixture.json').read_text())").stdout)
        ident = self.start(restore_id=restored["restore_id"])
        self.ready(ident)
        self.timings["restore_to_http_ready"] = round(time.perf_counter() - outage, 4)
        item = self.command("inspect", ident)[0]
        self.checks["workload_has_no_control_keys"] = {m["Name"] for m in item["Mounts"] if m["Type"] == "volume"} == {
            self.volumes["restores"], self.volumes["public"]}
        self.checks["public_trust_is_readonly"] = any(m["Destination"] == "/public" and not m["RW"] for m in item["Mounts"])
        self.checks["network_isolated_no_ports"] = item["HostConfig"]["NetworkMode"] == "none" and not item["HostConfig"]["PortBindings"]
        # The raw synthetic key/token cross stdin only; logs never contain them.
        probe = """import sys,json,urllib.request,urllib.error
v=json.load(sys.stdin)
for name,token in v['tokens'].items():
    body=json.dumps({'session_id':name,'resource_id':'zt-demo-documents','action':'READ','grant_token':token}).encode()
    request=urllib.request.Request('http://127.0.0.1:8000/zero-trust/protected-access',data=body,headers={'Content-Type':'application/json','X-API-Key':v['key']})
    try: urllib.request.urlopen(request,timeout=3); raise RuntimeError('unexpected_allow')
    except urllib.error.HTTPError as e:
        assert e.code==403 and json.load(e)['reason_code']=='SESSION_NOT_AUTHORIZED'
print(json.dumps({'denied':3}))
"""
        response = self.run("exec", "-i", ident, "python", "-c", probe,
                            input=json.dumps({"tokens": payload["tokens"], "key": self.api_key}))
        self.checks["real_authenticated_http_denies_old_grants"] = json.loads(response.stdout)["denied"] == 3
        if self.full_state:
            probe = """import sys,json,urllib.request
key=json.load(sys.stdin)['key']
def get(path):
    r=urllib.request.Request('http://127.0.0.1:8000'+path,headers={'X-API-Key':key})
    return json.load(urllib.request.urlopen(r,timeout=3))
cases=get('/cases?limit=100'); rows=get('/integrations/outbox?limit=100')
assert len(cases)==1 and len(rows)==4
assert {row['status'] for row in rows}=={'PENDING','DELIVERED','RETRY_SCHEDULED','DEAD_LETTER'}
assert all(row['event']['tenant_id']=='recovery-tenant' for row in rows)
print(json.dumps({'tenant_state_preserved':True}))
"""
            response = self.run("exec", "-i", ident, "python", "-c", probe,
                                input=json.dumps({"key": self.api_key}))
            self.checks["full_storage_real_http_cases_and_outbox_isolate_tenant"] = json.loads(response.stdout)["tenant_state_preserved"]
        self.run("stop", ident)
        if self.full_state:
            result = self.job("""import asyncio,json
from pathlib import Path
from scripts.app_storage_contract import FILES,inspect
from scripts.app_state_recovery import verify_admission,require
from app.services.cases import CaseStore
from app.services.integration_outbox import IntegrationOutboxStore,IntegrationOutboxService
p=Path(""" + repr(stage) + """)
before=inspect(p)
for _ in range(2):
    cases=CaseStore(p/FILES['cases'])
    service=IntegrationOutboxService(IntegrationOutboxStore(p/FILES['outbox']))
    for tenant in ('recovery-tenant','unrelated-tenant'):
        require(asyncio.run(service.reconcile_cases(cases.recent(100,tenant)))==(0,4),'duplicate_after_restore')
require(inspect(p)==before,'reconcile_changed_delivery_state')
verify_admission(p,Path('/lab/public'))
print(json.dumps({'reconciled':True}))
""")
            self.checks["full_storage_reconcile_twice_after_reopen_preserves_ids_and_attempts"] = json.loads(result.stdout)["reconciled"]
        self.job("from pathlib import Path; from scripts.app_state_recovery import verify_admission; "
                 "verify_admission(Path('" + stage + "'),Path('/lab/public'))")
        self.checks["audit_descendant_restart_admitted"] = True
        # Invalid release must exit before uvicorn exposes even loopback HTTP.
        self.job("from pathlib import Path; import json; p=Path('" + stage + "/release.json'); "
                 "v=json.loads(p.read_bytes()); v['release']['generation']+=1; p.write_text(json.dumps(v))")
        denied = self.start(restore_id=restored["restore_id"])
        self.run("wait", denied)
        state = self.command("inspect", denied)[0]["State"]
        self.checks["tampered_admission_exits_before_serving"] = not state["Running"] and state["ExitCode"] != 0
        logs = self.run("logs", denied)
        self.checks["tampered_admission_reports_expected_denial"] = "RECOVERY_ADMISSION_DENIED" in logs.stderr
        return {"backup_bytes_plaintext": backup["plaintext_bytes"], "jsonl_bytes": backup["jsonl_bytes"],
                "source_records": restored["source_records"],
                "fenced_sessions": restored["fenced_sessions"], "rpo_at_stopped_checkpoint_records": 0,
                "rpo_scope": "Only the fully stopped, witnessed lab writer boundary; no online RPO promise."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--full-state", action="store_true", help="Include audit, cases and outbox recovery")
    args = parser.parse_args()
    directory = args.directory.resolve()
    require(directory.is_relative_to((ROOT / "runtime/week3").resolve()) and not directory.exists(), "fresh_local_lab_required")
    directory.mkdir(parents=True)
    report = {"schema": "app-maintenance-recovery-1", "started_at": datetime.now(UTC).isoformat(),
              "source": fingerprint(), "base_git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True).strip()),
              "execution": "Chaeheeju / Codex tools; local Docker; rule analyzer; synthetic data", "passed": False}
    report["full_state"] = args.full_state
    if args.full_state:
        report["execution"] = "Local Docker; rule analyzer; synthetic data"
    lab = Lab(args.image, full_state=args.full_state)
    report["image_id"] = lab.image
    failure = None
    try:
        report["result"] = lab.experiment()
        report["passed"] = bool(lab.checks) and all(lab.checks.values())
    except (RuntimeError, OSError, ValueError, TypeError, LookupError, subprocess.SubprocessError) as error:
        report["error_type"] = type(error).__name__
        failure = error
    finally:
        report["cleanup"] = lab.cleanup()
        report["checks"], report["seconds"] = lab.checks, lab.timings
        report["passed"] &= report["cleanup"] == {"containers": 0, "volumes": 0}
        report["finished_at"] = datetime.now(UTC).isoformat()
        (directory / "verification.json").write_bytes(canonical(report) + b"\n")
    print(json.dumps(report, indent=2))
    if failure is not None:
        raise RuntimeError("app_recovery_experiment_failed; see redacted verification.json") from None
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
