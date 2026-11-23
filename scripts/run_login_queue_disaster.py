"""Exercise a fenced restore using three separate local Docker containers."""

import argparse
import json
import secrets
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from time import monotonic, sleep, time
from traceback import format_exc
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.services.audit_transfer import canonical, sha
from app.services.sqlite_audit import SQLiteAuditStore
from app.zero_trust_models import LoginDeliveryRequest
from scripts import login_queue_activation as activation
from scripts import login_queue_backup as backup
from scripts import login_queue_disaster_recovery as recovery
from scripts.evaluate_local_remote_holdout import write
from scripts.f1_lab.capture_backup import fresh_file
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.login_delivery_spool import LoginDeliverySpool
from scripts.run_login_queue_recovery import FIELDS, events, flagged
from scripts.run_login_queue_restore import AUDIT, COLLECTOR, QUEUE, TENANT, sender, service

ROOT = Path("/tmp/login-disaster-lab")
BRIDGE = Path("/exchange")
PORT = 8765
SCOPE = {"origin": f"http://127.0.0.1:{PORT}", "tenant_id": TENANT, "collector_subject": COLLECTOR}


@contextmanager
def rejected(error_type, message):
    try:
        yield
    except error_type as error:
        assert message in str(error)
    else:
        raise AssertionError(f"Expected rejection: {message}")


def until(callback, seconds=45):
    deadline = monotonic() + seconds
    while monotonic() < deadline:
        value = callback()
        if value is not None and value is not False:
            return value
        sleep(0.25)
    raise RuntimeError("Login disaster exercise condition timed out")


def load_bridge():
    return json.loads((BRIDGE / "snapshot.json").read_bytes())


def fixture_credentials(payload):
    ROOT.mkdir(mode=0o700, exist_ok=True)
    fresh_file(ROOT / "backup-key", bytes.fromhex(payload["backup_key"]))
    fresh_file(ROOT / "fixture-credentials.json", canonical(payload))


def login_body(event):
    return LoginDeliveryRequest(tenant_id=TENANT, collector_subject=COLLECTOR, event=event).model_dump(mode="json")


def source():
    payload = json.loads((ROOT / "fixture-credentials.json").read_bytes())
    site, control, cfg = ROOT / "active", ROOT / "control", ROOT / "config"
    for path in (site, control, cfg):
        path.mkdir(mode=0o700)
    BRIDGE.chmod(0o700)
    queue = LoginDeliverySpool(site / QUEUE, **SCOPE)
    store = SQLiteAuditStore(site / AUDIT)
    activation.initialize(control, queue.path, store.path, **SCOPE)
    before, expected = counts(), []
    cases = list(events(4))
    with service(
        cfg, PORT, payload["collector"], payload["reviewer"], control=control, startup_timeout=60,
    ) as (api, _, _):
        for event, truth in cases:
            result = api.post("/analysis", json=event.analysis_payload())
            result.raise_for_status()
            expected.append(result.json())
            record(before, truth, flagged(result.json()))
            activation.stage_login(control, event, None)
        # Commit one receipt while the original queue has not acknowledged it.
        committed = api.post("/analysis/login-delivery", json=login_body(cases[0][0]))
        committed.raise_for_status()
        assert not committed.json()["duplicate"] and queue.counts()["pending"] == 4
        pin = backup.backup(queue.path, store.path, BRIDGE / "archive.bin", ROOT / "backup-key", **SCOPE)
        checkpoint = recovery.Checkpoint(source_id=payload["source_id"], generation=1,
                                         package_sha256=pin["package_sha256"], **SCOPE)
        snapshot = {
            "checkpoint": checkpoint.model_dump(), "expected": expected, "before": metrics(before),
            "cases": [[event.analysis_payload(), truth] for event, truth in cases],
        }
        fresh_file(BRIDGE / "snapshot.json", canonical(snapshot))
        with sender(api, site, control) as collector, collector.replaying(interval=0.05):
            fresh_file(ROOT / "live", b"ready")
            sleep(300)


def source_live():
    failure = ROOT / "source-failure.log"
    if failure.is_file():
        raise RuntimeError(failure.read_text())
    if not (ROOT / "live").is_file():
        return {"ready": False}
    with rejected(activation.ActivationConflict, "sender.lock"), activation._lock(ROOT / "control", "sender.lock"):
        raise AssertionError("Source sender should hold the lock")
    return {"ready": True}


def run_source():
    try:
        source()
    except Exception:
        fresh_file(ROOT / "source-failure.log", format_exc().encode())
        raise


def enroll_authority():
    ROOT.mkdir(mode=0o700)
    key = Ed25519PrivateKey.generate()
    fresh_file(ROOT / "authority.key", key.private_bytes_raw())
    fresh_file(ROOT / "authority.pub", key.public_key().public_bytes_raw())
    checkpoint = recovery.Checkpoint.model_validate(load_bridge()["checkpoint"])
    recovery.enroll_authority(ROOT, checkpoint, sha(key.public_key().public_bytes_raw()))
    return {"public_key": key.public_key().public_bytes_raw().hex()}


def authority_issue(payload):
    from pydantic import ValidationError

    checkpoint = recovery.Checkpoint.model_validate(load_bridge()["checkpoint"])
    args = payload["evidence"]
    with rejected(ValidationError, "method"):
        recovery.FenceConfirmation.model_validate({**args, "method": "source_unreachable"})
    evidence = recovery.FenceConfirmation.model_validate(args)
    with rejected(activation.ActivationConflict, "different source"):
        recovery.issue(ROOT, ROOT / "authority.key", payload["standby"],
                       evidence.model_copy(update={"source_id": "unrelated"}))
    with rejected(activation.ActivationConflict, "outside the issue window"):
        recovery.issue(ROOT, ROOT / "authority.key", payload["standby"],
                       evidence.model_copy(update={"observed_at": evidence.observed_at - 1800}))
    wrong_key = ROOT / "wrong-authority.key"
    fresh_file(wrong_key, Ed25519PrivateKey.generate().private_bytes_raw())
    with rejected(activation.ActivationConflict, "does not match the authority enrollment"):
        recovery.issue(ROOT, wrong_key, payload["standby"], evidence)
    assert evidence.source_id == checkpoint.source_id
    pin = recovery.issue(ROOT, ROOT / "authority.key", payload["standby"], evidence)
    with rejected(FileExistsError, recovery.APPROVAL):
        recovery.issue(ROOT, ROOT / "authority.key", "a" * 32, evidence)
    return {"receipt": (ROOT / recovery.APPROVAL).read_text(), "pin": pin}


def standby_prepare(payload):
    fixture_credentials(payload)
    control = ROOT / "control"
    control.mkdir(mode=0o700)
    checkpoint = recovery.Checkpoint.model_validate(load_bridge()["checkpoint"])
    pub = bytes.fromhex(payload["public_key"])
    fresh_file(ROOT / "authority.pub", pub)
    standby = recovery.enroll_standby(control, checkpoint, sha(pub))
    candidate, package, key = ROOT / "candidate", BRIDGE / "archive.bin", ROOT / "backup-key"
    backup.restore(package, checkpoint.package_sha256, candidate, key, **SCOPE)
    with rejected(FileNotFoundError, "missing-receipt"):
        recovery.receive(control, ROOT / "missing-receipt", ROOT / "authority.pub", package, key, candidate)
    assert not (control / "selection.sqlite3").exists()
    with rejected(activation.ActivationConflict, "enrolled standby recovery method"):
        activation.initialize(control, candidate / QUEUE, candidate / AUDIT, handoff={"generation": 1}, **SCOPE)
    result = {"standby": standby, "without_fence_activation_blocked": True}
    if payload.get("routed"):
        readiness_key = Ed25519PrivateKey.generate()
        fresh_file(ROOT / "readiness.key", readiness_key.private_bytes_raw())
        result["readiness_pub"] = readiness_key.public_key().public_bytes_raw().hex()
    return result


def standby_recover(payload):
    from app.models import SecurityEvent

    snapshot = load_bridge()
    control, candidate, cfg = ROOT / "control", ROOT / "candidate", ROOT / "config"
    package, key, public_key = BRIDGE / "archive.bin", ROOT / "backup-key", ROOT / "authority.pub"
    receipt = ROOT / recovery.APPROVAL
    raw = payload["receipt"].encode()
    assert sha(raw) == payload["pin"]
    fresh_file(receipt, raw)
    altered = json.loads(raw)
    altered["decision"]["confirmation"]["record_id"] += "-altered"
    bad = ROOT / "bad-receipt.json"
    fresh_file(bad, canonical(altered))
    with rejected(activation.ActivationConflict, "signature is invalid"):
        recovery.receive(control, bad, public_key, package, key, candidate)
    wrong_standby = ROOT / "other-standby"
    wrong_standby.mkdir(mode=0o700)
    checkpoint = recovery.Checkpoint.model_validate(snapshot["checkpoint"])
    recovery.enroll_standby(wrong_standby, checkpoint, sha(public_key.read_bytes()))
    with rejected(activation.ActivationConflict, "different standby"):
        recovery.receive(wrong_standby, receipt, public_key, package, key, candidate)
    other_checkpoint = ROOT / "other-checkpoint"
    other_checkpoint.mkdir(mode=0o700)
    recovery.enroll_standby(other_checkpoint, checkpoint.model_copy(update={"generation": 2}), sha(public_key.read_bytes()))
    with rejected(activation.ActivationConflict, "different source checkpoint"):
        recovery.receive(other_checkpoint, receipt, public_key, package, key, candidate)
    assert recovery.receive(control, receipt, public_key, package, key, candidate) == 2
    selected = activation.status(control)
    assert selected["generations"][-1]["predecessor_state"] == "externally_fenced_host"
    assert selected["host_handoff"]["receipt"]["receipt_sha256"] == payload["pin"]
    with rejected(activation.ActivationConflict, "already initialized"):
        recovery.receive(control, receipt, public_key, package, key, candidate)
    spool = LoginDeliverySpool(candidate / QUEUE, **SCOPE, create=False)
    audit = SQLiteAuditStore.open_existing(candidate / AUDIT)
    assert audit.integrity()["verified_lines"] == 5 and spool.counts()["pending"] == 4
    credentials = json.loads((ROOT / "fixture-credentials.json").read_bytes())
    after = counts()
    cfg.mkdir(mode=0o700)
    result_summary = {
        "generation": 2, "restored_pending_events": 4, "pre_replay_audit_records": 5,
        "final_audit_records": 8, "duplicate_analysis_or_audit_records": 0,
        "invalid_signature_different_standby_and_checkpoint_rejected": True,
        "receipt_replay_rejected": True, "before": snapshot["before"],
    }
    readiness_key = ROOT / "readiness.key" if payload.get("routed") else None
    with service(cfg, PORT, credentials["collector"], credentials["reviewer"],
                 control=control, readiness_key=readiness_key, startup_timeout=60) as (api, _, _):
        with sender(api, candidate, control) as collector, collector.replaying(interval=0.05):
            until(lambda: spool.counts() == {"pending": 0, "held": 0})
        for (event, truth), expected in zip(snapshot["cases"], snapshot["expected"], strict=True):
            result = api.post("/analysis/login-delivery", json=login_body(SecurityEvent.model_validate(event)))
            result.raise_for_status()
            data = result.json()
            assert data["duplicate"] and all(data["result"][field] == expected[field] for field in FIELDS)
            record(after, truth, flagged(data["result"]))
        assert audit.integrity()["verified_lines"] == 8 and metrics(after) == snapshot["before"]
        result_summary["after"] = metrics(after)
        if readiness_key:
            fresh_file(ROOT / "standby-live.json", canonical(result_summary))
            sleep(300)
    return result_summary


def routed_standby():
    from app.models import SecurityEvent

    ready = json.loads((ROOT / "standby-live.json").read_bytes())
    latest = SQLiteAuditStore.open_existing(ROOT / "candidate" / AUDIT).integrity()["verified_lines"]
    event, _ = load_bridge()["cases"][0]
    body = SecurityEvent.model_validate(event)
    return {
        "summary": ready, "current_audit_records": latest, "request": login_body(body),
        "new_request": login_body(body.model_copy(update={"event_id": "post-fence-ingress-observation"})),
    }


def run_standby(payload):
    try:
        return standby_recover(payload)
    except Exception:
        if payload.get("routed"):
            fresh_file(ROOT / "standby-failure.log", format_exc().encode())
        raise


def hold_grant(payload):
    fresh_file(ROOT / "staged-grant.json", canonical(payload))


def start_staged_standby():
    return run_standby(json.loads((ROOT / "staged-grant.json").read_bytes()))


def docker(*args, stdin=None, check=True, timeout=40):
    return subprocess.run(["docker", *args], input=stdin, capture_output=True, check=check, timeout=timeout)


def phase(container, action, payload=None, *, detach=False):
    flags = ["-d"] if detach else ["-i"]
    process = docker("exec", *flags, container, "python", "-m", "scripts.run_login_queue_disaster", "--role", action,
                     stdin=None if payload is None else canonical(payload), timeout=75, check=False)
    if process.returncode:
        raise RuntimeError(f"{action}: {process.stderr.decode(errors='replace')[-2400:]}")
    return None if detach else json.loads(process.stdout)


def run(image, *, routed=False):
    repo = Path(__file__).resolve().parents[1]
    marker = "zt-login-dr-" + uuid4().hex[:12]
    label = "io.secops.fixture=" + marker
    volume = docker("volume", "create", "--label", label, marker).stdout.decode().strip()
    source_code = None
    created = []
    route_lab = None

    def node(role):
        mode = ",readonly" if role != "source" else ""
        node_id = docker(
            "run", "-d", "--pull=never", "--network", route_lab.network if route_lab and role != "authority" else "none",
            "--name", f"{marker}-{role}", "--label", label,
            "--mount", f"type=volume,source={source_code},target=/src,readonly",
            "--mount", f"type=volume,source={volume},target=/exchange{mode}",
            "--workdir", "/src", "-e", "PYTHONDONTWRITEBYTECODE=1", "--entrypoint", "python", image,
            "-c", "from threading import Event; Event().wait()",
        ).stdout.decode().strip()
        created.append(node_id)
        return node_id

    try:
        # Freeze only app and script source on the Docker filesystem. This
        # avoids repeated Python imports over a Windows bind mount.
        source_code = docker("volume", "create", "--label", label, marker + "-code").stdout.decode().strip()
        docker(
            "run", "--rm", "--pull=never", "--network", "none", "--label", label,
            "--mount", f"type=bind,source={repo},target=/checkout,readonly",
            "--mount", f"type=volume,source={source_code},target=/snapshot",
            "--entrypoint", "sh", image, "-c", "cp -R /checkout/app /checkout/scripts /snapshot/", timeout=150,
        )
        if routed:
            from scripts.run_login_queue_ingress import RouteLab

            route_lab = RouteLab(source_code, marker, label, image)
            route_lab.start()
        primary, standby, authority = (node(role) for role in ("source", "standby", "authority"))
        fixture = {"backup_key": secrets.token_hex(32), "collector": secrets.token_urlsafe(32),
                   "reviewer": secrets.token_urlsafe(32), "source_id": primary}
        phase(primary, "credentials", fixture)
        phase(primary, "source", detach=True)
        until(lambda: docker(
            "exec", primary, "sh", "-c", "test -f /tmp/login-disaster-lab/live -o -f /tmp/login-disaster-lab/source-failure.log",
            check=False,
        ).returncode == 0, seconds=100)
        assert phase(primary, "source-live")["ready"]
        pub = phase(authority, "authority-prepare")["public_key"]
        prepared = phase(standby, "standby-prepare", {**fixture, "public_key": pub, "routed": routed})
        if route_lab:
            checkpoint = phase(authority, "checkpoint")
            route_lab.prepare(primary, standby, fixture["collector"], checkpoint, prepared, pub)
            route_lab.pause()

        # The independent management plane remains reachable after the exact
        # disposable host has abruptly stopped. A stopped host alone is not fenced.
        docker("kill", "--signal", "KILL", primary)
        old = json.loads(docker("inspect", primary).stdout)[0]
        assert old["Id"] == primary and old["Config"]["Labels"]["io.secops.fixture"] == marker
        assert not old["State"]["Running"] and not old["State"]["Restarting"]
        if route_lab:
            route_lab.fence_source_proxy()
        docker("rm", primary)
        restarted = docker("start", primary, check=False)
        assert restarted.returncode and b"no such container" in restarted.stderr.lower()
        manager_view = json.loads(docker("inspect", standby).stdout)[0]
        assert manager_view["Id"] == standby and manager_view["State"]["Running"]
        evidence = {
            "source_id": primary, "method": "exact_instance_removed", "record_id": marker,
            "observed_at": int(time()), "restart_inhibited": True,
        }
        grant = phase(authority, "authority-issue", {"standby": prepared["standby"], "evidence": evidence})
        route_result = {}
        if route_lab:
            route_lab.verify_unready(grant)
            phase(standby, "hold-grant", {**grant, "routed": True})
            phase(standby, "start-staged-standby", detach=True)
            until(lambda: docker("exec", standby, "sh", "-c",
                                 "test -f /tmp/login-disaster-lab/standby-live.json -o -f /tmp/login-disaster-lab/standby-failure.log",
                                 check=False).returncode == 0, seconds=100)
            failure = docker("exec", standby, "cat", str(ROOT / "standby-failure.log"), check=False)
            if not failure.returncode:
                raise RuntimeError(failure.stdout.decode(errors="replace")[-2500:])
            ready = phase(standby, "routed-standby")
            result = ready["summary"]
            route_result = route_lab.promote(grant, ready["request"], ready["new_request"])
            final_count = phase(standby, "routed-standby")["current_audit_records"]
            assert ready["current_audit_records"] == 8 and final_count == 9
            route_result["audit_records_after_new_request_replayed"] = final_count
        else:
            result = phase(standby, "standby-recover", grant)
        assert docker("start", primary, check=False).returncode
        return {
            "scope": "separate Docker container processes and loopbacks on one local Docker daemon",
            "source_sender_held_original_lease": True,
            "source_terminated_without_planned_handoff": True,
            "source_exact_instance_cannot_restart": True,
            "without_fence_activation_blocked": prepared["without_fence_activation_blocked"],
            "off_host_authority_rejected_unreachable_wrong_source_stale_and_duplicate_confirmation": True,
            "wrong_signing_key_could_not_consume_authority_decision": True,
            "recovery": result, "aws_calls": 0, "paid_api_calls": 0,
            **({"ingress": route_result} if route_lab else {}),
        }
    finally:
        if route_lab:
            route_lab.stop()
        for node_id in created:
            docker("rm", "-f", node_id, check=False)
        docker("volume", "rm", volume)
        if route_lab:
            route_lab.finish()
        if source_code:
            docker("volume", "rm", source_code)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--image", default="secops-remaining-acceptance:9c83559")
    parser.add_argument("--routed", action="store_true", help="also verify the mTLS NGINX traffic switch")
    roles = {
        "credentials": fixture_credentials, "source": run_source, "source-live": source_live,
        "authority-prepare": enroll_authority, "authority-issue": authority_issue,
        "standby-prepare": standby_prepare, "standby-recover": run_standby,
        "checkpoint": lambda: load_bridge()["checkpoint"], "routed-standby": routed_standby,
        "hold-grant": hold_grant, "start-staged-standby": start_staged_standby,
    }
    parser.add_argument("--role", choices=roles, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.role:
        invocation = roles[args.role]
        accepts_payload = {"credentials", "authority-issue", "standby-prepare", "standby-recover", "hold-grant"}
        payload = sys.stdin.buffer.read() if args.role in accepts_payload else b""
        result = invocation(json.loads(payload)) if payload else invocation()
        print(json.dumps(result))
        return
    if args.output is None:
        parser.error("output is required")
    result = run(args.image, routed=args.routed)
    write(args.output, result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
