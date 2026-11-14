"""Real owned Linux process capture and signed local service/policy controls."""

import argparse
import base64
import hashlib
import json
import selectors
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.shared_execution_collector import (
    boot_id,
    executable_hash,
    runtime_proof,
    snapshot_process,
)
from scripts.f1_lab.shared_execution_evidence import (
    PinnedServiceRegistry,
    PolicyObservation,
    ServiceAuthority,
    ServiceEvent,
    ServiceEvidenceJoiner,
    ServiceProof,
    ServiceRegistry,
    VerifiedServiceRisk,
    digest,
    proof_bytes,
)

FIXTURE = "import sys;print('service-fixture-ready',flush=True);sys.stdin.buffer.read(1)"


def sign_policy(event, observation, key, *, observed_at, issued_at):
    proof = ServiceProof(
        tenant_id=event.tenant_id,
        source_id="local-policy",
        key_id="policy-1",
        event_sha256=event.sha256,
        observed_at=observed_at,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=30),
        observation=observation,
        signature="A" * 86,
    )
    return proof.model_copy(
        update={
            "signature": base64.urlsafe_b64encode(key.sign(proof_bytes(proof))).decode().rstrip("=")
        }
    )


def setup(directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = {kind: Ed25519PrivateKey.generate() for kind in ["runtime", "authorization"]}
    now = datetime.now(UTC)
    authorities = []
    for kind, key in keys.items():
        public = (
            base64.urlsafe_b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
            .decode()
            .rstrip("=")
        )
        authorities.append(
            ServiceAuthority(
                tenant_id="local-lab",
                server_id="shared-lab",
                source_id="local-proc" if kind == "runtime" else "local-policy",
                key_id="proc-1" if kind == "runtime" else "policy-1",
                kind=kind,
                mode="local_process_lab",
                units=["shared-fixture.service"],
                public_key=public,
                enabled=True,
                issued_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
    registry = ServiceRegistry(
        version=1,
        policy_sha256=digest({"action": "run_service_process", "fixture": 1}),
        minimum_policy_version=1,
        authorities=authorities,
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )
    path = directory / "registry.json"
    path.write_bytes(canonical(registry.model_dump(mode="json")) + b"\n")
    pinned = PinnedServiceRegistry(path, hashlib.sha256(path.read_bytes()).hexdigest())
    return keys, registry, pinned


def capture_case(keys, registry, *, decision="allow"):
    """Only this hardcoded fixture is launched. No caller command is executed."""
    argv = [sys.executable, "-u", "-c", FIXTURE]
    expected_command = hashlib.sha256(b"".join(v.encode() + b"\0" for v in argv)).hexdigest()
    expected_executable = executable_hash(Path(sys.executable))
    policy = PolicyObservation(
        decision=decision,
        policy_sha256=registry.policy_sha256,
        policy_version=1,
        executable_sha256=expected_executable,
        command_sha256=expected_command,
    )
    policy_time = datetime.now(UTC)  # Actual local policy observation, before launch.
    process = subprocess.Popen(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            require(bool(selector.select(5)), "service_fixture_ready_timeout")
            require(
                process.stdout.readline(64) == b"service-fixture-ready\n",
                "service_fixture_handshake",
            )
        event_time = datetime.now(UTC)
        invocation = uuid.uuid4().hex
        receipt = {
            "unit": "shared-fixture.service",
            "pid": process.pid,
            "invocation": invocation,
            "command": expected_command,
        }
        event = ServiceEvent(
            tenant_id="local-lab",
            server_id="shared-lab",
            unit="shared-fixture.service",
            boot_id=boot_id(),
            invocation_id=invocation,
            process_id=process.pid,
            event_id=digest(receipt),
            raw_sha256=digest(receipt),
            observed_at=event_time,
            mode="local_process_lab",
            collection_basis="local_process_lab",
        )
        boot, observation = snapshot_process(process.pid)
        require(
            boot == event.boot_id
            and observation.command_sha256 == expected_command
            and observation.executable_sha256 == expected_executable,
            "service_actual_process_mismatch",
        )
        runtime = runtime_proof(
            event, observation, keys["runtime"], source_id="local-proc", key_id="proc-1"
        )
        permission = sign_policy(
            event,
            policy,
            keys["authorization"],
            observed_at=policy_time,
            issued_at=datetime.now(UTC),
        )
        return event, [runtime, permission]
    finally:
        if process.poll() is None:
            process.stdin.write(b"x")
            process.stdin.flush()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
        require(process.returncode == 0, "service_fixture_did_not_stop_cleanly")


def run(directory):
    directory = Path(directory)
    keys, registry, pinned = setup(directory)
    report = {
        "schema": "extra-shared-execution-controls-1",
        "completed": False,
        "paid_api_calls": 0,
        "aws_calls": 0,
        "scope": "real local process observations and controlled policy cases; not independent attack performance",
        "goal_qualified": False,
        "production_systemd_integration_tested": False,
        "cases": [],
    }
    joiner = ServiceEvidenceJoiner(
        pinned, directory / "evidence.sqlite3", expected_mode="local_process_lab"
    )
    adapter = VerifiedServiceRisk(joiner)
    previous = OperationDecision(0.1, 0.1, False, False, "unchanged")

    def check(name, condition):
        require(condition, "service_control_expected_outcome_" + name)
        report["cases"].append({"name": name, "passed": True})

    try:
        allowed, proofs = capture_case(keys, registry, decision="allow")
        result = adapter.decide(previous, event=allowed, proofs=proofs)
        check("actual_allowed_process_does_not_add_alarm", result is previous)
        denied, badproofs = capture_case(keys, registry, decision="deny")
        result = adapter.decide(previous, event=denied, proofs=badproofs)
        check(
            "actual_process_conflicts_with_prior_denial",
            result.alert and result.review and not result.automatic_enforcement_allowed,
        )
        restarted = ServiceEvidenceJoiner(
            pinned, directory / "evidence.sqlite3", expected_mode="local_process_lab"
        )
        check(
            "restart_duplicate_is_bound_and_idempotent",
            restarted.check(denied, badproofs).duplicate,
        )
        check("missing_native_evidence_keeps_baseline", adapter.decide(previous) is previous)
        wrong = denied.model_copy(update={"invocation_id": uuid.uuid4().hex})
        check(
            "different_invocation_cannot_borrow_proof",
            adapter.decide(previous, event=wrong, proofs=badproofs) is previous,
        )
        future = badproofs[1].model_copy(
            update={"observed_at": denied.observed_at + timedelta(seconds=1)}
        )
        check(
            "post_event_policy_is_rejected",
            adapter.decide(previous, event=denied, proofs=[badproofs[0], future]) is previous,
        )
        production = VerifiedServiceRisk(
            ServiceEvidenceJoiner(pinned, directory / "production-mode.sqlite3")
        )
        check(
            "lab_evidence_cannot_satisfy_systemd_mode",
            production.decide(previous, event=denied, proofs=badproofs) is previous,
        )
        report.update(
            completed=True,
            normal_controls=1,
            normal_added_alerts=0,
            adverse_controls=1,
            adverse_detected=1,
            owned_child_processes_stopped=True,
            private_keys_persisted=False,
            plaintext_commands_persisted=False,
            actual_observation_fields=sorted(type(proofs[0].observation).model_fields),
            actor_collection={
                "uid_read_from_proc": True,
                "login_uid_present": proofs[0].observation.login_uid is not None,
                "audit_session_present": proofs[0].observation.audit_session_id is not None,
                "parent_reference_present": proofs[0].observation.parent_ref_sha256 is not None,
                "authenticated_human_identity_proven": False,
            },
        )
    finally:
        (directory / "run.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    result = run(args.directory)
    print(
        json.dumps(
            {
                "completed": result["completed"],
                "cases": len(result["cases"]),
                "normal_added_alerts": result["normal_added_alerts"],
                "adverse_detected": result["adverse_detected"],
            }
        )
    )


if __name__ == "__main__":
    main()
