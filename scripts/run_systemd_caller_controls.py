"""Local OIDC fixture plus real systemd integration. No real person login."""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.service_caller_identity import (
    PinnedCallerRegistry,
    ServiceCallerBroker,
    receipt_bytes,
    verify_receipt,
)
from scripts.f1_lab.shared_execution_collector import (
    READ_ENV,
    collect_latest_systemd,
    executable_hash,
)
from scripts.f1_lab.shared_execution_evidence import (
    PinnedServiceRegistry,
    PolicyObservation,
    ServiceEvidenceJoiner,
    VerifiedServiceRisk,
)
from scripts.f1_lab.systemd_request_launcher import SystemdUnitLauncher, UnitTarget
from scripts.run_shared_execution_controls import setup, sign_policy

FIXTURE = "import time;print('secops-fixture-ready',flush=True);time.sleep(90)"
ISSUER = "https://local-caller.invalid"


def setup_broker(directory, unit):
    keys, registry, _ = setup(directory)
    registry = registry.model_copy(
        update={
            "authorities": [
                a.model_copy(update={"mode": "systemd", "units": [unit]})
                for a in registry.authorities
            ]
        }
    )
    path = Path(directory) / "registry.json"
    path.write_bytes(canonical(registry.model_dump(mode="json")))
    service = PinnedServiceRegistry(path, hashlib.sha256(path.read_bytes()).hexdigest())
    identity_key = generate_private_key(public_exponent=65537, key_size=2048)
    broker_key = Ed25519PrivateKey.generate()
    exported = jwt.algorithms.RSAAlgorithm.to_jwk(identity_key.public_key(), as_dict=True)
    jwk = {name: exported[name] for name in ("kty", "n", "e")}
    jwk.update(kid="fixture-rsa-1", use="sig", alg="RS256")
    public = (
        base64.urlsafe_b64encode(
            broker_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        .decode()
        .rstrip("=")
    )
    now = datetime.now(UTC)
    identity = {
        "version": 1,
        "environment": "local_oidc",
        "issuer": ISSUER,
        "audience": "local-systemd-broker",
        "jwks": {"keys": [jwk]},
        "subjects": [
            {
                "subject": "fixture-person",
                "tenant_id": "local-lab",
                "kind": "person",
                "enabled": True,
            },
            {
                "subject": "fixture-machine",
                "tenant_id": "local-lab",
                "kind": "workload",
                "enabled": True,
            },
        ],
        "broker_public_key": public,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    }
    identity_path = Path(directory) / "caller-registry.json"
    identity_path.write_bytes(canonical(identity))
    pinned = PinnedCallerRegistry(
        identity_path,
        hashlib.sha256(identity_path.read_bytes()).hexdigest(),
        expected_environment="local_oidc",
    )
    joiner = ServiceEvidenceJoiner(service, Path(directory) / "service.sqlite3")
    broker = ServiceCallerBroker(pinned, joiner, Path(directory) / "caller.sqlite3", broker_key)
    return keys, registry, identity_key, broker


def token_for(request, key, **changes):
    now = int(datetime.now(UTC).timestamp())
    claims = {
        "iss": ISSUER,
        "aud": "local-systemd-broker",
        "sub": "fixture-person",
        "iat": now,
        "exp": now + 60,
        "auth_time": now,
        "nonce": request.authentication_nonce,
    }
    claims.update(changes)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "fixture-rsa-1"})


def run(directory):
    require(os.name == "posix" and os.geteuid() == 0, "systemd_controls_root_required")
    require(Path("/proc/1/comm").read_text().strip() == "systemd", "real_systemd_required")
    directory = Path(directory)
    unit = "secops-caller-v69-" + uuid.uuid4().hex + ".service"
    keys, registry, identity_key, broker = setup_broker(directory, unit)
    argv = ["/usr/bin/python3", "-u", "-c", FIXTURE]
    target = UnitTarget(
        "local-lab",
        "shared-lab",
        unit,
        executable_hash(Path(argv[0])),
        hashlib.sha256(b"".join(v.encode() + b"\0" for v in argv)).hexdigest(),
    )
    launcher = SystemdUnitLauncher(
        [target], keys["runtime"], source_id="local-proc", key_id="proc-1"
    )
    unit_file = Path("/run/systemd/system") / unit
    report = {
        "schema": "extra-systemd-caller-controls-1",
        "completed": False,
        "scope": "real WSL system manager and local signed OIDC fixture; functional controls only",
        "paid_api_calls": 0,
        "aws_calls": 0,
        "goal_qualified": False,
        "real_human_login_tested": False,
        "local_oidc_fixture": True,
        "cases": [],
    }

    def check(name, condition):
        require(condition, "systemd_caller_control_" + name)
        report["cases"].append({"name": name, "passed": True})

    def issue():
        return broker.issue(
            tenant_id=target.tenant_id,
            server_id=target.server_id,
            unit=unit,
            executable_sha256=target.executable_sha256,
            command_sha256=target.command_sha256,
        )

    def authorize(request):
        return PolicyObservation(
            decision="allow",
            policy_sha256=registry.policy_sha256,
            policy_version=1,
            executable_sha256=request.executable_sha256,
            command_sha256=request.command_sha256,
        ), datetime.now(UTC)

    def permission(event, observation, observed):
        return sign_policy(
            event,
            observation,
            keys["authorization"],
            observed_at=observed,
            issued_at=datetime.now(UTC),
        )

    def dispatch(request, token, **changes):
        callbacks = {
            "authorize": authorize,
            "launch": launcher.launch,
            "collect": launcher.collect,
            "policy_proof": permission,
        }
        callbacks.update(changes)
        return broker.dispatch(request.request_id, token, **callbacks)

    def rejects(request, token, **changes):
        try:
            dispatch(request, token, **changes)
        except (ValueError, jwt.PyJWTError):
            return True
        return False

    created = False
    try:
        with unit_file.open("x", encoding="utf8") as stream:
            created = True
            stream.write(
                "[Unit]\nDescription=Owned local SecOps caller control\n[Service]\n"
                "Type=exec\nUser=nobody\nNoNewPrivileges=yes\nPrivateNetwork=yes\n"
                "ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n"
                "MemoryMax=64M\nTasksMax=8\nRuntimeMaxSec=90\nRestart=no\n"
                "StandardOutput=journal\nStandardError=journal\n"
                'ExecStart=/usr/bin/python3 -u -c "' + FIXTURE + '"\n'
            )
        subprocess.run(
            ["/usr/bin/systemctl", "daemon-reload"], check=True, env=READ_ENV, timeout=10
        )
        for name, claims in [
            ("unknown_person_rejected", {"sub": "not-in-directory"}),
            ("workload_not_inferred_as_person", {"sub": "fixture-machine"}),
            ("wrong_audience_rejected", {"aud": "another-client"}),
            ("wrong_request_nonce_rejected", {"nonce": "0" * 64}),
            ("expired_authentication_rejected", {"exp": 1}),
        ]:
            request = issue()
            check(name, rejects(request, token_for(request, identity_key, **claims)))
        check(
            "invalid_identity_did_not_start_unit", launcher.state(unit)["ActiveState"] == "inactive"
        )
        request = issue()

        def deny(r):
            policy, observed = authorize(r)
            return policy.model_copy(update={"decision": "deny"}), observed

        check(
            "authenticated_person_still_needs_authorization",
            rejects(request, token_for(request, identity_key), authorize=deny),
        )
        check(
            "denied_request_did_not_start_unit", launcher.state(unit)["ActiveState"] == "inactive"
        )
        request = issue()
        token = token_for(request, identity_key)
        receipt, event, proofs = dispatch(request, token)
        check(
            "person_request_bound_to_real_systemd_invocation",
            receipt.event_sha256 == event.sha256
            and receipt.environment == "local_oidc"
            and event.mode == "systemd"
            and event.collection_basis == "manager_snapshot",
        )
        broker.key.public_key().verify(
            base64.urlsafe_b64decode(receipt.signature + "=="), receipt_bytes(receipt)
        )
        check("signed_caller_receipt_verified", True)
        check(
            "consumer_rechecks_current_identity_and_event",
            verify_receipt(receipt, broker.registry, request, event) == receipt,
        )
        check("one_request_cannot_start_twice", rejects(request, token))
        other = issue()
        check(
            "another_request_cannot_claim_running_unit",
            rejects(other, token_for(other, identity_key)),
        )
        # Read the actual journal separately from the manager snapshot. The
        # service prints one fixed harmless line; no caller argv/token is logged.
        journal, _ = collect_latest_systemd(
            unit,
            keys["runtime"],
            tenant_id="local-lab",
            server_id="shared-lab",
            source_id="local-proc",
            key_id="proc-1",
        )
        check(
            "trusted_journal_matches_live_invocation",
            journal.invocation_id == event.invocation_id
            and journal.process_id == event.process_id
            and journal.collection_basis == "native_journal",
        )
        previous = OperationDecision(0.1, 0.1, False, False, "baseline")
        check(
            "valid_normal_identity_does_not_add_alarm",
            VerifiedServiceRisk(broker.joiner).decide(previous, event=event, proofs=proofs)
            is previous,
        )
        (directory / "caller-receipt.json").write_bytes(canonical(receipt.model_dump(mode="json")))
        report.update(
            completed=True,
            real_systemd_integration_tested=True,
            systemd_version=subprocess.check_output(
                ["/usr/bin/systemctl", "--version"], env=READ_ENV, text=True
            ).splitlines()[0],
            normal_controls=1,
            normal_added_alerts=0,
            identity_does_not_grant_permissions=True,
            tokens_persisted=False,
            private_keys_persisted=False,
            plaintext_arguments_persisted=False,
            runtime_effective_uid=proofs[0].observation.effective_uid,
            runtime_login_uid_present=proofs[0].observation.login_uid is not None,
            caller_derived_from_uid=False,
            mfa_or_device_health_inferred=False,
        )
    finally:
        # Only this UUID-named test unit and file are ever stopped/removed.
        if created:
            subprocess.run(
                ["/usr/bin/systemctl", "stop", "--", unit],
                env=READ_ENV,
                capture_output=True,
                timeout=10,
                check=False,
            )
            unit_file.unlink()
            subprocess.run(
                ["/usr/bin/systemctl", "daemon-reload"], env=READ_ENV, check=True, timeout=10
            )
        report["owned_unit_file_removed"] = not unit_file.exists()
        report["owned_unit_stopped"] = launcher.state(unit)["ActiveState"] == "inactive"
        (directory / "run.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.directory)
    print(
        json.dumps(
            {
                "completed": result["completed"],
                "cases": len(result["cases"]),
                "normal_added_alerts": result["normal_added_alerts"],
            }
        )
    )


if __name__ == "__main__":
    main()
