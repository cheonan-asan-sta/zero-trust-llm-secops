"""Local signed identity/app fixtures and real systemd/ptrace acceptance.

Creates only UUID-owned transient unit files. No paid APIs or host audit rules.
Local OIDC and device signals are fixtures, not organization SSO/EDR evidence.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from app.models import SecurityEvent
from app.scenarios import synthetic_events
from app.security import Principal, Role
from app.services.trusted_signals import SignalVerifier, canonical_signal
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_models import (
    ProtectedAccessRequest,
    SessionRevocationRequest,
    SignedSessionSignal,
)
from scripts.f1_lab.app_execution_gate import AppExecutionGate, AppExecutionTarget
from scripts.f1_lab.exec_history_launcher import HistoryUnitLauncher
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.shared_execution_collector import READ_ENV, executable_hash
from scripts.f1_lab.shared_execution_evidence import PinnedServiceRegistry, VerifiedServiceRisk
from scripts.f1_lab.systemd_request_launcher import UnitTarget
from scripts.run_shared_execution_controls import sign_policy
from scripts.run_systemd_caller_controls import setup_broker, token_for


def setup_app(directory, unit, *, executable_sha256="a" * 64, command_sha256="b" * 64):
    directory = Path(directory)
    keys, registry, identity, broker = setup_broker(directory / "trust", unit)
    principal = Principal("fixture-person", "local-lab", frozenset({Role.RESPONDER}), "api_key")
    signal_key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    sources = {
        "sources": [
            {
                "source_id": "app-fixture",
                "tenant_id": "local-lab",
                "enabled": True,
                "user_ids": ["user-a"],
                "device_ids": ["device-a"],
                "roles": ["employee"],
                "keys": [
                    {
                        "key_id": "app-key",
                        "public_key_pem": signal_key.public_key()
                        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                        .decode(),
                        "enabled": True,
                        "not_before": (now - timedelta(minutes=1)).isoformat(),
                        "not_after": (now + timedelta(hours=1)).isoformat(),
                    }
                ],
            }
        ]
    }
    source_path = directory / "app-sources.json"

    def save_sources():
        source_path.write_bytes(canonical(sources))

    save_sources()
    operations = ZeroTrustOperations(
        directory / "app.sqlite3", signal_verifier=SignalVerifier(source_path)
    )
    registry = registry.model_copy(update={"policy_sha256": operations.policy_digest})
    service_path = directory / "trust/registry.json"
    service_path.write_bytes(canonical(registry.model_dump(mode="json")))
    broker.joiner.registry = PinnedServiceRegistry(
        service_path, hashlib.sha256(service_path.read_bytes()).hexdigest()
    )
    target = UnitTarget("local-lab", "shared-lab", unit, executable_sha256, command_sha256)

    def new_request():
        return broker.issue(
            tenant_id=target.tenant_id,
            server_id=target.server_id,
            unit=unit,
            executable_sha256=executable_sha256,
            command_sha256=command_sha256,
        )

    signals = {}

    def new_access():
        when = datetime.now(UTC)
        data = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
        data.update(event_id="exec-" + uuid.uuid4().hex, timestamp=when, action="READ")
        data["user"].update(user_id="user-a", role="employee", active=True)
        data["device"].update(device_id="device-a", managed=True, security_posture="healthy")
        data["resource"].update(resource_id="zt-demo-documents", required_role=None)
        data["auth_context"].update(authentication_result="success", mfa="success")
        event = SecurityEvent.model_validate(data)
        signal = SignedSessionSignal(
            session_id="exec-" + uuid.uuid4().hex,
            expected_version=0,
            event=event,
            tenant_id="local-lab",
            source_id="app-fixture",
            key_id="app-key",
            issued_at=when,
            expires_at=when + timedelta(seconds=90),
            signature="A" * 86,
        )
        signal = signal.model_copy(
            update={
                "signature": base64.urlsafe_b64encode(signal_key.sign(canonical_signal(signal)))
                .decode()
                .rstrip("=")
            }
        )
        result = operations.evaluate_signed(signal, principal)
        signals[signal.session_id] = signal
        require(result.grant_token is not None, "exec_history_fixture_grant")
        return ProtectedAccessRequest(
            session_id=signal.session_id,
            resource_id="zt-demo-documents",
            action="READ",
            grant_token=result.grant_token,
        )

    def gate(request, access, *, actor=principal, token=None):
        return AppExecutionGate(
            broker,
            operations,
            AppExecutionTarget(target, "zt-demo-documents", "READ"),
            request,
            actor,
            access,
            token_for(request, identity) if token is None else token,
        )

    def permission(event, observation, observed):
        return sign_policy(
            event,
            observation,
            keys["authorization"],
            observed_at=observed,
            issued_at=datetime.now(UTC),
        )

    return SimpleNamespace(
        keys=keys,
        registry=registry,
        identity=identity,
        broker=broker,
        operations=operations,
        principal=principal,
        target=target,
        new_request=new_request,
        new_access=new_access,
        signals=signals,
        gate=gate,
        permission=permission,
        sources=sources,
        save_sources=save_sources,
    )


def run(directory, *, retention=False, outbox_recovery=False, intent_recovery=False,
        recovery_observability=False, coherent_backup=False, bundle_observability=False,
        llm_evidence=False, http_analysis=False, shared_analysis=False, audit_recovery=False,
        worker_restart=False, worker_paging=False):
    worker_restart = worker_restart or worker_paging
    audit_recovery = audit_recovery or worker_restart
    shared_analysis = shared_analysis or audit_recovery
    http_analysis = http_analysis or shared_analysis
    llm_evidence = llm_evidence or http_analysis
    coherent_backup = coherent_backup or bundle_observability
    recovery_observability = recovery_observability or coherent_backup
    intent_recovery = intent_recovery or recovery_observability
    outbox_recovery = outbox_recovery or intent_recovery
    retention = retention or outbox_recovery
    require(
        sys.platform == "linux"
        and os.geteuid() == 0
        and Path("/proc/1/comm").read_text().strip() == "systemd",
        "exec_history_controls_systemd",
    )
    output = Path(directory)
    output.mkdir(parents=True, exist_ok=False)
    private = Path("/run") / ("zt-exec-history-" + uuid.uuid4().hex)
    private.mkdir(mode=0o700)
    unit = "secops-exec-history-" + uuid.uuid4().hex + ".service"
    unit_file = Path("/run/systemd/system") / unit
    argv = ["/usr/bin/true"]
    report = {
        "schema": "extra-exec-history-app-controls-1",
        "completed": False,
        "real_systemd": True,
        "real_ptrace_exec_stop": False,
        "local_oidc_fixture": True,
        "app_device_signal_fixture": True,
        "real_human_login_tested": False,
        "host_wide_audit_collected": False,
        "paid_api_calls": 0,
        "aws_calls": 0,
        "goal_qualified": False,
        "managed_exec_retention_tested": retention,
        "exec_outbox_recovery_tested": outbox_recovery,
        "exec_intent_recovery_tested": intent_recovery,
        "exec_recovery_observability_tested": recovery_observability,
        "exec_coherent_backup_tested": coherent_backup,
        "exec_bundle_observability_tested": bundle_observability,
        "native_llm_context_tested": llm_evidence,
        "llm_provider_stubbed": llm_evidence,
        "model_quality_measured": False,
        "native_http_analysis_tested": http_analysis,
        "shared_native_analysis_tested": shared_analysis,
        "native_transactional_audit_recovery_tested": audit_recovery,
        "http_worker_process_restart_tested": worker_restart,
        "http_cursor_worker_restart_tested": worker_paging,
        "cases": [],
    }

    def command(*args):
        return subprocess.run(
            ["/usr/bin/systemctl", *args],
            env=READ_ENV,
            capture_output=True,
            timeout=25,
            check=False,
        )

    def passed(name):
        report["cases"].append(name)

    try:
        if http_analysis:
            from scripts.f1_lab.service_http_controls import preload

            preload(private)
        lab = setup_app(
            private / "control",
            unit,
            executable_sha256=executable_hash(Path(argv[0])),
            command_sha256=hashlib.sha256(b"/usr/bin/true\0").hexdigest(),
        )
        work = private / "worker"
        work.mkdir(mode=0o700)
        key = private / "runtime-key"
        key.write_bytes(
            lab.keys["runtime"].private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        key.chmod(0o600)
        python_path = os.environ["PYTHONPATH"]
        require('"' not in python_path and "\n" not in python_path, "exec_history_python_path")
        unit_file.write_text(
            f"""[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -m scripts.collect_exec_history --directory {work}
Environment="PYTHONPATH={python_path}" PYTHONDONTWRITEBYTECODE=1 AWS_EC2_METADATA_DISABLED=true
LoadCredential=runtime-key:{key}
NoNewPrivileges=yes
PrivateNetwork=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths={work}
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_KILL
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryMax=192M
TasksMax=16
TimeoutStartSec=15
StandardOutput=null
StandardError=journal
""",
            encoding="utf8",
        )
        require(command("daemon-reload").returncode == 0, "exec_history_unit_reload")
        launcher = HistoryUnitLauncher(
            lab.target, argv, work, source_id="local-proc", key_id="proc-1"
        )
        access, request = lab.new_access(), lab.new_request()
        gate = lab.gate(request, access)
        receipt, event, proofs = gate.dispatch(launcher, lab.permission)
        from scripts.f1_lab.service_caller_identity import verify_receipt

        require(
            verify_receipt(receipt, lab.broker.registry, request, event) == receipt,
            "exec_history_receipt",
        )
        passed("local_oidc_person_and_signed_broker_receipt")
        require(
            event.collection_basis == "ptrace_exec" and proofs[0].observation.real_uid == 65534,
            "exec_history_native_origin",
        )
        report["real_ptrace_exec_stop"] = True
        passed("actual_kernel_exec_stop_and_unprivileged_child")
        require(not Path("/proc", str(event.process_id)).exists(), "exec_history_short_lived_exit")
        passed("short_lived_process_evidence_survives_exit")
        require(
            lab.broker.joiner.check(event, proofs).state == "consistent",
            "exec_history_valid_evidence",
        )
        passed("runtime_command_policy_and_systemd_invocation_bound")
        with lab.operations._transaction() as (_, entries, _):
            linked = [
                e
                for e in entries
                if e["kind"] == "access"
                and e.get("execution_request_sha256") == request.authentication_nonce
            ]
        require(len(linked) == 1 and linked[0]["allowed"], "exec_history_app_history_link")
        passed("app_grant_consumption_history_links_signed_request")
        if llm_evidence:
            from scripts.f1_lab.service_analysis_controls import run as run_analysis

            run_analysis(lab, request, access, receipt, event, proofs, passed)
        if http_analysis:
            from scripts.f1_lab.service_http_controls import run as run_http

            shared_config = None
            if shared_analysis:
                from scripts.f1_lab.shared_native_controls import run as run_shared

                shared_config = run_shared(
                    lab, request, access, receipt, event, proofs, private, passed,
                )
            if worker_restart:
                from scripts.f1_lab.http_worker_controls import run as run_workers

                report["worker_restart"] = run_workers(
                    lab, request, access, receipt, event, proofs, shared_config, private, passed,
                    paging=worker_paging,
                )
            report["http_analysis"] = run_http(
                lab, request, access, receipt, event, proofs, private, passed,
                shared_config=shared_config,
                audit_recovery=audit_recovery,
            )
        normal = OperationDecision(0.1, 0.1, False, False, "prior-normal")
        old_alert = OperationDecision(0.9, 0.9, True, True, "prior-alert")
        risk = VerifiedServiceRisk(lab.broker.joiner)
        require(
            risk.decide(normal, event=event, proofs=proofs) is normal
            and risk.decide(old_alert, event=event, proofs=proofs) is old_alert,
            "exec_history_previous_decisions",
        )
        passed("normal_no_added_alert_and_existing_alert_preserved")
        captured = (work / "capture.json").read_bytes()

        def rejected(name, callback):
            try:
                callback()
            except (ValueError, PermissionError):
                require(
                    (work / "capture.json").read_bytes() == captured,
                    "exec_history_unexpected_execution",
                )
                passed(name)
            else:
                raise AssertionError(name)

        rejected("broker_request_replay_denied", lambda: gate.dispatch(launcher, lab.permission))
        replay = lab.new_request()
        rejected(
            "consumed_app_grant_denied_before_launch",
            lambda: lab.gate(replay, access).dispatch(launcher, lab.permission),
        )
        revoked = lab.new_access()
        lab.operations.revoke(
            revoked.session_id,
            SessionRevocationRequest(expected_version=1, note="local revocation control"),
            lab.principal,
        )
        rejected(
            "revoked_app_session_denied_before_launch",
            lambda: lab.gate(lab.new_request(), revoked).dispatch(launcher, lab.permission),
        )
        fresh = lab.new_access()
        other = Principal("other-person", "local-lab", frozenset({Role.RESPONDER}), "api_key")
        rejected(
            "authenticated_person_cannot_be_replaced_by_app_subject",
            lambda: lab.gate(lab.new_request(), fresh, actor=other).dispatch(
                launcher, lab.permission
            ),
        )
        raw = b"\n".join((work / "capture.json").read_bytes().splitlines())
        require(
            b"eyJ" not in raw and key.read_bytes() not in raw and b"fixture-person" not in raw,
            "exec_history_private_values",
        )
        passed("capture_excludes_identity_token_key_and_raw_subject")
        if retention:
            from scripts.f1_lab.managed_exec_retention_controls import run as run_retention

            run_retention(
                lab,
                gate,
                (receipt, event, proofs),
                launcher,
                private,
                output,
                passed,
                outbox_recovery=outbox_recovery,
                intent_recovery=intent_recovery,
                recovery_observability=recovery_observability,
                coherent_backup=coherent_backup,
                bundle_observability=bundle_observability,
            )
        report["completed"] = True
    except Exception:
        diagnostic = subprocess.run(
            ["/usr/bin/journalctl", "--no-pager", "-u", unit, "-n", "70", "-o", "cat"],
            env=READ_ENV,
            capture_output=True,
            timeout=10,
            check=False,
        )
        (output / "private-unit-failure.log").write_bytes(diagnostic.stdout[:32768])
        raise
    finally:
        for action in [("stop", unit), ("reset-failed", unit)]:
            command(*action)
        if unit_file.exists():
            unit_file.unlink()
        command("daemon-reload")
        require(
            private.parent == Path("/run") and private.name.startswith("zt-exec-history-"),
            "exec_history_cleanup_scope",
        )
        shutil.rmtree(private)
        report["owned_unit_removed"] = not unit_file.exists()
        report["owned_private_state_removed"] = not private.exists()
        (output / "run.json").write_bytes(canonical(report) + b"\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--retention", action="store_true")
    parser.add_argument("--outbox-recovery", action="store_true")
    parser.add_argument("--recovery-observability", action="store_true")
    parser.add_argument("--coherent-backup", action="store_true")
    parser.add_argument("--bundle-observability", action="store_true")
    parser.add_argument("--intent-recovery", action="store_true")
    parser.add_argument("--llm-evidence", action="store_true")
    parser.add_argument("--http-analysis", action="store_true")
    parser.add_argument("--shared-analysis", action="store_true")
    parser.add_argument("--audit-recovery", action="store_true")
    parser.add_argument("--worker-restart", action="store_true")
    parser.add_argument("--worker-paging", action="store_true")
    args = parser.parse_args()
    result = run(args.directory, retention=args.retention, outbox_recovery=args.outbox_recovery,
                 intent_recovery=args.intent_recovery,recovery_observability=args.recovery_observability,
                 coherent_backup=args.coherent_backup,bundle_observability=args.bundle_observability,
                 llm_evidence=args.llm_evidence,http_analysis=args.http_analysis,
                 shared_analysis=args.shared_analysis,audit_recovery=args.audit_recovery,
                 worker_restart=args.worker_restart,worker_paging=args.worker_paging)
    print(json.dumps({"completed": result["completed"], "cases": len(result["cases"])}))


if __name__ == "__main__":
    main()
