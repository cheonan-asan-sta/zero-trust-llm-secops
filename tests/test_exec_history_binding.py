"""Adversarial contract controls; actual kernel/systemd is a separate native run."""

import os
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.security import Principal, Role
from app.zero_trust_models import SessionRevocationRequest
from scripts.f1_lab.exec_history import collect_owned_exec, validate_target
from scripts.f1_lab.shared_execution_collector import runtime_proof
from scripts.f1_lab.shared_execution_evidence import ProcessObservation, ServiceEvent
from scripts.run_exec_history_controls import setup_app
from scripts.run_systemd_caller_controls import token_for


def fixture(tmp_path):
    lab = setup_app(tmp_path / "control", "fixture.service")
    launches = []

    def collect(request):
        event = ServiceEvent(
            tenant_id=request.tenant_id,
            server_id=request.server_id,
            unit=request.unit,
            boot_id="1" * 32,
            invocation_id="2" * 32,
            process_id=42,
            observed_at=datetime.now(UTC),
            mode="systemd",
            collection_basis="ptrace_exec",
            event_id=request.authentication_nonce,
            raw_sha256="d" * 64,
        )
        process = ProcessObservation(
            pid=42,
            start_ticks=1,
            parent_pid=1,
            real_uid=65534,
            effective_uid=65534,
            login_uid=None,
            audit_session_id=None,
            executable_sha256=request.executable_sha256,
            command_sha256=request.command_sha256,
            argument_count=1,
            parent_ref_sha256=None,
        )
        return event, runtime_proof(
            event, process, lab.keys["runtime"], source_id="local-proc", key_id="proc-1"
        )

    launcher = SimpleNamespace(launch=lambda r: launches.append(r.request_id), collect=collect)
    return lab, launcher, launches


def test_identity_app_grant_request_and_execution_history_bind(tmp_path):
    lab, launcher, launches = fixture(tmp_path)
    request, access = lab.new_request(), lab.new_access()
    receipt, event, proofs = lab.gate(request, access).dispatch(launcher, lab.permission)
    assert launches == [request.request_id] and event.collection_basis == "ptrace_exec"
    assert receipt.request_sha256 == request.authentication_nonce and len(proofs) == 2
    with lab.operations._transaction() as (_, entries, _):
        records = [e for e in entries if e["kind"] == "access" and e["allowed"]]
    assert len(records) == 1 and records[0]["execution_request_sha256"] == receipt.request_sha256
    assert access.grant_token not in str(entries) and "eyJ" not in str(entries)
    assert not lab.operations.access(access, lab.principal).allowed


@pytest.mark.parametrize(
    "change",
    [
        "viewer",
        "different_person",
        "different_tenant",
        "untrusted_auth",
        "wrong_resource",
        "wrong_action",
        "wrong_grant",
        "revoked",
        "already_consumed",
        "source_revoked",
        "policy_changed",
        "different_request",
        "identity_workload",
        "identity_wrong_nonce",
    ],
)
def test_invalid_context_never_launches(tmp_path, change):
    lab, launcher, launches = fixture(tmp_path)
    request, access = lab.new_request(), lab.new_access()
    actor = lab.principal
    token = None
    if change == "viewer":
        actor = Principal(actor.subject, actor.tenant_id, frozenset({Role.VIEWER}), "api_key")
    if change == "different_person":
        actor = Principal("someone-else", actor.tenant_id, actor.roles, "api_key")
    if change == "different_tenant":
        actor = Principal(actor.subject, "other", actor.roles, "api_key")
    if change == "untrusted_auth":
        actor = Principal(actor.subject, actor.tenant_id, actor.roles, "unverified")
    if change == "wrong_resource":
        access = access.model_copy(update={"resource_id": "zt-demo-vault"})
    if change == "wrong_action":
        access = type(access).model_validate({**access.model_dump(), "action": "DOWNLOAD"})
    if change == "wrong_grant":
        access = access.model_copy(update={"grant_token": "x" * 64})
    if change == "revoked":
        lab.operations.revoke(
            access.session_id,
            SessionRevocationRequest(expected_version=1, note="local denial control"),
            lab.principal,
        )
    if change == "already_consumed":
        assert lab.operations.access(access, lab.principal).allowed
    if change == "source_revoked":
        lab.sources["sources"][0]["enabled"] = False
        lab.save_sources()
    if change == "policy_changed":
        lab.operations.policy_digest = "c" * 64
    if change == "identity_workload":
        token = token_for(request, lab.identity, sub="fixture-machine")
    if change == "identity_wrong_nonce":
        token = token_for(request, lab.identity, nonce="bad")
    gate = lab.gate(request, access, actor=actor, token=token)
    if change == "different_request":
        gate.request = lab.new_request()
    with pytest.raises(ValueError):
        gate.dispatch(launcher, lab.permission)
    assert not launches


@pytest.mark.parametrize("change", ["revoke", "source_revoke", "policy_change", "not_authorized"])
def test_recheck_after_consumption_before_launch(tmp_path, change):
    lab, launcher, launches = fixture(tmp_path)
    request, access = lab.new_request(), lab.new_access()
    gate = lab.gate(request, access)
    if change != "not_authorized":
        gate.authorize(request)
    if change == "revoke":
        lab.operations.revoke(
            access.session_id,
            SessionRevocationRequest(expected_version=1, note="race control"),
            lab.principal,
        )
    if change == "source_revoke":
        lab.sources["sources"][0]["enabled"] = False
        lab.save_sources()
    if change == "policy_change":
        lab.operations.policy_digest = "c" * 64
    with pytest.raises(ValueError):
        gate.launch(request, launcher)
    assert not launches


def test_uncertain_launch_does_not_refund_the_app_grant(tmp_path):
    lab, launcher, _ = fixture(tmp_path)
    request, access = lab.new_request(), lab.new_access()

    def fail(_):
        raise RuntimeError("controlled startup failure")

    launcher.launch = fail
    with pytest.raises(RuntimeError):
        lab.gate(request, access).dispatch(launcher, lab.permission)
    assert not lab.operations.access(access, lab.principal).allowed
    with lab.broker.connect() as con:
        assert (
            con.execute("SELECT state FROM requests WHERE id=?", (request.request_id,)).fetchone()[
                0
            ]
            == "uncertain"
        )


@pytest.mark.parametrize("value", [True, 1, "a" * 63, "g" * 64, "A" * 64, {}, "a" * 65])
def test_app_history_binding_rejects_invalid_digest_before_consumption(tmp_path, value):
    lab, _, _ = fixture(tmp_path)
    access = lab.new_access()
    with pytest.raises(ValueError):
        lab.operations.access(access, lab.principal, execution_request_sha256=value)
    assert lab.operations.access(access, lab.principal).allowed


def test_legacy_access_has_no_new_field(tmp_path):
    lab, _, _ = fixture(tmp_path)
    assert lab.operations.access(lab.new_access(), lab.principal).allowed
    with lab.operations._transaction() as (_, entries, _):
        assert all("execution_request_sha256" not in e for e in entries if e["kind"] == "access")


def test_high_risk_target_cannot_use_internal_read_adapter(tmp_path):
    from dataclasses import replace

    lab, launcher, launches = fixture(tmp_path)
    gate = lab.gate(lab.new_request(), lab.new_access())
    gate.target = replace(gate.target, resource_id="zt-demo-vault")
    with pytest.raises(ValueError, match="low_impact_target"):
        gate.dispatch(launcher, lab.permission)
    assert not launches


def test_unsigned_demo_session_is_not_enough_for_default_gate(tmp_path):
    from app.models import SecurityEvent
    from app.scenarios import synthetic_events
    from app.zero_trust_models import SessionEvaluationRequest

    lab, launcher, launches = fixture(tmp_path)
    data = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
    data.update(event_id="unsigned-demo", timestamp=datetime.now(UTC), action="READ")
    data["user"].update(user_id="user-a", role="employee", active=True)
    data["device"].update(device_id="device-a", managed=True, security_posture="healthy")
    data["resource"].update(resource_id="zt-demo-documents", required_role=None)
    data["auth_context"].update(authentication_result="success", mfa="success")
    result = lab.operations.evaluate(
        SessionEvaluationRequest(
            session_id="demo-session", expected_version=0, event=SecurityEvent.model_validate(data)
        ),
        lab.principal,
    )
    access = lab.new_access().model_copy(
        update={"session_id": "demo-session", "grant_token": result.grant_token}
    )
    with pytest.raises(ValueError, match="verified_session_required"):
        lab.gate(lab.new_request(), access).dispatch(launcher, lab.permission)
    assert not launches


@pytest.mark.parametrize(
    "mode,basis",
    [
        ("systemd", "ptrace_exec_lab"),
        ("local_process_lab", "ptrace_exec"),
    ],
)
def test_lab_capture_cannot_claim_systemd_mode(mode, basis):
    with pytest.raises(ValueError):
        ServiceEvent(
            tenant_id="t",
            server_id="s",
            unit="fixture.service",
            boot_id="1" * 32,
            invocation_id="2" * 32,
            process_id=1,
            observed_at=datetime.now(UTC),
            mode=mode,
            collection_basis=basis,
            event_id="a" * 64,
            raw_sha256="b" * 64,
        )


@pytest.mark.parametrize(
    "argv",
    [[], ["relative"], ["/bin/true", "bad\0arg"], ["/bin/true", 1], ["/bin/true"] * 257, None],
)
def test_unsafe_argv_is_rejected(argv):
    with pytest.raises(ValueError):
        validate_target(SimpleNamespace(), argv)


@pytest.mark.parametrize("timeout", [0, -1, 31, True, float("nan"), float("inf"), "10"])
def test_trace_limits_fail_before_fork(monkeypatch, timeout):
    monkeypatch.setattr("scripts.f1_lab.exec_history.sys.platform", "linux")
    with pytest.raises(ValueError):
        collect_owned_exec(None, [], None, source_id="s", key_id="k", timeout=timeout)


@pytest.mark.parametrize("stage", ["initial_exit", "exec_failure", "ownership_lost", "timeout"])
@pytest.mark.skipif(os.name != "posix", reason="POSIX wait-status and fork cleanup contract")
def test_failed_trace_never_kills_reaped_or_unowned_pid(monkeypatch, stage):
    import signal
    from datetime import timedelta

    import scripts.f1_lab.exec_history as module

    now = datetime.now(UTC)
    request = SimpleNamespace(
        issued_at=now, expires_at=now + timedelta(seconds=60), request_id="1" * 32
    )
    monkeypatch.setattr(module.sys, "platform", "linux")
    monkeypatch.setattr(module, "validate_target", lambda *a: None)
    monkeypatch.setattr(module, "boot_id", lambda: "1" * 32)
    monkeypatch.setattr(module.os, "fork", lambda: 42)
    monkeypatch.setattr(module, "ptrace", lambda *a: None)
    statuses = iter(
        [127 << 8] if stage == "initial_exit" else [(signal.SIGSTOP << 8) | 0x7F, 127 << 8]
    )

    def wait(*_):
        if stage == "ownership_lost":
            raise ChildProcessError()
        if stage == "timeout":
            raise TimeoutError()
        return next(statuses)

    monkeypatch.setattr(module, "wait_owned", wait)
    killed = []
    monkeypatch.setattr(module.os, "kill", lambda *a: killed.append(a))
    monkeypatch.setattr(module.os, "waitpid", lambda *a: (42, signal.SIGKILL))
    with pytest.raises((ValueError, TimeoutError)):
        collect_owned_exec(request, [], None, source_id="s", key_id="k", mode="local_process_lab")
    assert killed == ([(42, signal.SIGKILL)] if stage == "timeout" else [])
