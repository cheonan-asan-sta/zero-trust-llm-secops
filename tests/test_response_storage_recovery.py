import asyncio
import json
import os
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

from app.models import AnalysisResult, PolicyDecision, SecurityAssessment
from app.response_workflow import PlanRequest, ResponseWorkflow, TransitionRequest, WorkflowConflict
from app.security import Principal, Role
from app.services.audit import AuditStore
from scripts import app_state_recovery as recovery
from scripts import response_storage_contract as response
from scripts import serve_recovered_app as gate
from scripts.app_recovery_fixture import prepare, verify
from scripts.app_storage_fixture import seed_logs


def person(subject="requester", role=Role.ADMIN, tenant="a"):
    return Principal(subject, tenant, frozenset({role}), "test")


def seed(directory):
    service = ResponseWorkflow(directory / response.FILE)
    plans = {}
    for tenant in ("a", "b"):
        for state in ("PENDING", "APPROVED", "REJECTED", "SIMULATED"):
            record = AnalysisResult(event_id=f"event-{state}", analysis_id=f"analysis-{state}",
                tenant_id=tenant, analyzer="rule", latency_ms=1,
                assessment=SecurityAssessment(risk_score=90, risk_level="HIGH",
                    violation_type="PRIVILEGE_ESCALATION", rationale="권한 불일치가 확인되었습니다.",
                    recommended_action="REDUCE_PRIVILEGE", confidence=.9, requires_human_review=True),
                policy_decision=PolicyDecision(action="REDUCE_PRIVILEGE", allowed=True,
                    requires_human_review=True, reason="simulation"))
            asyncio.run(AuditStore(directory / "audit.jsonl").save(record))
            plan = service.create(record, PlanRequest(event_id=record.event_id,
                analysis_id=record.analysis_id, request_key=state), person(tenant=tenant))
            reviewer = person("reviewer", tenant=tenant)
            if state != "PENDING":
                plan = service.transition(plan["id"], "reject" if state == "REJECTED" else "approve",
                    TransitionRequest(expected_version=1, note="Review scope"), reviewer)
            if state == "SIMULATED":
                plan = service.transition(plan["id"], "execute",
                    TransitionRequest(expected_version=2, note="Execute simulation"), reviewer)
            plans[tenant, state] = plan
    return plans


@pytest.fixture
def lab(tmp_path, recovery_clock):
    data = tmp_path / "data"
    prepare(data)
    seed_logs(data)
    plans = seed(data)
    store = recovery.Store(tmp_path)
    store.initialize(full_state=True, response_state=True)
    store.checkpoint()
    backup = store.backup()
    return SimpleNamespace(root=tmp_path, data=data, plans=plans, store=store, backup=backup)


def restore(lab):
    result = lab.store.restore(lab.backup["backup_id"])
    return lab.root / "restores" / result["restore_id"], result


def test_full_restore_fences_all_unfinished_plans_keeps_history_and_receipts(lab):
    stage, result = restore(lab)
    assert result["response_plans_fenced"] == 4
    assert verify(stage, lab.data)["old_grants_denied"] == 3
    service = ResponseWorkflow(stage / response.FILE)
    assert response.inspect(stage)["count"] == 8
    for (tenant, state), old in lab.plans.items():
        plan = service.get(old["id"], person(tenant=tenant))
        if state in {"PENDING", "APPROVED"}:
            assert plan["state"] == "REJECTED"
            assert plan["version"] == old["version"] + 1
            assert plan["history"][:-1] == old["history"]
            for op in ("approve", "execute"):
                with pytest.raises(WorkflowConflict):
                    service.transition(plan["id"], op, TransitionRequest(
                        expected_version=plan["version"], note="Try old plan"), person("reviewer", tenant=tenant))
        else:
            assert plan == old
    assert recovery.verify_admission(stage, lab.root / "public")["admission_verified"]
    # Repeated restore fences the original pending entries again, never publishes a runnable approval.
    second, _ = restore(lab)
    assert recovery.verify_admission(second, lab.root / "public")["admission_verified"]
    with pytest.raises(recovery.RecoveryError, match="admission_pin"):
        recovery.verify_admission(stage, lab.root / "public")


def test_old_simulated_exact_retry_is_only_original_zero_effect_receipt(lab):
    stage, _ = restore(lab)
    old = lab.plans["a", "SIMULATED"]
    result = ResponseWorkflow(stage / response.FILE).transition(old["id"], "execute",
        TransitionRequest(expected_version=2, note="Execute simulation"), person("reviewer"),
        now=old["expires_at"] + 1)
    assert result == old
    assert result["result"]["external_calls"] == result["result"]["session_changes"] == 0


@pytest.mark.parametrize("damage", ["delete", "rewrite", "missing", "foreign", "trigger"])
def test_missing_rollback_or_rewritten_baseline_is_not_admitted(lab, damage):
    stage, _ = restore(lab)
    path = stage / response.FILE
    if damage == "missing":
        path.unlink()
    else:
        with sqlite3.connect(path) as db:
            if damage == "delete":
                db.execute("DELETE FROM response_plans WHERE tenant='a'")
            elif damage == "foreign":
                db.execute("PRAGMA application_id=0")
            elif damage == "trigger":
                db.execute("CREATE TRIGGER forbidden AFTER INSERT ON response_plans BEGIN SELECT 1; END")
            else:
                plan = lab.plans["a", "APPROVED"]
                db.execute("UPDATE response_plans SET body=? WHERE tenant=? AND id=?",
                           (json.dumps(plan), "a", plan["id"]))
    with pytest.raises((ValueError, recovery.RecoveryError)):
        recovery.verify_admission(stage, lab.root / "public")


def test_changed_source_after_checkpoint_is_rejected(lab):
    old = lab.plans["a", "PENDING"]
    ResponseWorkflow(lab.data / response.FILE).transition(old["id"], "approve",
        TransitionRequest(expected_version=1, note="New approval"), person("reviewer"))
    with pytest.raises(recovery.RecoveryError, match="source_advanced"):
        lab.store.backup()


def test_source_wal_commits_are_in_snapshot(lab):
    # Keep the WAL connection open so copying only the main DB would miss the committed update.
    with sqlite3.connect(lab.data / response.FILE) as db:
        db.execute("PRAGMA journal_mode=WAL")
        old = lab.plans["a", "PENDING"]
        ResponseWorkflow(lab.data / response.FILE).transition(old["id"], "approve",
            TransitionRequest(expected_version=1, note="WAL approval"), person("reviewer"))
        lab.store.checkpoint()
        lab.backup = lab.store.backup()
        stage, _ = restore(lab)
        plan = ResponseWorkflow(stage / response.FILE).get(old["id"], person())
        assert plan["history"][-2]["state"] == "APPROVED"
        assert plan["state"] == "REJECTED"


def test_new_plan_after_recovery_does_not_change_signed_terminal_baseline(lab):
    stage, _ = restore(lab)
    record = AuditStore(stage / "audit.jsonl").get("event-PENDING", "a")
    service = ResponseWorkflow(stage / response.FILE)
    plan = service.create(record, PlanRequest(event_id=record.event_id,
        analysis_id=record.analysis_id, request_key="new-after-recovery"), person())
    service.transition(plan["id"], "approve", TransitionRequest(expected_version=1, note="New review"),
                       person("reviewer"))
    assert recovery.verify_admission(stage, lab.root / "public")["admission_verified"]


@pytest.mark.parametrize("damage", ["missing", "corrupt", "foreign"])
def test_pinned_response_mode_cannot_silently_downgrade(lab, damage):
    path = lab.data / response.FILE
    if damage == "missing":
        path.unlink()
    elif damage == "corrupt":
        path.write_bytes(b"broken")
    else:
        with sqlite3.connect(path) as db:
            db.execute("PRAGMA application_id=123")
    with pytest.raises((ValueError, sqlite3.Error, recovery.RecoveryError)):
        lab.store.checkpoint()
    with pytest.raises(recovery.RecoveryError, match="publication_incomplete"):
        lab.store.restore(lab.backup["backup_id"])


def test_existing_ledger_requires_explicit_full_and_response_opt_in(tmp_path):
    prepare(tmp_path / "data")
    seed_logs(tmp_path / "data")
    seed(tmp_path / "data")
    with pytest.raises(recovery.RecoveryError, match="explicit_response"):
        recovery.Store(tmp_path).initialize(full_state=True)
    assert not (tmp_path / "control").exists()


def test_gate_pins_response_path_to_recovered_volume(lab, monkeypatch):
    stage, _ = restore(lab)
    settings = SimpleNamespace(analyzer_mode="rule", auth_mode="api_key", audit_backend="jsonl",
        zero_trust_db_path=stage / "app.sqlite3", trusted_signal_sources_path=stage / "sources.json",
        audit_log_path=stage / "audit.jsonl", case_log_path=stage / "cases.jsonl",
        outbox_log_path=stage / "integration-outbox.jsonl", response_workflow_db_path=stage / response.FILE)
    monkeypatch.setattr(gate, "get_settings", lambda: settings)
    assert gate.admit(stage, lab.root / "public")["admission_verified"]
    settings.response_workflow_db_path = lab.data / response.FILE
    with pytest.raises(recovery.RecoveryError, match="response_path"):
        gate.admit(stage, lab.root / "public")


@pytest.mark.parametrize("fail_at", [response.FILE, "release.json"])
def test_real_process_exit_during_restore_denies_old_release_and_retry_recovers(lab, fail_at):
    old_stage, _ = restore(lab)
    program = """import os,sys
from pathlib import Path
from scripts import app_state_recovery as r
original=r.atomic
def fail(path,raw):
    if path.name==sys.argv[3]: os._exit(73)
    original(path,raw)
r.atomic=fail
r.Store(Path(sys.argv[1])).restore(sys.argv[2])
"""
    result = subprocess.run([sys.executable, "-c", program, str(lab.root), lab.backup["backup_id"], fail_at],
                            capture_output=True, env=os.environ.copy(), timeout=30, check=False)
    assert result.returncode == 73
    with pytest.raises(recovery.RecoveryError, match="admission_pin"):
        recovery.verify_admission(old_stage, lab.root / "public")
    new, result = restore(lab)
    assert result["response_plans_fenced"] == 4
    assert recovery.verify_admission(new, lab.root / "public")["admission_verified"]
