import hashlib
from dataclasses import replace

import pytest

from scripts import run_audit_auth_review as driver
from scripts.f1_lab.audit_auth_review import (
    AuditReview,
    SuEvent,
    caller_events,
    field,
    refine,
    su_transition,
)
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.native_jsonl import decode
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.transfer_evaluation import sha


def auth(body="Successful su for worker by www-data", pid=42):
    return f"Jan 24 12:00:00 host su[{pid}]: {body}"


def audit(kind="USER_AUTH", pid=42, acct="worker", exe="/bin/su", extra="", res="success"):
    return (
        f"type={kind} msg=audit(1643025600.1:1): pid={pid} uid=0 auid=1001 ses=3 "
        f'msg=\'op=PAM:authentication acct="{acct}" exe="{exe}" res={res} {extra}\''
    )


@pytest.mark.parametrize(
    "message", ["Successful su for worker by www-data", "+ /dev/pts/1 www-data:worker"]
)
def test_explicit_service_caller_transition(message):
    assert su_transition(auth(message)) == (42, "worker")


@pytest.mark.parametrize(
    "message",
    [
        "Successful su for worker by admin",
        "Successful su for www-data by www-data",
        "failed su for worker by www-data",
        "prefix Successful su for worker by www-data",
        "Successful su for worker by www-data trailing",
        "+ /dev/pts/1 admin:worker",
        "Successful su for worker by www-data\nforged",
    ],
)
def test_ordinary_or_spoofed_messages_are_not_seed(message):
    assert su_transition(auth(message)) is None


@pytest.mark.parametrize("pid", [0, 4294967295, 99999999999])
def test_invalid_process_ids_are_not_seed(pid):
    assert su_transition(auth(pid=pid)) is None


def test_source_time_regression_disables_seed_source():
    assert caller_events([(2, auth()), (1, auth())]) == ()
    assert len(caller_events([(None, auth()), (1, auth())])) == 1


def primed():
    review = AuditReview((SuEvent(10, 42, "worker"),))
    assert review.observe(audit(), 10.1) is None
    return review


@pytest.mark.parametrize("kind", ["USER_ACCT", "CRED_ACQ", "USER_START"])
def test_exact_past_caller_seed_can_explain_systemd_account_transition(kind):
    assert primed().observe(audit(kind, pid=43, exe="/lib/systemd/systemd"), 10.2)


@pytest.mark.parametrize(
    "mode",
    ["future", "tie", "expired", "wrong_pid", "wrong_account", "failed", "wrong_exe", "no_seed"],
)
def test_missing_or_mismatched_causal_seed_does_not_propagate(mode):
    time = {"future": 11, "tie": 10.1, "expired": 0}.get(mode, 10)
    review = AuditReview(
        ()
        if mode == "no_seed"
        else (
            SuEvent(
                time,
                41 if mode == "wrong_pid" else 42,
                "other" if mode == "wrong_account" else "worker",
            ),
        )
    )
    review.observe(
        audit(
            res="failed" if mode == "failed" else "success",
            exe="/usr/bin/id" if mode == "wrong_exe" else "/bin/su",
        ),
        10.1,
    )
    assert review.observe(audit("USER_ACCT", pid=43, exe="/lib/systemd/systemd"), 10.2) is None


def login(pid=43, auid=1001, ses=3):
    return f"type=LOGIN msg=audit(1643025600.1:1): pid={pid} uid=0 auid={auid} ses={ses} res=1"


def test_login_requires_strictly_earlier_same_process_account_observation():
    review = primed()
    review.observe(audit("USER_ACCT", pid=43, exe="/lib/systemd/systemd"), 10.2)
    assert review.observe(login(), 10.2) is None
    assert review.observe(login(pid=44), 10.3) is None
    assert review.observe(login(auid=4294967295), 10.3) is None
    assert review.observe(login(ses=4294967295), 10.3) is None
    assert review.observe(login(), 10.3)


def test_reused_pid_with_another_account_cannot_borrow_previous_risk():
    review = primed()
    review.observe(audit("USER_ACCT", pid=43, exe="/lib/systemd/systemd"), 10.2)
    review.observe(audit("USER_ACCT", pid=43, acct="other", exe="/lib/systemd/systemd"), 10.3)
    assert review.observe(login(), 10.4) is None


def service(unit="user@1001", exe="/lib/systemd/systemd"):
    return (
        f"type=SERVICE_START msg=audit(1643025600.1:1): pid=1 uid=0 auid=4294967295 ses=4294967295 "
        f'msg=\'unit={unit} comm="systemd" exe="{exe}" res=success\''
    )


def test_user_manager_needs_explicit_valid_uid_binding_not_unset_identity():
    review = primed()
    assert review.observe(service(), 10.2) is None
    review.observe(audit("USER_START", pid=43, exe="/lib/systemd/systemd"), 10.3)
    assert review.observe(service(), 10.3) is None
    assert review.observe(service(unit="user@1002"), 10.4) is None
    assert review.observe(service(exe="/tmp/unknown"), 10.4) is None
    assert review.observe(service(unit="arbitrary-transient-name"), 10.4) is None
    assert review.observe(service(), 10.4)


@pytest.mark.parametrize("reset", [None, 9])
def test_missing_time_or_regression_clears_process_and_user_links(reset):
    review = primed()
    review.observe(audit("USER_START", pid=43, exe="/lib/systemd/systemd"), 10.2)
    review.observe("", reset)
    assert review.observe(service(), 10.4) is None
    assert review.observe(login(), 10.4) is None


def test_repetition_does_not_extend_episode_and_new_instance_cannot_inherit():
    review = primed()
    review.observe(audit(), 14.9)
    assert review.observe(audit("USER_ACCT", pid=43, exe="/lib/systemd/systemd"), 15.001) is None
    assert (
        AuditReview().observe(audit("USER_ACCT", pid=43, exe="/lib/systemd/systemd"), 10.3) is None
    )


def test_nested_field_injection_and_duplicate_values_are_not_authority():
    assert field("pid=1 pid=2", "pid") is None
    assert field("msg='acct=\"worker res=success\"'", "res") is None
    assert field("msg='acct=\"worker\" res=success'", "res") == "success"
    assert field("pid=1 msg='pid=2 res=success'", "res") is None
    assert field("msg='unterminated", "res") is None


def test_decisions_are_additive_and_advisory_only():
    old = OperationDecision(0.2, 0.2, False, False, "old")
    assert refine(old, None) is old
    new = refine(old, "web_service_account_su")
    assert new.alert and new.review and new.score == 0.95 and not new.automatic_enforcement_allowed
    alarm = replace(old, score=1.0, alert=True, review=True)
    assert refine(alarm, "web_service_account_su") is alarm
    with pytest.raises(ValueError):
        refine(replace(old, automatic_enforcement_allowed=True), None)


def fixture(folder):
    raw = folder / "raw"
    raw.mkdir(parents=True)
    sources = [
        (
            "gather/server/logs/auth.log",
            [auth("Successful su for worker by admin"), auth()],
            [False, True],
            [False, False],
        ),
        (
            "gather/server/logs/audit/audit.log",
            [
                audit(),
                audit("USER_ACCT", pid=43, exe="/lib/systemd/systemd"),
                audit("USER_ACCT", pid=44, acct="other", exe="/lib/systemd/systemd"),
            ],
            [True, True, False],
            [True, False, False],
        ),
        ("gather/share/logs/audit/audit.log", [service(unit="unknown")], [True], [False]),
    ]
    pairs, provenance, previous, truth = [], [], [], []
    for index, (member, lines, labels, alerts) in enumerate(sources):
        if index == 1:
            lines = [
                line.replace("5600.1:", "5600." + str(i + 1) + ":") for i, line in enumerate(lines)
            ]
        path = raw / f"pair-{index}-raw.source"
        path.write_bytes(("\n".join(lines) + "\n").encode())
        digest = sha(path)
        pairs.append({"raw_member": member, "raw_sha256": digest, "rows": len(lines)})
        provenance.append(
            {
                "provenance": {
                    **pairs[-1],
                    "simulation_start": 1642982400,
                    "simulation_end": 1643068800,
                }
            }
        )
        for ordinal, (malicious, alert) in enumerate(zip(labels, alerts, strict=True), 1):
            case = hashlib.sha256((digest + ":" + str(ordinal)).encode()).hexdigest()
            previous.append(
                {
                    "case_id": case,
                    "source_index": index,
                    "after": alert,
                    "before_score": 0.99 if alert else 0.1,
                    "after_score": 0.99 if alert else 0.1,
                    "reason": "old",
                    "error": None,
                }
            )
            truth.append({"case_id": case, "malicious": malicious})
    (raw / "audit.json").write_bytes(
        canonical(
            {
                "completed": True,
                "pairs": provenance,
                "timestamp_basis": "naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check",
            }
        )
    )
    prep = {"pairs": pairs, "source_manifest_sha256": sha(raw / "audit.json"), "files": {}}
    baseline = folder / "old.jsonl"
    baseline.write_bytes(b"".join(canonical(p) + b"\n" for p in previous))
    return raw, prep, baseline, truth


def test_real_raw_prediction_keeps_unknown_service_and_never_reads_labels(tmp_path):
    raw, prep, old, _ = fixture(tmp_path)
    (tmp_path / "truth.jsonl").write_bytes(b"poisoned truth")
    out = tmp_path / "predictions.jsonl"
    result = driver.predict(tmp_path, prep, raw, old, sha(old), out)
    rows = [decode(line) for line in out.read_bytes().splitlines()]
    assert [row["after"] for row in rows] == [False, True, True, True, False, False]
    assert result["population"] == 6 and result["inference_errors"] == 0


@pytest.mark.parametrize(
    "mode", ["raw_tamper", "baseline_tamper", "source_order", "wrong_population"]
)
def test_input_tampering_cannot_seal_a_successful_prediction(tmp_path, mode):
    raw, prep, old, _ = fixture(tmp_path)
    expected = sha(old)
    if mode == "raw_tamper":
        (raw / "pair-0-raw.source").write_bytes(b"changed")
    elif mode == "baseline_tamper":
        old.write_bytes(old.read_bytes() + b"changed")
    elif mode == "source_order":
        old.write_bytes(b"".join(reversed(old.read_bytes().splitlines(keepends=True))))
        expected = sha(old)
    else:
        prep["pairs"][0]["rows"] += 1
    out = tmp_path / "out.jsonl"
    with pytest.raises(ValueError):
        driver.predict(tmp_path, prep, raw, old, expected, out)
    assert not out.exists()


def test_full_paired_run_seals_all_scenarios_before_truth_and_preserves_original_fn(
    tmp_path, monkeypatch
):
    plan = {
        "scope": "observed_development_only",
        "goal_qualified": False,
        "candidate_sha256": driver.source_pins(driver.ROOT)["scripts/f1_lab/audit_auth_review.py"],
        "scenarios": [],
    }
    prior = {"scope": plan["scope"], "goal_qualified": False, "completed": True, "scenarios": {}}
    for name in driver.SCENARIOS:
        folder = tmp_path / name
        raw, prep, old, truth = fixture(folder)
        truth_path = folder / "truth.jsonl"
        truth_path.write_bytes(b"".join(canonical(row) + b"\n" for row in truth))
        prep["files"]["truth.jsonl"] = {"sha256": sha(truth_path)}
        (folder / "preparation.json").write_bytes(canonical(prep))
        c = counts()
        for p, g in zip(old.read_bytes().splitlines(), truth, strict=True):
            record(c, g["malicious"], decode(p)["after"])
        prior["scenarios"][name] = {
            "population": 6,
            "prediction": {"predictions_sha256": sha(old)},
            "metrics": {"after": metrics(c)},
        }
        plan["scenarios"].append(
            {
                "name": name,
                "prepared": str(folder),
                "raw": str(raw),
                "preparation_sha256": sha(folder / "preparation.json"),
                "baseline": str(old),
                "baseline_sha256": sha(old),
            }
        )
    plan_path, prior_path = tmp_path / "plan.json", tmp_path / "prior.json"
    plan_path.write_bytes(canonical(plan))
    prior_path.write_bytes(canonical(prior))
    out = tmp_path / "out"
    original = driver.score

    def checked(*args):
        assert (out / "prediction-seal.json").exists()
        assert all((out / (name + "-predictions.jsonl")).exists() for name in driver.SCENARIOS)
        return original(*args)

    monkeypatch.setattr(driver, "score", checked)
    result = driver.run(plan_path, sha(plan_path), prior_path, sha(prior_path), out)
    assert result["completed"] and result["candidate_development_gate_passed"]
    assert all(
        s["metrics"]["after"]["fn"] == 1
        and s["changes"]["new_tp"] == 2
        and s["changes"]["introduced_fp"] == s["changes"]["lost_tp"] == 0
        for s in result["scenarios"].values()
    )
