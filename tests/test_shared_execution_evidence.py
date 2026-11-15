import base64
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.shared_execution_collector import runtime_proof
from scripts.f1_lab.shared_execution_evidence import (
    PinnedServiceRegistry,
    PolicyObservation,
    ProcessObservation,
    ServiceEvent,
    ServiceEvidenceJoiner,
    VerifiedServiceRisk,
    proof_bytes,
)
from scripts.f1_lab.transfer_evaluation import sha
from scripts.run_shared_execution_controls import capture_case, run, setup, sign_policy


def bundle(tmp_path, decision="deny", capacity=10000):
    keys, registry, pinned = setup(tmp_path / "keys")
    now = registry.issued_at + timedelta(minutes=2)
    event = ServiceEvent(
        tenant_id="local-lab",
        server_id="shared-lab",
        unit="shared-fixture.service",
        boot_id="1" * 32,
        invocation_id="2" * 32,
        process_id=42,
        event_id="e" * 64,
        raw_sha256="d" * 64,
        observed_at=now,
        mode="local_process_lab",
        collection_basis="local_process_lab",
    )
    observation = ProcessObservation(
        pid=42,
        start_ticks=100,
        parent_pid=1,
        real_uid=10001,
        effective_uid=10001,
        login_uid=None,
        audit_session_id=None,
        executable_sha256="a" * 64,
        command_sha256="b" * 64,
        argument_count=3,
        parent_ref_sha256=None,
    )
    runtime = runtime_proof(
        event,
        observation,
        keys["runtime"],
        source_id="local-proc",
        key_id="proc-1",
        observed_at=now,
    )
    policy = PolicyObservation(
        decision=decision,
        policy_sha256=registry.policy_sha256,
        policy_version=1,
        executable_sha256="a" * 64,
        command_sha256="b" * 64,
    )
    permission = sign_policy(event, policy, keys["authorization"], observed_at=now, issued_at=now)
    joiner = ServiceEvidenceJoiner(
        pinned, tmp_path / "ledger.sqlite3", expected_mode="local_process_lab", capacity=capacity
    )
    return keys, registry, pinned, event, [runtime, permission], joiner, now


def resign(proof, key):
    return proof.model_copy(
        update={
            "signature": base64.urlsafe_b64encode(key.sign(proof_bytes(proof))).decode().rstrip("=")
        }
    )


@pytest.mark.parametrize(
    "decision,state,alert",
    [("allow", "consistent", False), ("deny", "adverse", True), ("unknown", "review", False)],
)
def test_separate_authorization_and_execution_are_required(tmp_path, decision, state, alert):
    _, _, _, event, proofs, joiner, now = bundle(tmp_path, decision)
    facts = joiner.check(event, proofs, now=now)
    assert facts.state == state and facts.evidence_sha256 and not facts.duplicate
    previous = OperationDecision(0.2, 0.2, False, False, "baseline")
    result = VerifiedServiceRisk(joiner).decide(previous, event=event, proofs=proofs, now=now)
    assert result.alert is alert and not result.automatic_enforcement_allowed
    if not alert:
        assert result is previous


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "other"),
        ("server_id", "other"),
        ("unit", "other.service"),
        ("boot_id", "3" * 32),
        ("invocation_id", "4" * 32),
        ("event_id", "f" * 64),
        ("raw_sha256", "f" * 64),
        ("process_id", 43),
        ("mode", "systemd"),
        ("process_id", True),
    ],
)
def test_proof_cannot_be_moved_to_another_event_or_scope(tmp_path, field, value):
    _, _, _, event, proofs, joiner, now = bundle(tmp_path)
    event = event.model_copy(update={field: value})
    assert joiner.check(event, proofs, now=now).state == "unavailable"


@pytest.mark.parametrize(
    "field,value",
    [
        ("executable_sha256", "c" * 64),
        ("command_sha256", "c" * 64),
        ("policy_sha256", "c" * 64),
        ("policy_version", 0),
    ],
)
def test_correctly_signed_wrong_command_or_policy_is_rejected(tmp_path, field, value):
    keys, _, _, event, proofs, joiner, now = bundle(tmp_path)
    changed = proofs[1].model_copy(
        update={"observation": proofs[1].observation.model_copy(update={field: value})}
    )
    proofs[1] = resign(changed, keys["authorization"])
    assert joiner.check(event, proofs, now=now).state == "unavailable"


@pytest.mark.parametrize(
    "mode",
    [
        "one",
        "duplicate",
        "signature",
        "wrong_role",
        "source",
        "key",
        "post_policy",
        "old_policy",
        "runtime_before",
        "runtime_late",
        "expired",
        "future",
        "naive",
    ],
)
def test_missing_forged_stale_or_post_event_proofs_do_not_add_alert(tmp_path, mode):
    keys, _, _, event, proofs, joiner, now = bundle(tmp_path)
    if mode == "one":
        proofs = proofs[:1]
    elif mode == "duplicate":
        proofs = [proofs[0], proofs[0]]
    elif mode == "signature":
        proofs[0] = proofs[0].model_copy(update={"signature": "A" * 86})
    elif mode == "wrong_role":
        proofs[1] = resign(proofs[1], keys["runtime"])
    elif mode == "source":
        proofs[0] = resign(proofs[0].model_copy(update={"source_id": "other"}), keys["runtime"])
    elif mode == "key":
        proofs[0] = resign(proofs[0].model_copy(update={"key_id": "other"}), keys["runtime"])
    elif mode == "post_policy":
        proofs[1] = resign(
            proofs[1].model_copy(update={"observed_at": now + timedelta(seconds=1)}),
            keys["authorization"],
        )
    elif mode == "old_policy":
        proofs[1] = resign(
            proofs[1].model_copy(update={"observed_at": now - timedelta(seconds=31)}),
            keys["authorization"],
        )
    elif mode == "runtime_before":
        proofs[0] = resign(
            proofs[0].model_copy(update={"observed_at": now - timedelta(seconds=1)}),
            keys["runtime"],
        )
    elif mode == "runtime_late":
        proofs[0] = resign(
            proofs[0].model_copy(
                update={
                    "observed_at": now + timedelta(seconds=6),
                    "issued_at": now + timedelta(seconds=6),
                }
            ),
            keys["runtime"],
        )
        now += timedelta(seconds=6)
    elif mode == "expired":
        now += timedelta(seconds=30)
    elif mode == "future":
        now -= timedelta(seconds=1)
    else:
        now = now.replace(tzinfo=None)
    previous = OperationDecision(0.1, 0.1, False, False, "baseline")
    assert (
        VerifiedServiceRisk(joiner).decide(previous, event=event, proofs=proofs, now=now)
        is previous
    )


def test_restart_duplicate_does_not_create_another_receipt_and_collision_is_rejected(tmp_path):
    keys, _, pinned, event, proofs, joiner, now = bundle(tmp_path)
    assert joiner.check(event, proofs, now=now).state == "adverse"
    restarted = ServiceEvidenceJoiner(
        pinned, tmp_path / "ledger.sqlite3", expected_mode="local_process_lab"
    )
    assert restarted.check(event, list(reversed(proofs)), now=now + timedelta(seconds=1)).duplicate
    changed = event.model_copy(update={"raw_sha256": "f" * 64})
    altered = [
        resign(p.model_copy(update={"event_sha256": changed.sha256}), keys[p.observation.kind])
        for p in proofs
    ]
    assert restarted.check(changed, altered, now=now + timedelta(seconds=1)).state == "unavailable"
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as con:
        assert con.execute("SELECT count(*) FROM observations").fetchone()[0] == 1


def test_clock_rollback_is_rejected_after_restart(tmp_path):
    _, _, pinned, event, proofs, joiner, now = bundle(tmp_path)
    assert joiner.check(event, proofs, now=now + timedelta(seconds=2)).state == "adverse"
    other = ServiceEvidenceJoiner(
        pinned, tmp_path / "ledger.sqlite3", expected_mode="local_process_lab"
    )
    assert other.check(event, proofs, now=now + timedelta(seconds=1)).state == "unavailable"


def test_concurrent_duplicate_deliveries_keep_one_bound_receipt(tmp_path):
    _, _, _, event, proofs, joiner, now = bundle(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: joiner.check(event, proofs, now=now), range(8)))
    assert all(result.state == "adverse" for result in results)
    assert sum(not result.duplicate for result in results) == 1
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as con:
        assert con.execute("SELECT count(*) FROM observations").fetchone()[0] == 1


@pytest.mark.parametrize(
    "mode", ["disabled", "rotated", "hash_changed", "role_key_reused", "minimum_policy"]
)
def test_current_registry_is_revalidated_even_for_duplicates(tmp_path, mode):
    _, registry, pinned, event, proofs, joiner, now = bundle(tmp_path)
    assert joiner.check(event, proofs, now=now).state == "adverse"
    data = registry.model_dump(mode="json")
    data["version"] = 2
    if mode == "disabled":
        data["authorities"][0]["enabled"] = False
    elif mode == "rotated":
        _, fresh, _ = setup(tmp_path / "rotated")
        data["authorities"][0]["public_key"] = fresh.authorities[0].public_key
    elif mode == "role_key_reused":
        data["authorities"][1]["public_key"] = data["authorities"][0]["public_key"]
    elif mode == "minimum_policy":
        data["minimum_policy_version"] = 2
    else:
        data["policy_sha256"] = "f" * 64
    pinned.path.write_bytes(canonical(data))
    assert joiner.check(event, proofs, now=now).state == "unavailable"
    updated = PinnedServiceRegistry(pinned.path, sha(pinned.path), minimum_version=2)
    new = ServiceEvidenceJoiner(
        updated, tmp_path / "ledger.sqlite3", expected_mode="local_process_lab"
    )
    assert new.check(event, proofs, now=now).state == "unavailable"
    current_alarm = OperationDecision(0.1, 1.0, True, True, "existing")
    assert (
        VerifiedServiceRisk(new).decide(current_alarm, event=event, proofs=proofs, now=now)
        is current_alarm
    )


def test_lab_evidence_is_not_accepted_by_default_systemd_joiner(tmp_path):
    _, _, pinned, event, proofs, _, now = bundle(tmp_path)
    assert (
        ServiceEvidenceJoiner(pinned, tmp_path / "systemd.sqlite3")
        .check(event, proofs, now=now)
        .state
        == "unavailable"
    )


def test_capacity_and_corrupt_store_do_not_produce_verified_facts(tmp_path):
    keys, _, _, event, proofs, joiner, now = bundle(tmp_path, capacity=1)
    assert joiner.check(event, proofs, now=now).state == "adverse"
    event = event.model_copy(update={"event_id": "f" * 64})
    proofs = [
        resign(p.model_copy(update={"event_sha256": event.sha256}), keys[p.observation.kind])
        for p in proofs
    ]
    assert joiner.check(event, proofs, now=now).state == "unavailable"
    (tmp_path / "ledger.sqlite3").write_bytes(b"corrupt store")
    assert joiner.check(event, proofs, now=now).state == "unavailable"


def test_unavailable_event_preserves_every_existing_decision(tmp_path):
    _, _, _, _, _, joiner, _ = bundle(tmp_path)
    adapter = VerifiedServiceRisk(joiner)
    for alert in [False, True]:
        old = OperationDecision(0.1, 0.99 if alert else 0.1, alert, alert, "old")
        assert adapter.decide(old) is old


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux /proc")
def test_real_owned_process_collection_and_policy_controls(tmp_path):
    report = run(tmp_path / "actual")
    assert report["completed"] and len(report["cases"]) == 7
    assert report["normal_added_alerts"] == 0 and report["adverse_detected"] == 1
    assert report["owned_child_processes_stopped"] and not report["private_keys_persisted"]


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux /proc")
def test_actual_snapshot_keeps_unknown_login_identity_and_hashes_only(tmp_path):
    keys, registry, _ = setup(tmp_path / "actual")
    event, proofs = capture_case(keys, registry)
    observation = proofs[0].observation
    assert observation.pid == event.process_id and observation.start_ticks > 0
    assert (
        observation.command_sha256
        and observation.executable_sha256
        and observation.argument_count == 4
    )
    assert "argv" not in observation.model_dump() and "command" not in observation.model_dump()
