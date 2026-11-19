"""Normal poll intervals must not cause outages or prematurely critical lag."""

import asyncio
import copy
import json
import os
from datetime import UTC, datetime, timedelta

import pytest
from test_audit_witness import ready
from test_sqlite_audit import initial

from app.services import audit_witness as witness
from app.services import audit_witness_observer as observer
from scripts.f1_lab import witness_observer_status as bridge


def test_default_sixty_second_collection_remains_available_between_healthy_polls(tmp_path):
    source, signer, key_pin, first = ready(tmp_path)
    directory = tmp_path / "control"
    pin = observer.initialize(directory, signer, source.path, key_pin,
                              expected_receipt=first["receipt_sha256"])["profile_sha256"]
    observer.cycle(directory, pin, minimum_receipt=first["receipt_sha256"])
    value = bridge.inspect(directory, pin, first["receipt_sha256"])
    profile = {"profile_sha256": pin, "minimum_receipt": first["receipt_sha256"]}
    now = datetime.fromisoformat(value["checked_at"]) + timedelta(seconds=45)
    text = bridge.render_report(profile, value, now=now)
    assert "secops_witness_status_success 1" in text
    assert "secops_witness_observation_healthy 1" in text


def collected(tmp_path, *, interval=60, max_age=180, capacity_warning=0):
    source, signer, key_pin, first = ready(tmp_path)
    directory = tmp_path / "control"
    pin = observer.initialize(directory, signer, source.path, key_pin,
                              expected_receipt=first["receipt_sha256"], interval_seconds=interval,
                              max_age_seconds=max_age, capacity_warning=capacity_warning)["profile_sha256"]
    observer.cycle(directory, pin, minimum_receipt=first["receipt_sha256"])
    profile = {"profile_sha256": pin, "minimum_receipt": first["receipt_sha256"]}
    value = bridge.inspect(directory, pin, first["receipt_sha256"])
    return source, directory, profile, value


def test_healthy_cache_expires_after_two_configured_cycles_without_reusing_old_counts(tmp_path):
    _, _, profile, value = collected(tmp_path)
    checked = datetime.fromisoformat(value["checked_at"])
    assert "status_success 1" in bridge.render_report(profile, value, now=checked + timedelta(seconds=119))
    expired = bridge.render_report(profile, value, now=checked + timedelta(seconds=121))
    assert "status_success 0" in expired and "anchor_count" not in expired


def test_longest_supported_poll_cadence_uses_its_bound_and_still_expires(tmp_path):
    _, _, profile, value = collected(tmp_path, interval=3600, max_age=7200)
    checked = datetime.fromisoformat(value["checked_at"])
    assert "observation_healthy 1" in bridge.render_report(profile, value, now=checked + timedelta(seconds=3700))
    assert "status_success 0" in bridge.render_report(profile, value, now=checked + timedelta(seconds=7201))


def test_new_rows_remain_unobserved_during_normal_cadence_without_premature_critical_action(tmp_path):
    source, directory, profile, _ = collected(tmp_path)
    asyncio.run(source.save(initial(2)))
    value = bridge.inspect(directory, profile["profile_sha256"], profile["minimum_receipt"])
    checked = datetime.fromisoformat(value["checked_at"])
    normal = bridge.render_report(profile, value, now=checked + timedelta(seconds=60))
    assert 'state="unobserved"} 1' in normal and "observation_healthy 0" in normal
    assert "observation_action_required 0" in normal and "unobserved_rows 1" in normal
    # A fresh check of the same old signed observation does not reset its age.
    later = checked + timedelta(seconds=181)
    state = observer.status(directory, profile["profile_sha256"],
                            minimum_receipt=profile["minimum_receipt"], now=later)
    overdue = bridge.report(profile["profile_sha256"], profile["minimum_receipt"], state, now=later)
    text = bridge.render_report(profile, overdue, now=later)
    assert "status_success 1" in text and "observation_action_required 1" in text
    assert "unobserved_rows 1" in text


def test_pending_has_a_cadence_budget_and_failed_cycles_keep_their_own_signal(tmp_path, monkeypatch):
    _, directory, profile, _ = collected(tmp_path)

    def failed(*args, **kwargs):
        raise OSError("test-owned failure before witness sign")

    monkeypatch.setattr(witness, "observe", failed)
    with pytest.raises(OSError):
        observer.cycle(directory, profile["profile_sha256"], minimum_receipt=profile["minimum_receipt"])
    value = bridge.inspect(directory, profile["profile_sha256"], profile["minimum_receipt"], cycle_success=False)
    checked = datetime.fromisoformat(value["checked_at"])
    normal = bridge.render_report(profile, value, now=checked + timedelta(seconds=60))
    assert "observation_action_required 0" in normal and "last_cycle_success 0" in normal
    later = checked + timedelta(seconds=121)
    state = observer.status(directory, profile["profile_sha256"],
                            minimum_receipt=profile["minimum_receipt"], now=later)
    value = bridge.report(profile["profile_sha256"], profile["minimum_receipt"], state, now=later)
    assert "observation_action_required 1" in bridge.render_report(profile, value, now=later)


@pytest.mark.parametrize("kind", ["legacy_pending", "new_rows"])
def test_known_exhaustion_is_urgent_even_during_pending_or_new_row_grace(tmp_path, monkeypatch, kind):
    monkeypatch.setattr(witness, "MAX_RECEIPTS", 2)
    source, directory, profile, _ = collected(tmp_path)
    state = observer.status(directory, profile["profile_sha256"], minimum_receipt=profile["minimum_receipt"])
    assert state["remaining_receipts"] == 0
    if kind == "legacy_pending":
        # Exact old-version shape: preserve it as evidence, never drop or
        # acknowledge it merely to improve the public state/alert.
        pending = {"observation_id": "a" * 32, "predecessor": state["receipt_sha256"],
                   "started_at": datetime.now(UTC).isoformat()}
        raw = observer.canonical(pending).decode()
        with observer._database(directory, write=True) as con:
            con.execute("INSERT INTO pending VALUES (1,?,?)", (raw, observer.sha(raw.encode())))
    else:
        asyncio.run(source.save(initial(2)))
    before = (directory / "observer.sqlite3").read_bytes()
    value = bridge.inspect(directory, profile["profile_sha256"], profile["minimum_receipt"])
    text = bridge.render_report(profile, value)
    assert value["values"]["state"] == ("pending" if kind == "legacy_pending" else "unobserved")
    assert "observation_healthy 0" in text and "observation_action_required 1" in text
    assert "secops_witness_remaining_receipts 0" in text
    assert (directory / "observer.sqlite3").read_bytes() == before


def test_pressure_is_distinct_from_exhaustion_without_marking_the_observation_healthy(tmp_path, monkeypatch):
    monkeypatch.setattr(witness, "MAX_RECEIPTS", 3)
    _, directory, profile, value = collected(tmp_path, capacity_warning=1)
    warning = bridge.render_report(profile, value)
    assert 'state="capacity_pressure"} 1' in warning and "observation_healthy 0" in warning
    assert "observation_action_required 0" in warning
    observer.cycle(directory, profile["profile_sha256"], minimum_receipt=profile["minimum_receipt"])
    value = bridge.inspect(directory, profile["profile_sha256"], profile["minimum_receipt"])
    full = bridge.render_report(profile, value)
    assert 'state="capacity_exhausted"} 1' in full and "observation_action_required 1" in full


@pytest.mark.parametrize("interval", [True, 0, -1, 3601, "60", 100])
def test_invalid_or_inconsistent_cadence_never_extends_a_cache(tmp_path, interval):
    _, _, profile, value = collected(tmp_path)
    value["values"]["interval_seconds"] = interval
    text = bridge.render_report(profile, value)
    assert "status_success 0" in text and "anchor_count" not in text


def test_legacy_reports_keep_their_old_bound_and_cannot_supply_new_fields(tmp_path):
    _, _, profile, value = collected(tmp_path)
    value["schema"] = bridge.LEGACY_SCHEMA
    value["values"].pop("interval_seconds")
    checked = datetime.fromisoformat(value["checked_at"])
    assert "status_success 1" in bridge.render_report(profile, value, now=checked + timedelta(seconds=10))
    assert "status_success 0" in bridge.render_report(profile, value, now=checked + timedelta(seconds=31))
    value["values"]["interval_seconds"] = 3600
    assert "status_success 0" in bridge.render_report(profile, value)


@pytest.mark.skipif(os.name != "posix", reason="native public cache publication")
def test_v1_to_v2_cache_upgrade_keeps_same_pins_and_monotonic_checked_time(tmp_path):
    _, _, profile, current = collected(tmp_path)
    legacy = copy.deepcopy(current)
    legacy["schema"] = bridge.LEGACY_SCHEMA
    legacy["values"].pop("interval_seconds")
    path = tmp_path / "public.json"
    bridge.publish(path, legacy)
    bridge.publish(path, current)
    assert json.loads(path.read_text())["schema"] == bridge.SCHEMA
    assert json.loads(path.read_text())["profile_sha256"] == profile["profile_sha256"]
