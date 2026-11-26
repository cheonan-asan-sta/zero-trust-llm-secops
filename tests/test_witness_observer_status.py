"""Cached monitoring preserves observation age and exposes failed collection."""

import copy
import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import pytest
from test_audit_witness_observer import ready
from test_signal_metrics_exporter import serve

from app.services import audit_witness_observer as observer
from app.services.audit_transfer import AuditTransferError
from scripts import audit_witness_observer as runner
from scripts import signal_metrics_exporter as exporter
from scripts.f1_lab import witness_observer_status as bridge
from scripts.local_process_runtime import direct_python


def fixture(tmp_path):
    source, signer, _key, first, directory, pin = ready(tmp_path)
    observer.cycle(directory, pin, minimum_receipt=first["receipt_sha256"])
    value = bridge.inspect(directory, pin, first["receipt_sha256"])
    path = tmp_path / "status.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    profile = {"schema": bridge.PROFILE_SCHEMA, "status_file": str(path),
               "profile_sha256": pin, "minimum_receipt": first["receipt_sha256"]}
    return source, signer, directory, profile, value


def test_real_observation_exports_only_aggregates_without_source_or_pin_labels(tmp_path):
    source, signer, directory, profile, value = fixture(tmp_path)
    text = bridge.render_report(profile, value)
    assert "secops_witness_status_success 1" in text
    assert "secops_witness_observation_healthy 1" in text
    assert 'secops_witness_state{state="healthy"} 1' in text
    assert "last_cycle_success" not in text  # read is not a signing attempt
    for secret in (str(source.path), str(signer), str(directory), profile["profile_sha256"],
                   profile["minimum_receipt"], (signer / "private.key").read_bytes().hex()):
        assert secret not in text
    assert value["authorization_asserted"] is False


def test_generation_metrics_require_the_approved_record_even_with_matching_observer_pins(tmp_path):
    _, _, directory, legacy, snapshot = fixture(tmp_path)
    pin = "a" * 64
    profile = dict(legacy, schema=bridge.GENERATION_PROFILE_SCHEMA, record_sha256=pin)
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    profile_path.chmod(0o400)
    try:
        assert bridge.load_profile(profile_path) == profile
    finally:
        profile_path.chmod(0o600)
    signed_scope = bridge.inspect(directory, profile["profile_sha256"], profile["minimum_receipt"],
                                  record_sha256=pin, cycle_success=True)
    wrong_scope = dict(signed_scope, record_sha256="b" * 64)
    for rejected in (snapshot, wrong_scope):
        metrics = bridge.render_report(profile, rejected)
        assert "secops_witness_status_success 0" in metrics
        assert "anchor_count" not in metrics
    metrics = bridge.render_report(profile, signed_scope)
    assert "secops_witness_status_success 1" in metrics
    assert "secops_witness_last_cycle_success 1" in metrics
    assert pin not in metrics


def test_cached_observation_expires_even_before_report_cache_ttl(tmp_path):
    _, _, _, profile, value = fixture(tmp_path)
    # Real observation is still valid at publication; time advances after it.
    value["values"]["max_age_seconds"] = 2
    path = profile["status_file"]
    Path(path).write_text(json.dumps(value), encoding="utf-8")
    text = bridge.render_report(profile, value, now=datetime.now(UTC) + timedelta(seconds=3))
    assert "status_success 1" in text and "observation_healthy 0" in text
    assert 'state="stale"} 1' in text


@pytest.mark.parametrize("delta", [-1, bridge.TTL + 1])
def test_future_or_expired_cached_report_has_no_old_counters(tmp_path, delta):
    _, _, _, profile, value = fixture(tmp_path)
    now = datetime.fromisoformat(value["checked_at"]) + timedelta(seconds=delta)
    text = bridge.render_report(profile, value, now=now)
    assert "status_success 0" in text and "observation_healthy 0" in text
    assert "anchor_count" not in text and "state{" not in text


@pytest.mark.parametrize("mutation", [
    lambda v: v.update(profile_sha256="0" * 64),
    lambda v: v.update(minimum_receipt="0" * 64),
    lambda v: v.update(authorization_asserted=True),
    lambda v: v.update(automatic_activation_allowed=True),
    lambda v: v.update(independent_storage_verified=True),
    lambda v: v.update(cycle_success=1),
    lambda v: v.update(unexpected="identity"),
    lambda v: v["values"].update(live_checked=False),
    lambda v: v["values"].update(audit_minimum_verified=False),
    lambda v: v["values"].update(unobserved_rows=1),
    lambda v: v["values"].update(pending_started_at=v["checked_at"]),
    lambda v: v["values"].update(remaining_receipts=0),
    lambda v: v["values"].update(anchor_count=True),
    lambda v: v["values"].update(observed_at=None),
    lambda v: v["values"].update(max_age_seconds=float("nan")),
])
def test_invalid_or_false_healthy_cache_never_exports_good_old_values(tmp_path, mutation):
    _, _, _, profile, value = fixture(tmp_path)
    mutation(value)
    Path(profile["status_file"]).write_text(json.dumps(value), encoding="utf-8")
    text = bridge.render_report(profile, value)
    assert "status_success 0" in text and "observation_healthy 0" in text
    assert "anchor_count" not in text


def test_missing_or_broken_origin_is_an_explicit_unhealthy_new_report(tmp_path):
    _, signer, directory, profile, _ = fixture(tmp_path)
    (signer / "journal.sqlite3").unlink()
    value = bridge.inspect(directory, profile["profile_sha256"], profile["minimum_receipt"])
    assert value["values"]["state"] == "unavailable"
    assert not value["values"]["live_checked"]
    # Broken control is different: producer emits no verified counters at all.
    (directory / "profile.json").write_text("broken", encoding="utf-8")
    value = bridge.inspect(directory, profile["profile_sha256"], profile["minimum_receipt"])
    assert value["values"] == {} and not value["automatic_activation_allowed"]


def test_watch_failure_is_not_erased_by_a_successful_read_or_last_good_observation(tmp_path, capsys):
    _, signer, directory, profile, _ = fixture(tmp_path)
    (signer / "private.key").unlink()
    code = runner.watch(directory, profile["profile_sha256"],
                        minimum_receipt=profile["minimum_receipt"], cycles=1)
    value = json.loads(capsys.readouterr().out)
    assert code == 1 and value["cycle_success"] is False
    assert value["state"] == "pending" and value["pending"]
    assert value["signing_capability_checked"] is False


@pytest.mark.skipif(os.name != "posix", reason="native cache permission contract")
def test_exporter_bridge_is_opt_in_authenticated_and_source_independent(tmp_path, monkeypatch):
    _, signer, directory, profile, _ = fixture(tmp_path)
    # Source files are not read during a scrape: only the bounded public cache.
    monkeypatch.setattr(observer, "status", lambda *a, **k: pytest.fail("live DB scrape"))
    monkeypatch.setattr(exporter, "metrics", lambda *a, **k: "secops_signal_collection_success 0\n")
    http = build_opener(ProxyHandler({}))
    token = "test-scrape-token"
    with serve(exporter.handler("unused", "upstream-secret", token, witness_profile=profile)) as url:
        with pytest.raises(HTTPError) as error:
            http.open(url + "/metrics")
        assert error.value.code == 401
        with http.open(Request(url + "/metrics", headers={"Authorization": "Bearer " + token})) as r:
            body = r.read().decode()
            assert r.headers["Cache-Control"] == "no-store"
            assert "witness_observation_healthy 1" in body
            assert "upstream-secret" not in body and str(signer) not in body and str(directory) not in body
    with serve(exporter.handler("unused", "upstream-secret", token)) as url, http.open(
        Request(url + "/metrics", headers={"Authorization": "Bearer " + token})
    ) as r:
        assert "witness" not in r.read().decode()


@pytest.mark.skipif(os.name != "posix", reason="POSIX locked durable publication")
def test_publication_prevents_clock_rollback_scope_replacement_and_link_writes(tmp_path):
    _, _, _, _profile, value = fixture(tmp_path)
    path = tmp_path / "published.json"
    bridge.publish(path, value)
    before = path.read_bytes()
    old = copy.deepcopy(value)
    old["checked_at"] = (datetime.fromisoformat(value["checked_at"]) - timedelta(seconds=1)).isoformat()
    old["values"] = {}
    with pytest.raises(AuditTransferError, match="publication_clock"):
        bridge.publish(path, old)
    changed = copy.deepcopy(value)
    changed["minimum_receipt"] = "f" * 64
    with pytest.raises(AuditTransferError, match="binding"):
        bridge.publish(path, changed)
    assert path.read_bytes() == before
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(AuditTransferError, match="output"):
        bridge.publish(alias, value)
    assert path.read_bytes() == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX locked durable publication")
def test_publisher_active_lease_and_unsafe_parent_fail_before_replacement(tmp_path):
    import fcntl
    _, _, _, _, value = fixture(tmp_path)
    path = tmp_path / "published.json"
    lock = tmp_path / ".published.json.lock"
    lock.touch(mode=0o600)
    with lock.open("rb") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            bridge.publish(path, value)
        assert not path.exists()
    tmp_path.chmod(0o777)
    try:
        with pytest.raises(AuditTransferError, match="parent_permissions"):
            bridge.publish(path, value)
    finally:
        tmp_path.chmod(0o700)


def test_windows_publication_rejects_before_mutation(tmp_path, monkeypatch):
    # Capability check can be tested on Linux without relabeling a POSIX run.
    monkeypatch.setattr(bridge.status_publication.os, "name", "nt")
    with pytest.raises(AuditTransferError, match="posix_required"):
        bridge.publish(str(tmp_path / "never-created.json"), {})


def test_failed_cycle_keeps_a_distinct_metric_even_when_snapshot_is_healthy(tmp_path):
    _, _, _, profile, value = fixture(tmp_path)
    value["cycle_success"] = False
    Path(profile["status_file"]).write_text(json.dumps(value), encoding="utf-8")
    text = bridge.render_report(profile, value)
    assert "observation_healthy 1" in text and "last_cycle_success 0" in text


@pytest.mark.skipif(os.name != "posix", reason="native cache permission contract")
def test_real_bounded_watch_publication_retains_failure_and_recovers_same_pending(tmp_path):
    _, signer, directory, profile, _ = fixture(tmp_path)
    target = tmp_path / "published.json"
    profile["status_file"] = str(target)
    binary, environment = direct_python(dict(os.environ, AWS_EC2_METADATA_DISABLED="true"))
    argv = [binary, "-m", "scripts.audit_witness_observer", "watch", "--directory", str(directory),
            "--profile-sha256", profile["profile_sha256"], "--minimum-receipt", profile["minimum_receipt"],
            "--cycles", "1", "--status-file", str(target)]
    private = (signer / "private.key").read_bytes()
    (signer / "private.key").unlink()
    before = (signer / "journal.sqlite3").read_bytes()
    failed = subprocess.run(argv, env=environment, capture_output=True, text=True, timeout=30, check=False)
    assert failed.returncode == 1, failed.stderr
    assert json.loads(failed.stdout)["cycle_success"] is False
    assert (signer / "journal.sqlite3").read_bytes() == before
    text = bridge.metrics(profile)
    assert 'state="pending"} 1' in text and "last_cycle_success 0" in text
    (signer / "private.key").write_bytes(private)
    (signer / "private.key").chmod(0o600)
    recovered = subprocess.run(argv, env=environment, capture_output=True, text=True, timeout=30, check=False)
    assert recovered.returncode == 0, recovered.stderr
    text = bridge.metrics(profile)
    assert "last_cycle_success 1" in text and "observation_healthy 1" in text
    assert "anchor_count 2" in text


@pytest.mark.skipif(os.name != "posix", reason="native cache permission contract")
def test_public_cache_corruption_expiration_and_profile_mismatch_are_red(tmp_path):
    _, _, _, profile, value = fixture(tmp_path)
    assert "status_success 1" in bridge.metrics(profile)
    path = Path(profile["status_file"])
    path.write_text('{"schema":1,"schema":2}', encoding="utf-8")
    assert "status_success 0" in bridge.metrics(profile)
    path.write_text(json.dumps(value), encoding="utf-8")
    profile["minimum_receipt"] = "f" * 64
    assert "status_success 0" in bridge.metrics(profile)
    profile["minimum_receipt"] = value["minimum_receipt"]
    text = bridge.metrics(profile, now=datetime.fromisoformat(value["checked_at"])
                          + timedelta(seconds=bridge.TTL + 1))
    assert "status_success 0" in text and "anchor_count" not in text


@pytest.mark.parametrize("state", ["pending", "capacity_pressure", "capacity_exhausted", "witness_advanced"])
def test_other_states_remain_distinct_and_never_healthy(tmp_path, state):
    _, _, _, profile, value = fixture(tmp_path)
    value["values"]["state"] = state
    if state == "pending":
        value["values"]["pending_started_at"] = value["checked_at"]
    text = bridge.render_report(profile, value)
    assert f'state="{state}"}} 1' in text and "observation_healthy 0" in text


def test_report_schema_cannot_inject_source_fields_or_change_false_trust_flags(tmp_path):
    _, _, _, profile, value = fixture(tmp_path)
    value["values"]["raw_command"] = "sensitive-command"
    text = bridge.render_report(profile, value)
    assert "status_success 0" in text and "sensitive-command" not in text
    assert "anchor_count" not in text
