import copy
import os
import stat
import sys
from datetime import UTC, datetime, timedelta

import pytest

from scripts.f1_lab import collector_status_bridge as bridge
from scripts.f1_lab.capture_archive import ArchiveScope
from scripts.f1_lab.collector_freshness import CollectorMonitor, atomic_capture
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_collector import runtime_proof
from tests.test_collector_freshness import envelope, fixture

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="POSIX public status file contract")


def setup(tmp_path):
    scope = ArchiveScope(
        tenant_id="tenant-secret", server_id="host-secret", unit="app.service", source_id="proc"
    )
    now = datetime.now(UTC)
    health = bridge.report(
        "health",
        scope,
        "fresh",
        checked_at=now,
        observed_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(seconds=5),
    )
    archive = bridge.report(
        "archive", scope, "ready", checked_at=now, values=dict.fromkeys(bridge.COUNTERS, 1)
    )
    profile = {
        "schema": "zt-collector-metrics-profile-1",
        "scope_sha256": bridge.scope_hash(scope),
        "health_file": str(tmp_path / "health.json"),
        "archive_file": str(tmp_path / "archive.json"),
    }
    for name, value in [("health", health), ("archive", archive)]:
        bridge.publish(profile[name + "_file"], value)
    return scope, now, health, archive, profile


def test_public_projection_is_bounded_and_contains_no_raw_identity_or_credentials(tmp_path):
    _, now, _, _, profile = setup(tmp_path)
    raw = (tmp_path / "health.json").read_bytes() + bridge.metrics(profile, now=now).encode()
    assert b"secops_collector_observation_fresh 1" in raw
    assert all(
        value not in raw
        for value in [
            b"tenant-secret",
            b"host-secret",
            b"app.service",
            b"signature",
            b"private_key",
        ]
    )
    assert stat.S_IMODE((tmp_path / "health.json").stat().st_mode) == 0o644
    assert len(raw) < 8192


@pytest.mark.parametrize(
    "seconds,fresh,available", [(0, 1, 1), (5, 0, 1), (25, 0, 0), (181, 0, 0), (-1, 0, 0)]
)
def test_scrape_expires_proof_and_stopped_worker_reports_without_reusing_fresh_values(
    tmp_path, seconds, fresh, available
):
    _, now, _, _, profile = setup(tmp_path)
    text = bridge.metrics(profile, now=now + timedelta(seconds=seconds))
    assert f"secops_collector_observation_fresh {fresh}\n" in text
    assert f'secops_collector_status_success{{worker="health"}} {available}\n' in text
    if seconds >= 181:
        assert 'secops_collector_status_success{worker="archive"} 0' in text
        assert "secops_collector_archive_records " not in text


@pytest.mark.parametrize(
    "mode",
    [
        "missing",
        "corrupt",
        "oversize",
        "symlink",
        "hardlink",
        "writable",
        "foreign_scope",
        "foreign_kind",
        "extra_field",
        "future",
        "invalid_window",
        "bool_counter",
    ],
)
def test_unsafe_reports_fail_closed_without_leaking_content(tmp_path, mode):
    _, now, health, archive, profile = setup(tmp_path)
    path = tmp_path / ("archive.json" if mode == "bool_counter" else "health.json")
    value = copy.deepcopy(archive if mode == "bool_counter" else health)
    if mode == "missing":
        path.unlink()
    elif mode == "corrupt":
        path.write_bytes(b"secret-not-json")
    elif mode == "oversize":
        path.write_bytes(b"x" * 8193)
    elif mode == "symlink":
        path.unlink()
        path.symlink_to(tmp_path / "archive.json")
    elif mode == "hardlink":
        os.link(path, tmp_path / "other")
    elif mode == "writable":
        path.chmod(0o666)
    else:
        if mode == "foreign_scope":
            value["scope_sha256"] = "f" * 64
        elif mode == "foreign_kind":
            value["kind"] = "archive"
        elif mode == "extra_field":
            value["secret"] = "must-never-export"
        elif mode == "future":
            value["checked_at"] = (now + timedelta(seconds=1)).isoformat()
        elif mode == "invalid_window":
            value["expires_at"] = (now + timedelta(hours=1)).isoformat()
        elif mode == "bool_counter":
            value["values"]["archive_records"] = True
        path.write_bytes(canonical(value))
    text = bridge.metrics(profile, now=now)
    kind = "archive" if mode == "bool_counter" else "health"
    assert f'secops_collector_status_success{{worker="{kind}"}} 0' in text
    assert "must-never-export" not in text and "secret-not-json" not in text
    if kind == "health":
        assert "secops_collector_observation_fresh 0" in text


@pytest.mark.parametrize(
    "mode", ["symlink", "hardlink", "wrong_scope", "clock_regression", "wrong_kind", "corrupt"]
)
def test_publication_refuses_unsafe_existing_destination(tmp_path, mode):
    _, _, health, _, profile = setup(tmp_path)
    path = tmp_path / "health.json"
    if mode == "symlink":
        path.unlink()
        path.symlink_to(tmp_path / "archive.json")
    elif mode == "hardlink":
        os.link(path, tmp_path / "alias")
    elif mode == "wrong_scope":
        health["scope_sha256"] = "f" * 64
    elif mode == "clock_regression":
        health["checked_at"] = (
            bridge.timestamp(health["checked_at"]) - timedelta(microseconds=1)
        ).isoformat()
    elif mode == "wrong_kind":
        health = bridge.read_public(profile["archive_file"])
    else:
        path.write_bytes(b"bad")
    before = path.read_bytes()
    with pytest.raises((ValueError, OSError)):
        bridge.publish(path, health)
    assert path.read_bytes() == before


def test_failed_atomic_replace_preserves_last_report_and_removes_only_own_temp(
    tmp_path, monkeypatch
):
    _, _, health, _, _ = setup(tmp_path)
    before = (tmp_path / "health.json").read_bytes()

    def fail(*_):
        raise OSError("controlled_replace_failure")

    monkeypatch.setattr(bridge.os, "replace", fail)
    with pytest.raises(OSError):
        bridge.publish(tmp_path / "health.json", health)
    assert (tmp_path / "health.json").read_bytes() == before and not list(
        tmp_path.glob(".collector-status-*")
    )


def test_health_report_revalidates_signed_capture_and_clips_short_key_expiry(tmp_path):
    keys, _, pinned, scope, event, proof, _, latest, _ = fixture(tmp_path)
    now = datetime.now(UTC)
    event = event.model_copy(update={"observed_at": now})
    proof = runtime_proof(
        event,
        proof.observation,
        keys["runtime"],
        source_id=scope.source_id,
        key_id=scope.key_id,
        observed_at=now,
    )
    from tests.test_collector_freshness import resign

    proof = resign(
        proof.model_copy(update={"expires_at": now + timedelta(seconds=3)}), keys["runtime"]
    )
    atomic_capture(latest, canonical(envelope(event, proof)))
    monitor = CollectorMonitor(scope, pinned, tmp_path / "ledger.sqlite3")
    result = monitor.check(latest)
    projected = bridge.health_report(scope, result, latest, pinned)
    assert bridge.timestamp(projected["expires_at"]) == proof.expires_at
    latest.write_bytes(b"bad")
    with pytest.raises(ValueError):
        bridge.health_report(scope, result, latest, pinned)


@pytest.mark.parametrize("mode", ["extra", "relative", "same", "bad_scope"])
def test_profile_validation_is_fixed_and_local(tmp_path, mode):
    *_, profile = setup(tmp_path)
    if mode == "extra":
        profile["arbitrary_url"] = "https://example.invalid"
    elif mode == "relative":
        profile["health_file"] = "relative.json"
    elif mode == "same":
        profile["archive_file"] = profile["health_file"]
    else:
        profile["scope_sha256"] = "bad"
    path = tmp_path / "profile.json"
    path.write_bytes(canonical(profile))
    with pytest.raises(ValueError):
        bridge.load_profile(path)


@pytest.mark.parametrize("state", ["storage_pressure", "unavailable"])
def test_archive_failure_never_reuses_previous_good_counts(tmp_path, state):
    scope, now, _, _, profile = setup(tmp_path)
    bridge.publish(profile["archive_file"], bridge.report("archive", scope, state, checked_at=now))
    text = bridge.metrics(profile, now=now)
    assert "secops_collector_archive_records " not in text
    assert f"secops_collector_archive_storage_pressure {int(state == 'storage_pressure')}" in text
    assert (
        f'secops_collector_status_success{{worker="archive"}} {int(state != "unavailable")}' in text
    )


def test_opt_in_existing_exporter_keeps_inbox_metrics_and_scrape_authentication(tmp_path):
    from urllib.error import HTTPError
    from urllib.request import ProxyHandler, Request, build_opener

    from scripts import signal_metrics_exporter as exporter
    from tests.test_signal_metrics_exporter import serve

    *_, profile = setup(tmp_path)
    token = "t" * 32

    class InboxFailureHandler(
        exporter.handler(
            "http://127.0.0.1:1/zero-trust/signals/inbox",
            "secret",
            token,
            collector_profile=profile,
        )
    ):
        pass

    with serve(InboxFailureHandler) as base:
        opener = build_opener(ProxyHandler({}))
        with pytest.raises(HTTPError) as denied:
            opener.open(base + "/metrics", timeout=3)
        assert denied.value.code == 401
        with opener.open(
            Request(base + "/metrics", headers={"Authorization": "Bearer " + token}), timeout=3
        ) as response:
            raw = response.read().decode()
        assert "secops_signal_collection_success 0" in raw
        assert "secops_collector_observation_fresh 1" in raw
        assert "secret" not in raw and token not in raw
