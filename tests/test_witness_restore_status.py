"""Restore monitoring never acquires keys or refreshes old restore timestamps."""

import copy
import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import pytest
from test_signal_metrics_exporter import serve
from test_witness_observer_restore_inspection import prepared

from app.services import audit_witness_observer_backup as backup
from app.services.audit_transfer import AuditTransferError
from scripts import signal_metrics_exporter as exporter
from scripts.f1_lab import witness_restore_status as status
from scripts.local_process_runtime import direct_python


def fixture(tmp_path):
    _, _, _, pin, minimum, package, saved, restored = prepared(tmp_path)
    profile = {"schema": status.PROFILE_SCHEMA, "profile_sha256": pin,
               "minimum_receipt": minimum["receipt_sha256"], "backup_sha256": saved["backup_sha256"],
               "restore_receipt_sha256": restored["restore_receipt_sha256"],
               "status_file": str(tmp_path / "status.json"), "max_backup_age_seconds": 60,
               "max_restore_age_seconds": 60}
    value = status.inspect(package, tmp_path / "restored", profile)
    return profile, value, package


def test_report_is_pinned_aggregate_only_and_not_live_health(tmp_path):
    profile, value, _ = fixture(tmp_path)
    text = status.render_report(profile, value)
    assert "restore_status_success 1" in text and "restore_recent 1" in text
    assert "restore_snapshot_anchor_count 1" in text
    assert "observation_healthy" not in text and "authorization" not in text
    for secret in (*[profile[k] for k in status.PINS], str(tmp_path)):
        assert secret not in text
    assert all(value[k] is False for k in status.FALSE_FLAGS)


def test_repeated_integrity_check_does_not_make_old_backup_or_restore_recent(tmp_path):
    profile, value, package = fixture(tmp_path)
    later = datetime.now(UTC) + timedelta(seconds=61)
    proof = backup.inspect_restore(package, tmp_path / "restored", profile["backup_sha256"],
                                   profile["restore_receipt_sha256"], profile["profile_sha256"],
                                   profile["minimum_receipt"])
    newer_report = status.report(profile, proof, now=later)
    text = status.render_report(profile, newer_report, now=later)
    assert "restore_status_success 1" in text and "restore_recent 0" in text
    assert newer_report["values"]["restore_started_at"] == value["values"]["restore_started_at"]
    assert newer_report["values"]["backup_created_at"] == value["values"]["backup_created_at"]


@pytest.mark.parametrize("delta", [-1, status.TTL + 1])
def test_future_or_expired_report_drops_old_counts(tmp_path, delta):
    profile, value, _ = fixture(tmp_path)
    now = datetime.fromisoformat(value["checked_at"]) + timedelta(seconds=delta)
    text = status.render_report(profile, value, now=now)
    assert "restore_status_success 0" in text and "anchor_count" not in text


@pytest.mark.parametrize("mutation", [
    lambda v: v.update(backup_sha256="f" * 64),
    lambda v: v.update(profile_sha256="f" * 64),
    lambda v: v.update(minimum_receipt="f" * 64),
    lambda v: v.update(restore_receipt_sha256="f" * 64),
    lambda v: v.update(decryption_checked=True),
    lambda v: v.update(live_source_checked=True),
    lambda v: v.update(independent_storage_verified=True),
    lambda v: v.update(automatic_activation_allowed=True),
    lambda v: v.update(raw_identity="private"),
    lambda v: v["values"].update(pending=1),
    lambda v: v["values"].update(current_anchor_count=False),
    lambda v: v["values"].update(snapshot_anchor_count=2),
    lambda v: v["values"].update(backup_created_at="2099-01-01T00:00:00+00:00"),
    lambda v: v["values"].update(extra="raw command"),
])
def test_invalid_snapshot_cannot_export_old_counts_or_freshness(tmp_path, mutation):
    profile, value, _ = fixture(tmp_path)
    mutation(value)
    text = status.render_report(profile, value)
    assert "restore_status_success 0" in text and "anchor_count" not in text


def test_real_package_or_receipt_failure_generates_no_verified_values(tmp_path):
    profile, _, package = fixture(tmp_path)
    package.write_bytes(package.read_bytes() + b"changed")
    failed = status.inspect(package, tmp_path / "restored", profile)
    assert failed["values"] == {}
    assert "restore_status_success 0" in status.render_report(profile, failed)


@pytest.mark.skipif(os.name != "posix", reason="POSIX locked durable public cache")
def test_publication_is_bound_to_all_pins_and_rejects_old_or_foreign_status(tmp_path):
    profile, value, _ = fixture(tmp_path)
    path = Path(profile["status_file"])
    status.publish(path, value)
    assert "restore_status_success 1" in status.metrics(profile)
    old = copy.deepcopy(value)
    old["checked_at"] = (datetime.fromisoformat(value["checked_at"]) - timedelta(seconds=1)).isoformat()
    old["values"] = {}
    with pytest.raises(AuditTransferError, match="publication_clock"):
        status.publish(path, old)
    foreign = copy.deepcopy(value)
    foreign["backup_sha256"] = "f" * 64
    with pytest.raises(AuditTransferError, match="binding"):
        status.publish(path, foreign)
    assert "restore_status_success 1" in status.metrics(profile)
    path.write_text("broken", encoding="utf-8")
    assert "restore_status_success 0" in status.metrics(profile)


@pytest.mark.skipif(os.name != "posix", reason="native cached file permission and HTTP contract")
def test_exporter_is_opt_in_authenticated_and_does_not_open_private_package(tmp_path, monkeypatch):
    profile, value, _ = fixture(tmp_path)
    status.publish(profile["status_file"], value)
    monkeypatch.setattr(backup, "inspect_restore", lambda *a, **k: pytest.fail("private file scrape"))
    monkeypatch.setattr(exporter, "metrics", lambda *a, **k: "secops_signal_collection_success 0\n")
    http = build_opener(ProxyHandler({}))
    token = "local-scrape-token"
    with serve(exporter.handler("unused", "secret", token, witness_restore_profile=profile)) as url:
        with pytest.raises(HTTPError) as error:
            http.open(url + "/metrics")
        assert error.value.code == 401
        with http.open(Request(url + "/metrics", headers={"Authorization": "Bearer " + token})) as response:
            body = response.read().decode()
            assert "restore_status_success 1" in body
            assert str(tmp_path) not in body and profile["backup_sha256"] not in body
            assert response.headers["Cache-Control"] == "no-store"
    with serve(exporter.handler("unused", "secret", token)) as url, http.open(
        Request(url + "/metrics", headers={"Authorization": "Bearer " + token})
    ) as response:
        assert "witness_restore" not in response.read().decode()


@pytest.mark.skipif(os.name != "posix", reason="native cached publication")
def test_actual_cli_publishes_failure_and_recovers_without_changing_restore_start(tmp_path):
    profile, original, package = fixture(tmp_path)
    binary, env = direct_python(dict(os.environ, AWS_EC2_METADATA_DISABLED="true"))
    argv = [binary, "-m", "scripts.witness_restore_status", "--package", str(package),
            "--directory", str(tmp_path / "restored"), "--status-file", profile["status_file"]]
    for key in status.PINS:
        argv += ["--" + key.replace("_", "-"), profile[key]]
    good = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30, check=False)
    assert good.returncode == 0, good.stderr
    assert json.loads(good.stdout)["verified"] is True
    raw = package.read_bytes()
    package.unlink()
    failed = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30, check=False)
    assert failed.returncode == 1 and json.loads(failed.stdout)["verified"] is False
    assert "restore_status_success 0" in status.metrics(profile)
    package.write_bytes(raw)
    package.chmod(0o600)
    repaired = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30, check=False)
    assert repaired.returncode == 0, repaired.stderr
    now = json.loads(Path(profile["status_file"]).read_text())
    assert now["values"]["restore_started_at"] == original["values"]["restore_started_at"]
    assert "restore_status_success 1" in status.metrics(profile)


@pytest.mark.skipif(os.name != "posix", reason="native public profile reader")
@pytest.mark.parametrize("bad", ["relative", "bad_age", "bool_age", "bad_pin", "unknown_field"])
def test_metrics_profile_rejects_bad_policy_or_binding(tmp_path, bad):
    profile, _, _ = fixture(tmp_path)
    if bad == "relative":
        profile["status_file"] = "relative.json"
    elif bad == "bad_age":
        profile["max_restore_age_seconds"] = 0
    elif bad == "bool_age":
        profile["max_backup_age_seconds"] = True
    elif bad == "bad_pin":
        profile["backup_sha256"] = "guess"
    else:
        profile["auto_rebase"] = True
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    path.chmod(0o600)
    with pytest.raises(AuditTransferError):
        status.load_profile(path)
