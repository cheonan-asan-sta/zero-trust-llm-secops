import copy
import http.client
import json
import os
import stat
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from scripts.f1_lab import backup_recovery_status as module
from scripts.f1_lab.operation_context import canonical
from tests.test_capture_backup import restore, setup

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="private POSIX backup/review contracts"
)


@pytest.fixture
def evidence(tmp_path):
    data = setup(tmp_path)
    receipt, review = restore(data)
    # Establish the cooperative review lock once before read-only service use.
    data[3].verify(review, receipt["receipt_sha256"], data[5], data[6]["checkpoint_sha256"])
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    args = {
        "scope": data[2].scope,
        "package": data[8],
        "manifest_sha256": data[9]["manifest_sha256"],
        "checkpoint": data[5],
        "checkpoint_sha256": data[6]["checkpoint_sha256"],
        "review": review,
        "receipt_sha256": receipt["receipt_sha256"],
    }
    profile = {
        "schema": "zt-backup-recovery-metrics-profile-1",
        "scope_sha256": module.scope_hash(args["scope"]),
        "status_file": str(public / "status.json"),
        "max_snapshot_age_seconds": 60,
        "max_restore_age_seconds": 60,
    }
    return args, profile, data[7], public


def check(evidence, **changes):
    args, profile, _, _ = evidence
    value = module.inspect(**{**args, **changes})
    module.publish(profile["status_file"], value)
    return value


def test_pinned_package_and_restored_database_bind_without_key_or_mutation(evidence):
    args, profile, key, _ = evidence
    paths = [
        args["package"] / "payload.aesgcm",
        args["package"] / "manifest.json",
        args["checkpoint"],
        args["review"] / "restore.json",
        args["review"] / "review/archive.sqlite3",
    ]
    before = {p: p.read_bytes() for p in paths}
    value = check(evidence)
    assert value["state"] == "verified" and value["values"]["records"] > 0
    assert before == {p: p.read_bytes() for p in paths}
    raw = Path(profile["status_file"]).read_bytes()
    assert stat.S_IMODE(os.stat(profile["status_file"]).st_mode) == 0o644
    assert all(
        s not in raw
        for s in [
            key,
            key.hex().encode(),
            str(args["review"]).encode(),
            args["scope"].tenant_id.encode(),
            b"signature",
            b"manifest_sha256",
            b"receipt_sha256",
        ]
    )
    assert "secops_capture_backup_status_success 1\n" in module.metrics(profile)
    assert "secops_capture_backup_recovery_recent 1\n" in module.metrics(profile)
    assert (
        value["automatic_activation_allowed"]
        is value["authenticity_or_freshness_asserted"]
        is False
    )


def test_rechecking_cannot_renew_snapshot_or_restore_age(evidence):
    first = check(evidence)
    later = module.aware(first["checked_at"]) + timedelta(seconds=61)
    second = check(evidence, now=later)
    assert second["values"] == first["values"]
    text = module.metrics(evidence[1], now=later)
    assert "secops_capture_backup_status_success 1\n" in text
    assert "secops_capture_backup_recovery_recent 0\n" in text


@pytest.mark.parametrize("delta,available", [(-1, 0), (0, 1), (179, 1), (180, 0), (181, 0)])
def test_reporter_clock_and_expiry_do_not_reuse_success_values(evidence, delta, available):
    value = check(evidence)
    text = module.metrics(
        evidence[1], now=module.aware(value["checked_at"]) + timedelta(seconds=delta)
    )
    assert f"secops_capture_backup_status_success {available}\n" in text
    assert ("secops_capture_backup_records " in text) == bool(available)


@pytest.mark.parametrize(
    "failure",
    [
        "manifest_pin",
        "checkpoint_pin",
        "receipt_pin",
        "ciphertext",
        "database",
        "scope",
        "missing_review",
    ],
)
def test_disconnected_or_changed_evidence_is_not_verified(evidence, failure):
    args = evidence[0].copy()
    if failure.endswith("_pin"):
        key = {
            "manifest_pin": "manifest_sha256",
            "checkpoint_pin": "checkpoint_sha256",
            "receipt_pin": "receipt_sha256",
        }[failure]
        args[key] = "0" * 64
    elif failure in {"ciphertext", "database"}:
        path = (
            args["package"] / "payload.aesgcm"
            if failure == "ciphertext"
            else args["review"] / "review/archive.sqlite3"
        )
        raw = bytearray(path.read_bytes())
        raw[-1] ^= 1
        path.write_bytes(raw)
    elif failure == "scope":
        args["scope"] = args["scope"].model_copy(update={"tenant_id": "other-tenant"})
    else:
        args["review"] = args["review"] / "absent"
    with pytest.raises((ValueError, OSError)):
        module.inspect(**args)


@pytest.mark.parametrize(
    "failure",
    [
        "extra",
        "activation",
        "attestation",
        "boolean_count",
        "negative",
        "chronology",
        "state",
        "scope",
        "timezone",
    ],
)
def test_report_validation_rejects_forged_aggregate_contracts(evidence, failure):
    value = check(evidence)
    if failure == "extra":
        value["secret"] = "must-not-leak"
    elif failure == "activation":
        value["automatic_activation_allowed"] = True
    elif failure == "attestation":
        value["authenticity_or_freshness_asserted"] = True
    elif failure == "boolean_count":
        value["values"]["records"] = True
    elif failure == "negative":
        value["values"]["raw_bytes"] = -1
    elif failure == "chronology":
        value["values"]["restored_at"] = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    elif failure == "state":
        value["state"] = []
    elif failure == "scope":
        value["scope_sha256"] = "0" * 64
    else:
        value["checked_at"] = "2026-11-15T00:00:00"
    path = evidence[1]["status_file"]
    with open(path, "wb") as stream:
        stream.write(canonical(value))
    text = module.metrics(evidence[1])
    assert "secops_capture_backup_status_success 0\n" in text
    assert "secops_capture_backup_records " not in text and "must-not-leak" not in text


@pytest.mark.parametrize(
    "name,value",
    [
        ("max_snapshot_age_seconds", True),
        ("max_snapshot_age_seconds", 59),
        ("max_snapshot_age_seconds", 604801),
        ("max_restore_age_seconds", 2592001),
        ("max_restore_age_seconds", 60.0),
        ("status_file", "relative.json"),
        ("status_file", ""),
        ("schema", "unknown"),
        ("scope_sha256", "bad"),
        ("extra", "not-allowed"),
    ],
)
def test_profile_requires_explicit_bounded_policy(evidence, name, value):
    profile = copy.deepcopy(evidence[1])
    profile[name] = value
    path = evidence[3] / "profile.json"
    path.write_bytes(canonical(profile))
    with pytest.raises(ValueError):
        module.load_profile(path)


def test_profile_and_publication_refuse_links_and_clock_rollback(evidence):
    first = check(evidence)
    profile = evidence[1]
    path = evidence[3] / "profile.json"
    path.write_bytes(canonical(profile))
    assert module.load_profile(path) == profile
    link = evidence[3] / "linked.json"
    link.symlink_to(profile["status_file"])
    with pytest.raises(ValueError):
        module.publish(link, first)
    earlier = copy.deepcopy(first)
    earlier["checked_at"] = (
        module.aware(first["checked_at"]) - timedelta(microseconds=1)
    ).isoformat()
    # Preserve valid order even if the fixture's restore and check were close.
    earlier["values"] = {}
    earlier["state"] = "unavailable"
    with pytest.raises(ValueError, match="clock_regression"):
        module.publish(profile["status_file"], earlier)
    assert json.loads(Path(profile["status_file"]).read_bytes()) == first


@pytest.mark.parametrize("protected", ["package", "review", "checkpoint"])
def test_public_output_never_overwrites_private_inputs(evidence, protected):
    args = evidence[0]
    path = args[protected] / "status.json" if protected != "checkpoint" else args[protected]
    with pytest.raises(ValueError, match="output_overlap"):
        module.public_destination(path, args["package"], args["review"], args["checkpoint"])


def test_cli_replaces_prior_success_with_safe_unavailable_and_recovers(evidence):
    args, profile, _, _ = evidence
    argv = [
        sys.executable,
        "-m",
        "scripts.capture_backup_status",
        "--tenant",
        args["scope"].tenant_id,
        "--server",
        args["scope"].server_id,
        "--unit",
        args["scope"].unit,
        "--source",
        args["scope"].source_id,
        "--backup",
        str(args["package"]),
        "--manifest-sha256",
        args["manifest_sha256"],
        "--checkpoint",
        str(args["checkpoint"]),
        "--checkpoint-sha256",
        args["checkpoint_sha256"],
        "--review",
        str(args["review"]),
        "--receipt-sha256",
        args["receipt_sha256"],
        "--status-file",
        profile["status_file"],
    ]
    for correct in [True, False, True]:
        command = argv.copy()
        if not correct:
            command[command.index("--manifest-sha256") + 1] = "0" * 64
        result = subprocess.run(command, capture_output=True, timeout=20, check=False)
        assert result.returncode == (0 if correct else 2)
        assert json.loads(result.stdout)["completed"] is correct
        value = module.read_public(profile["status_file"])
        assert value["state"] == ("verified" if correct else "unavailable")
        assert bool(value["values"]) is correct
        assert f"secops_capture_backup_status_success {int(correct)}\n" in module.metrics(profile)


@pytest.mark.parametrize("enabled", [False, True])
def test_exporter_backup_bridge_is_opt_in_and_keeps_scrape_authentication(
    evidence, monkeypatch, enabled
):
    from scripts import signal_metrics_exporter as exporter

    check(evidence)
    monkeypatch.setattr(exporter, "metrics", lambda *_: "secops_signal_collection_success 1\n")
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        exporter.handler(
            "http://127.0.0.1:1/zero-trust/signals/inbox",
            "fixture-upstream",
            "fixture-scrape",
            backup_profile=evidence[1] if enabled else None,
        ),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for authorized in [False, True]:
            connection = http.client.HTTPConnection(*server.server_address, timeout=3)
            try:
                connection.request(
                    "GET",
                    "/metrics",
                    headers={"Authorization": "Bearer fixture-scrape"} if authorized else {},
                )
                response = connection.getresponse()
                raw = response.read()
                assert response.status == (200 if authorized else 401)
                assert (b"secops_capture_backup_bridge_enabled" in raw) == (enabled and authorized)
                assert evidence[0]["scope"].tenant_id.encode() not in raw
            finally:
                connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
