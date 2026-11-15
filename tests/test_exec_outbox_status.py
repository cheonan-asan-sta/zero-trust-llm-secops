"""Opt-in health, original pending age, expiration and authenticated scrape."""

import copy
import http.client
import json
import sys
import threading
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer

import pytest

from scripts import signal_metrics_exporter as exporter
from scripts.f1_lab import exec_outbox as inventory
from scripts.f1_lab import exec_outbox_status as module
from scripts.f1_lab.operation_context import canonical
from tests.test_exec_outbox_recovery import pending
from tests.test_managed_exec_retention import fixture as execution_fixture

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="private POSIX outbox contracts")


def setup(tmp_path, *, unpublished=True):
    f = execution_fixture(tmp_path)
    f.execute()
    if unpublished:
        pending(f)
    values = inventory.inspect_outbox(
        f.outbox, f.root, f.archive_scope, f.lab.broker.joiner.registry, f.lab.broker.registry
    )
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    value = module.report(f.archive_scope, values)
    path = public / "outbox.json"
    module.publish(path, value)
    profile = {
        "schema": "zt-exec-outbox-metrics-profile-1",
        "scope_sha256": value["scope_sha256"],
        "status_file": str(path),
        "max_pending_age_seconds": 5,
        "max_records": 10000,
    }
    return f, value, profile, path


def test_actual_published_and_pending_records_export_only_bounded_aggregates(tmp_path):
    f, value, profile, path = setup(tmp_path)
    assert value["state"] == "pending" and value["values"]["pending"] == 1
    assert value["values"]["published"] == 1 and value["values"]["records"] == 2
    now = datetime.fromisoformat(value["checked_at"]) + timedelta(seconds=6)
    text = module.metrics(profile, now=now)
    assert "secops_exec_outbox_status_success 1" in text
    assert "secops_exec_outbox_pending_overdue 1" in text
    assert "secops_exec_outbox_capacity_pressure 0" in text
    assert path.stat().st_mode & 0o777 == 0o644
    raw = path.read_text()
    for secret in [
        f.lab.principal.subject,
        f.scope.tenant_id,
        f.scope.server_id,
        f.scope.unit,
        "grant_token",
        "request_id",
        "private_key",
        str(f.outbox),
    ]:
        assert secret not in raw and secret not in text
    original = path.read_bytes()
    module.metrics(profile, now=now + timedelta(seconds=1))
    assert path.read_bytes() == original


@pytest.mark.parametrize(
    "seconds,valid", [(59.999, True), (60, False), (60.001, False), (-0.001, False)]
)
def test_expiration_has_no_cached_queue_counts(tmp_path, seconds, valid):
    _, value, profile, _ = setup(tmp_path)
    text = module.metrics(
        profile, now=datetime.fromisoformat(value["checked_at"]) + timedelta(seconds=seconds)
    )
    assert f"secops_exec_outbox_status_success {int(valid)}" in text
    assert ("secops_exec_outbox_pending " in text) is valid


@pytest.mark.parametrize(
    "change",
    [
        "scope",
        "schema",
        "extra",
        "negative",
        "boolean",
        "too_many",
        "wrong_sum",
        "future_oldest",
        "no_oldest",
        "permission",
        "authority",
        "state",
        "missing_counter",
    ],
)
def test_malformed_public_status_never_exports_success(tmp_path, change):
    _, value, profile, path = setup(tmp_path)
    bad = copy.deepcopy(value)
    if change == "scope":
        bad["scope_sha256"] = "0" * 64
    elif change == "schema":
        bad["schema"] = "unknown"
    elif change == "extra":
        bad["raw_identity"] = "must not export"
    elif change == "negative":
        bad["values"]["pending"] = -1
    elif change == "boolean":
        bad["values"]["pending"] = True
    elif change == "too_many":
        bad["values"]["records"] = 10001
    elif change == "wrong_sum":
        bad["values"]["published"] = 100
    elif change == "future_oldest":
        bad["oldest_pending_at"] = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    elif change == "no_oldest":
        bad["oldest_pending_at"] = None
    elif change == "permission":
        bad["automatic_execution_allowed"] = True
    elif change == "authority":
        bad["authorization_asserted"] = True
    elif change == "state":
        bad["state"] = "ready"
    else:
        del bad["values"]["raw_bytes"]
    path.write_bytes(canonical(bad))
    text = module.metrics(profile)
    assert "secops_exec_outbox_status_success 0" in text
    assert "secops_exec_outbox_pending " not in text


@pytest.mark.parametrize("fault", ["missing", "link", "mode", "hardlink", "unavailable"])
def test_status_file_failure_is_not_an_empty_healthy_queue(tmp_path, fault):
    f, _, profile, path = setup(tmp_path)
    if fault == "unavailable":
        module.publish(path, module.report(f.archive_scope))
    elif fault == "mode":
        path.chmod(0o666)
    elif fault == "hardlink":
        (path.parent / "other-link").hardlink_to(path)
    else:
        original = path.read_bytes()
        path.unlink()
        if fault == "link":
            target = path.parent / "target"
            target.write_bytes(original)
            path.symlink_to(target)
    text = module.metrics(profile)
    assert "secops_exec_outbox_status_success 0" in text
    assert "secops_exec_outbox_records " not in text


def test_empty_outbox_checks_pins_and_reports_ready_not_permission(tmp_path):
    f = execution_fixture(tmp_path)
    state = inventory.inspect_outbox(
        f.outbox, f.root, f.archive_scope, f.lab.broker.joiner.registry, f.lab.broker.registry
    )
    assert state["records"] == state["pending"] == 0
    value = module.report(f.archive_scope, state)
    assert value["state"] == "ready" and value["automatic_execution_allowed"] is False
    f.lab.broker.registry.path.write_bytes(b"invalid current trust")
    with pytest.raises(ValueError):
        inventory.inspect_outbox(
            f.outbox, f.root, f.archive_scope, f.lab.broker.joiner.registry, f.lab.broker.registry
        )


def test_ready_and_capacity_use_actual_counts(tmp_path):
    _, value, profile, _ = setup(tmp_path, unpublished=False)
    assert value["state"] == "ready"
    assert "secops_exec_outbox_pending_overdue 0" in module.metrics(profile)
    profile["max_records"] = 1
    assert "secops_exec_outbox_capacity_pressure 1" in module.metrics(profile)


def test_profile_is_explicit_bounded_and_publication_cannot_go_backwards(tmp_path):
    f, value, profile, path = setup(tmp_path)
    config = path.parent / "profile.json"
    config.write_bytes(canonical(profile))
    assert module.load_profile(config) == profile
    earlier = module.report(
        f.archive_scope, now=datetime.fromisoformat(value["checked_at"]) - timedelta(seconds=1)
    )
    with pytest.raises(ValueError):
        module.publish(path, earlier)
    assert json.loads(path.read_bytes()) == value
    for key, invalid in [
        ("max_pending_age_seconds", 0),
        ("max_records", True),
        ("max_records", 10001),
        ("status_file", "relative"),
        ("schema", "unknown"),
    ]:
        config.write_bytes(canonical({**profile, key: invalid}))
        with pytest.raises(ValueError):
            module.load_profile(config)


@pytest.mark.parametrize("enabled", [False, True])
def test_existing_exporter_is_opt_in_and_requires_bearer(tmp_path, monkeypatch, enabled):
    _, _, profile, _ = setup(tmp_path)
    monkeypatch.setattr(exporter, "metrics", lambda *_: "secops_signal_collection_success 1\n")
    token = "t" * 32
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        exporter.handler(
            "http://127.0.0.1:1/zero-trust/signals/inbox",
            "fixture",
            token,
            outbox_profile=profile if enabled else None,
        ),
    )
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        client = http.client.HTTPConnection(*server.server_address, timeout=5)
        client.request("GET", "/metrics")
        result = client.getresponse()
        assert result.status == 401
        result.read()
        client.close()
        client = http.client.HTTPConnection(*server.server_address, timeout=5)
        client.request("GET", "/metrics", headers={"Authorization": "Bearer " + token})
        result = client.getresponse()
        body = result.read().decode()
        assert result.status == 200
        assert ("secops_exec_outbox_bridge_enabled" in body) is enabled
        client.close()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
