import copy
import hashlib
import json
from datetime import UTC, datetime

import pytest
import yaml

from scripts import continuous_mtls_assets as base_assets
from scripts import continuous_mtls_runtime as base
from scripts import monitored_mtls_runtime as runtime
from scripts import monitoring_runtime_assets as assets
from scripts import monitoring_runtime_control as control
from scripts import runtime_release as release
from scripts.test_monitored_mtls_runtime import MonitoredChecks

PROJECT = "kmtls-012345abcdef"


@pytest.fixture
def spec():
    return runtime.definition(PROJECT, "app-image", "nginx-image")


def mounts(service):
    return {item.split(":")[1]: (item.split(":")[0], item.endswith(":ro")) for item in service["volumes"]}


def test_optional_profile_does_not_expand_default_inventory():
    assert len(base.SERVICES) == 9 and len(base.compose_spec(PROJECT, "app", "nginx")["networks"]) == 6
    assert len(runtime.MonitoredRuntime.services) == 14
    assert len(set(runtime.MonitoredRuntime.volumes)) == len(runtime.MonitoredRuntime.volumes)


@pytest.mark.parametrize("name", runtime.EXTRA_SERVICES)
def test_monitored_services_remain_hardened_and_bounded(spec, name):
    service = spec["services"][name]
    assert service["user"] == "10001:10001" and service["read_only"] and service["init"]
    assert service["restart"] == "unless-stopped" and service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"] and service["pids_limit"] == 128
    assert service["mem_limit"] == service["memswap_limit"] and 0 < service["cpus"] <= 1.5
    assert not service.get("ports") and not service.get("privileged")
    assert all(mount.split(":")[0] in spec["volumes"] for mount in service["volumes"])


def test_monitoring_networks_cannot_reach_core_or_intake(spec):
    assert len(spec["networks"]) == 8 and all(value["internal"] for value in spec["networks"].values())
    for name in ("exporter", "prometheus", "alertmanager", "sink"):
        assert not set(spec["services"][name]["networks"]) & {"core", "intake", "auth", "consume", "resource", "client"}
    assert set(spec["services"]["reader"]["networks"]) == {"metrics-read"}
    assert set(spec["services"]["exporter"]["networks"]) == {"metrics-read", "monitoring"}
    for name in ("worker", "watchdog"):
        assert spec["services"][name]["network_mode"] == "none"


@pytest.mark.parametrize("name", ["exporter", "prometheus", "alertmanager", "sink"])
def test_export_pipeline_has_no_security_db_or_responder_credentials(spec, name):
    sources = {item[0] for item in mounts(spec["services"][name]).values()}
    assert not sources & {"data", "registry", "core-auth", "operator-auth", "collector-state", "collector-auth"}
    assert "docker.sock" not in json.dumps(spec["services"][name])


def test_reader_reuses_same_db_but_uses_separate_api_identity(spec):
    reader = spec["services"]["reader"]
    assert mounts(reader)["/data"] == mounts(spec["services"]["app"])["/data"]
    assert mounts(reader)["/auth"] == ("reader-auth", True)
    assert reader["environment"]["TRUSTED_SIGNAL_SOURCES_PATH"] == "/signals/sources.json"
    assert reader["environment"]["ANALYZER_MODE"] == "rule"


def test_separate_tool_storage_is_not_shadowed_by_tmpfs(spec):
    for name in ("prometheus", "alertmanager"):
        service = spec["services"][name]
        assert mounts(service)["/data"] == (name + "-data", False)
        assert not any(row.startswith("/data:") for row in service["tmpfs"])
        assert service["image"] == "sha256:" + "2" * 64
    assert mounts(spec["services"]["operator"])["/monitor-tls"] == ("monitor-operator-tls", True)


@pytest.fixture(scope="module")
def material():
    # Test failures must not display ephemeral keys/tokens via fixture repr.
    class PrivateMaterial(dict):
        def __repr__(self):
            return "<private synthetic monitoring assets>"
    return PrivateMaterial(base_assets.assets(monitoring=True))


def require(value):
    if not value:
        raise AssertionError("monitoring credential boundary mismatch")


def test_monitoring_api_key_is_viewer_specific_and_scrape_notification_tokens_are_distinct(material):
    viewer = material["exporter-auth"]["api-key.txt"]
    scrape = material["exporter-auth"]["scrape.token"]
    notify = material["sink-tls"]["notify.token"]
    require(len({viewer, scrape, notify, material["operator-auth"]["api-key.txt"]}) == 4)
    require(hashlib.sha256(viewer.encode()).hexdigest() == material["reader-auth"]["api-key.sha256"])
    require(scrape == material["prometheus-tls"]["scrape.token"])
    require(notify == material["alertmanager-tls"]["notify.token"])


def test_private_keys_and_tokens_are_not_given_to_reader_or_operator(material):
    require(set(material["reader-auth"]) == {"api-key.sha256"})
    require(not any(name.endswith(".token") or name == "api-key.txt" for name in material["monitor-operator-tls"]))
    for files in material.values():
        require("ca.key" not in files and not any("CA PRIVATE" in value for value in files.values()))
    require(not any("session-private.pem" in files for name, files in material.items() if name != "operator-auth"))


@pytest.mark.parametrize("name", ["prometheus", "alertmanager"])
def test_tool_listener_requires_verified_client_san_and_no_insecure_skip(name):
    config = yaml.safe_load(assets.configurations()[name + "-tls"]["web.yml"])
    tls = config["tls_server_config"]
    assert tls["client_auth_type"] == "RequireAndVerifyClientCert"
    assert tls["min_version"] == "TLS12" and tls["client_allowed_sans"]
    assert config["http_server_config"]["http2"] is False


def test_scrape_and_notification_paths_use_mtls_and_file_bearers_only():
    config = assets.configurations()
    prom = yaml.safe_load(config["prometheus-tls"]["config.yml"])
    am = yaml.safe_load(config["alertmanager-tls"]["config.yml"])
    scrape = prom["scrape_configs"][0]
    assert scrape["scheme"] == "https" and scrape["tls_config"]["insecure_skip_verify"] is False
    assert scrape["authorization"]["credentials_file"] == "/tls/scrape.token"
    assert prom["alerting"]["alertmanagers"][0]["scheme"] == "https"
    hook = am["receivers"][0]["webhook_configs"][0]
    assert hook["url"] == "https://sink:9001/events" and hook["send_resolved"]
    assert hook["http_config"]["authorization"]["credentials_file"] == "/tls/notify.token"
    assert hook["http_config"]["tls_config"]["insecure_skip_verify"] is False
    assert "credentials:" not in json.dumps(config)


@pytest.fixture
def instance(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "ROOT", tmp_path)
    directory = tmp_path / "runtime/c02/monitored"
    directory.mkdir(parents=True)
    obj = runtime.MonitoredRuntime(directory)
    obj.state = {"schema": "continuous-mtls-runtime-1", "project": PROJECT, "image": PROJECT + "-app",
        "image_id": "sha256:" + "a" * 64, "nginx_image_id": "sha256:" + "b" * 64,
        "monitoring_image_id": "sha256:" + "c" * 64, "monitoring_image": PROJECT + "-monitoring",
        "volumes": {name: PROJECT + "-" + name for name in obj.volumes}, "initialized": True}
    obj.save()
    return obj


def test_generated_manifest_pins_optional_tool_image_ids(instance):
    instance.load()
    spec = yaml.safe_load(instance.manifest.read_text())
    assert len(spec["services"]) == 14
    for name, service in spec["services"].items():
        assert service["image"] == instance.expected_image(name)
        assert service["pull_policy"] == "never" and service["platform"] == "linux/amd64"


def test_base_and_monitoring_descriptors_cannot_be_confused(instance):
    with pytest.raises(ValueError, match="descriptor_scope"):
        base.Runtime(instance.directory).load()


def test_cleanup_rejects_foreign_monitoring_image_reference(instance):
    instance.state["monitoring_image"] = "unrelated-user-image"
    instance.save()
    with pytest.raises(ValueError, match="monitoring_image_scope"):
        instance.load()


def test_monitoring_inputs_extend_locked_source_with_tools_and_rules():
    obj = runtime.MonitoredRuntime(base.ROOT / "runtime/c02/unit-inputs")
    saved = obj.release_inputs()
    assert all(name in saved["payload"]["files"] for name in runtime.INPUTS)
    changed = copy.deepcopy(saved)
    changed["payload"]["files"]["infra/observability/alerts.yaml"] = "0" * 64
    changed["sha256"] = release.digest(changed["payload"])
    with pytest.raises(ValueError, match="release_changed"):
        release.verify(changed, saved)


def test_episode_requires_new_event_and_same_binding_fingerprint_and_start(monkeypatch):
    checks = object.__new__(MonitoredChecks)
    original = {"alertname": "C01SignalQueueBacklog", "status": "firing", "job": "zt-signals", "instance": "exporter:9101",
                "fingerprint": "episode-a", "starts_at": "start-a"}
    wrong = original | {"status": "resolved", "fingerprint": "episode-b"}
    matching = original | {"status": "resolved"}
    monkeypatch.setattr(checks, "events", lambda: [original, wrong, matching])
    assert checks.episode(original["alertname"], "firing", 1) is None
    assert checks.episode(original["alertname"], "resolved", 1, original) == matching
    assert checks.episode(original["alertname"], "resolved", 3, original) is None


def test_delayed_old_notification_cannot_satisfy_new_fault_even_after_event_floor(monkeypatch):
    checks = object.__new__(MonitoredChecks)
    checks.episode_starts = {0: datetime(2026, 11, 6, 1, 0, tzinfo=UTC)}
    old = {"alertname": "C01SignalCollectionUnavailable", "status": "firing", "job": "zt-signals",
           "instance": "exporter:9101", "fingerprint": "old", "starts_at": "2026-11-06T00:59:59Z"}
    fresh = old | {"fingerprint": "new", "starts_at": "2026-11-06T01:00:01Z"}
    monkeypatch.setattr(checks, "events", lambda: [old])
    assert checks.episode(old["alertname"], "firing", 0) is None
    monkeypatch.setattr(checks, "events", lambda: [old, fresh])
    assert checks.episode(old["alertname"], "firing", 0) == fresh


@pytest.mark.parametrize("role", ["reader", "exporter"])
def test_service_wrappers_reject_production_without_opening_credentials(monkeypatch, role):
    monkeypatch.setenv("APP_ENVIRONMENT", "production")
    monkeypatch.setattr(control, "_credential", lambda *a, **kw: pytest.fail("must fail before reading credentials"))
    with pytest.raises(ValueError, match="local_test"):
        control.service(role)


def test_reader_process_uses_viewer_role_and_separate_subject(monkeypatch):
    monkeypatch.setenv("APP_ENVIRONMENT", "test")
    for key in ("AUTH_MODE", "API_KEY_SHA256", "API_KEY_SUBJECT", "API_KEY_TENANT_ID", "API_KEY_ROLES", "ANALYZER_MODE"):
        monkeypatch.setenv(key, control.os.environ.get(key, ""))
    monkeypatch.setattr(control, "_credential", lambda *a, **kw: "a" * 64)
    calls = []
    monkeypatch.setattr(control.os, "execv", lambda *a: calls.append(a))
    control.service("reader")
    assert control.os.environ["API_KEY_ROLES"] == "viewer"
    assert control.os.environ["API_KEY_SUBJECT"] == "monitor-reader"
    assert control.os.environ["ANALYZER_MODE"] == "rule"
    assert "scripts.mtls_native" in calls[0][1]


@pytest.mark.parametrize("name", ["../core", "core", "", None])
def test_probe_cannot_escape_monitoring_profile_namespace(name):
    with pytest.raises(ValueError, match="probe_profile"):
        control.probe({"profile": name})


@pytest.mark.parametrize("path", ["bad", "/a\r\nx", "x" * 5000])
def test_probe_rejects_invalid_request_path(path):
    with pytest.raises(ValueError, match="probe_path"):
        control.probe({"profile": "prometheus", "path": path})


def test_monitoring_config_drift_is_not_overwritten_or_started(instance, monkeypatch):
    instance.state["monitoring_binary_sha256"] = {"prometheus": "d" * 64}
    instance.state["monitoring_config_sha256"] = {"prometheus-tls": {"config.yml": "e" * 64}}
    replies = iter([json.dumps([{"Id": instance.state["monitoring_image_id"], "Os": "linux", "Architecture": "amd64"}]),
                    json.dumps(instance.state["monitoring_binary_sha256"]), json.dumps({"config.yml": "0" * 64})])
    calls = []
    monkeypatch.setattr(runtime, "command", lambda *a, **kw: calls.append(a[0]) or next(replies))
    with pytest.raises(base.RuntimeFailure, match="configuration_drift"):
        instance.verify_extra_images()
    assert len(calls) == 3 and "readonly" in " ".join(calls[-1])


def test_modified_monitoring_image_is_not_started(instance, monkeypatch):
    detail = {"Id": "sha256:" + "f" * 64, "Os": "linux", "Architecture": "amd64"}
    monkeypatch.setattr(runtime, "command", lambda *a, **kw: json.dumps([detail]))
    with pytest.raises(ValueError, match="image_identity"):
        instance.verify_extra_images()


def test_legacy_cleanup_manifest_with_app_id_and_no_proxy_pin_remains_available(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "ROOT", tmp_path)
    directory = tmp_path / "runtime/c02/legacy-cleanup"
    directory.mkdir(parents=True)
    obj = base.Runtime(directory)
    obj.state = {"schema": "continuous-mtls-runtime-1", "project": PROJECT, "image": PROJECT + "-app",
        "image_id": "sha256:" + "a" * 64, "volumes": {name: PROJECT + "-" + name for name in obj.volumes},
        "initialized": True}
    obj.save()
    monkeypatch.setattr(base, "command", lambda *a, **kw: pytest.fail("loading cleanup metadata must not start Docker"))
    assert obj.load()["image_id"] == obj.state["image_id"]
    spec = yaml.safe_load(obj.manifest.read_text())
    assert spec["services"]["proxy"]["image"] == "nginx@sha256:" + "0" * 64
    assert spec["services"]["proxy"]["pull_policy"] == "never"


def test_duplicate_tool_names_fail_before_download_or_binary_extraction(instance, tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "ROOT", tmp_path)
    path = tmp_path / "infra/observability/tools.lock.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"platform": "linux/amd64", "tools": [
        {"name": "prometheus"}, {"name": "prometheus"}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="monitoring_tool_inventory"):
        instance.prepare_extra_images()
