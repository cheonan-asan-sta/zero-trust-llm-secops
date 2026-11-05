"""Security boundaries of the persistent local mTLS container runtime."""

import base64
import hashlib
import json
import shlex
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.services.trusted_signals import canonical_signal
from app.zero_trust_models import SignedSessionSignal
from scripts import continuous_mtls_assets as helpers
from scripts import continuous_mtls_runtime as runtime
from scripts import test_continuous_mtls_runtime as runtime_checks
from scripts.continuous_mtls_runtime import compose_spec

PROJECT = "kmtls-012345abcdef"
APP_IMAGE = "secops-runtime:contract-test"
NGINX_IMAGE = "nginx:contract-test"
SERVICES = {"app", "gateway", "bridge", "resource", "proxy", "collector", "worker", "watchdog", "operator"}


def test_runtime_mint_binds_a_separate_source_to_its_operator_key(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    (tmp_path / "tail-private.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    monkeypatch.setattr(helpers, "AUTH", tmp_path)
    monkeypatch.setattr(helpers, "_request", lambda request: request)
    result = helpers.mint({"session_id": "runtime-key-selection", "source_id": "separate-source",
                           "signing_key_file": "tail-private.pem"})
    signal = SignedSessionSignal.model_validate(result["body"])
    assert signal.source_id == "separate-source" and signal.expected_version == 0
    key.public_key().verify(base64.urlsafe_b64decode(signal.signature + "=="), canonical_signal(signal))


@pytest.mark.parametrize("key_file", ["../session-private.pem", "/tmp/session-private.pem", "..-private.pem", True])
def test_runtime_mint_never_reads_a_key_outside_its_operator_volume(key_file):
    with pytest.raises(ValueError, match="filename"):
        helpers.mint({"session_id": "runtime-invalid-key-path", "signing_key_file": key_file})


def test_runtime_writer_retries_the_same_complete_event_after_busy_or_lost_reply():
    sent = []

    def execute(service, argv, payload):
        assert service == "collector" and argv[-1] == "append"
        sent.append(payload)
        if len(sent) < 3:
            # First a busy input lock, then an append committed before its reply
            # was lost. Both retries must retain the original observation time.
            raise runtime.RuntimeFailure("runtime_command_failed_1")
        return '{"appended":true}'

    checks = object.__new__(runtime_checks.Checks)
    checks.runtime = SimpleNamespace(execute=execute,
                                    wait=lambda predicate: runtime.Runtime.wait(predicate, timeout=3))
    checks.append("same-source-event", active=True, other=True)
    assert len(sent) == 3 and len(set(sent)) == 1
    event = json.loads(sent[0])
    assert event["event_id"] == "same-source-event"
    assert event["observed_at"] and event["subject"] == helpers.OTHER


def expiry_campaign(monkeypatch, *, status=403, transition="expiry"):
    initial = {"version": 1, "decision": "ALLOW", "status": "ACTIVE",
               "grant_expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()}
    held = initial | {"version": 2, "decision": "HOLD", "status": "HELD", "reason_codes": ["SIGNAL_PROOF_EXPIRED"]}
    if transition == "revoked":
        held.update(decision="DENY", status="REVOKED", reason_codes=["OPERATOR_REVOKED"])
    elif transition == "wrong_reason":
        held["reason_codes"] = ["OTHER_REASON"]
    elif transition == "version_gap":
        held["version"] = 3
    after = [initial, held] if transition != "none" else [initial]
    if transition == "rewritten_prefix":
        after = [initial | {"grant_expires_at": "changed"}, held]
    values = iter([[initial], after])
    checks = object.__new__(runtime_checks.Checks)
    checks.runtime = SimpleNamespace(probe=lambda request: {
        "status": status, "body": {"reason_code": "SESSION_NOT_AUTHORIZED"}})
    seen = []
    monkeypatch.setattr(checks, "history", lambda name: next(values))
    monkeypatch.setattr(checks, "mint", lambda *a, **kw: seen.append("mint-fresh") or ("fresh-session", "synthetic"))
    monkeypatch.setattr(checks, "access", lambda *a: seen.append("fresh-access"))
    monkeypatch.setattr(checks, "add", lambda *a, **kw: seen.append(kw))
    return checks, seen


def test_expiry_after_pre_request_snapshot_is_verified_before_accepting_denial(monkeypatch):
    checks, seen = expiry_campaign(monkeypatch)
    checks.unrelated_after_outage(("old-session", "synthetic"))
    assert seen[:2] == ["mint-fresh", "fresh-access"]
    assert seen[2]["original_versions"] == 2 and seen[2]["expired_original_denied"]
    assert seen[2]["post_request_expiry_history_verified"]


@pytest.mark.parametrize("transition", ["revoked", "wrong_reason", "version_gap", "rewritten_prefix", "none"])
def test_expiry_race_never_masks_revocation_or_unexplained_history(monkeypatch, transition):
    checks, seen = expiry_campaign(monkeypatch, transition=transition)
    with pytest.raises(runtime.RuntimeFailure):
        checks.unrelated_after_outage(("old-session", "synthetic"))
    assert not seen


def test_expiry_race_never_accepts_successful_old_access(monkeypatch):
    checks, seen = expiry_campaign(monkeypatch, status=200)
    with pytest.raises(runtime.RuntimeFailure, match="expired_control_revived"):
        checks.unrelated_after_outage(("old-session", "synthetic"))
    assert not seen


def mounts(service):
    """Normalize Compose's two volume syntaxes without accepting host paths."""
    result = {}
    for value in service.get("volumes", []):
        if isinstance(value, str):
            source, target, *mode = value.split(":")
            assert not mode or mode == ["ro"] or mode == ["rw"]
            read_only = mode == ["ro"]
        else:
            assert value.get("type", "volume") == "volume"
            source, target = value["source"], value["target"]
            read_only = value.get("read_only", False)
        assert target not in result, "a service must not shadow one of its own mounts"
        result[target] = (source, read_only)
    return result


def networks(service):
    return set(service.get("networks", []))


def command(service):
    value = service.get("entrypoint", []) + service.get("command", [])
    return shlex.split(value) if isinstance(value, str) else value


@pytest.fixture
def spec():
    return compose_spec(PROJECT, APP_IMAGE, NGINX_IMAGE)


def test_runtime_has_a_separate_project_and_the_complete_service_graph(spec):
    assert spec["name"] == PROJECT
    assert set(spec["services"]) == SERVICES
    assert spec.get("networks") and spec.get("volumes")
    assert "default" not in spec["networks"]


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_every_service_has_automatic_restart_and_unprivileged_container_boundaries(spec, name):
    service = spec["services"][name]
    assert service["user"] == "10001:10001"
    assert service["read_only"] is True
    assert service["init"] is True
    assert service["restart"] == "unless-stopped"
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert not service.get("ports") and not service.get("publish_all_ports")
    assert not service.get("privileged") and not service.get("cap_add")
    assert not service.get("devices") and not service.get("volumes_from")
    assert service.get("pid") != "host" and service.get("ipc") != "host"
    assert service.get("network_mode") != "host"
    assert service["image"] == (NGINX_IMAGE if name == "proxy" else APP_IMAGE)


def test_every_network_is_internal_and_every_networked_service_is_explicit(spec):
    for network in spec["networks"].values():
        assert network["internal"] is True
        assert not network.get("external")
    for name, service in spec["services"].items():
        if name in {"worker", "watchdog"}:
            assert service["network_mode"] == "none"
            assert not networks(service)
        else:
            assert networks(service)
            assert networks(service) <= spec["networks"].keys()
            assert "default" not in networks(service)


def test_collector_can_reach_only_intake_not_the_native_core_or_pep(spec):
    services = spec["services"]
    assert networks(services["collector"]) == {"intake"}
    assert networks(services["collector"]) < networks(services["gateway"])
    for name in ("app", "proxy", "resource", "operator"):
        assert not networks(services["collector"]) & networks(services[name])
    assert not networks(services["proxy"]) & networks(services["app"])


def test_no_service_mounts_host_files_or_a_docker_socket(spec):
    declared = set(spec["volumes"])
    for service in spec["services"].values():
        for target, (source, _) in mounts(service).items():
            assert source in declared
            assert not source.startswith(("/", ".", "~"))
            assert "docker.sock" not in source and "docker.sock" not in target
    for name, volume in spec["volumes"].items():
        assert volume["name"] == PROJECT + "-" + name
        assert volume["external"] is True
        assert not (volume or {}).get("driver_opts")


@pytest.mark.parametrize("name", ["worker", "watchdog"])
def test_networkless_maintenance_has_only_the_shared_db_and_public_registry(spec, name):
    services = spec["services"]
    own = mounts(services[name])
    assert own == {"/data": ("data", False), "/signals": ("registry", True)}
    assert own["/data"] == mounts(services["app"])["/data"]
    assert own["/signals"] == mounts(services["app"])["/signals"]
    environment = services[name].get("environment", {})
    assert environment["ZERO_TRUST_DB_PATH"] == "/data/zero-trust.sqlite3"
    assert environment["TRUSTED_SIGNAL_SOURCES_PATH"] == "/signals/sources.json"
    assert environment["APP_ENVIRONMENT"] in {"local", "test"}
    assert environment.get("ANALYZER_MODE", "rule") == "rule"
    assert not any("API_KEY" in key or "PRIVATE" in key or "TLS" in key for key in environment)
    assert "--once" not in command(services[name])


def test_collector_credentials_and_durable_spool_are_exclusive_to_its_container(spec):
    services = spec["services"]
    own = mounts(services["collector"])
    assert own == {
        "/collector": ("collector-state", False),
        "/tls": ("collector-tls", True),
        "/auth": ("collector-auth", True),
    }
    secret_volumes = {source for source, _ in own.values()}
    for name, service in services.items():
        if name != "collector":
            assert not secret_volumes & {source for source, _ in mounts(service).values()}
    assert "--once" not in command(services["collector"])


def test_api_cannot_read_collector_or_pep_private_material(spec):
    assert mounts(spec["services"]["app"]) == {
        "/data": ("data", False),
        "/signals": ("registry", True),
        "/tls": ("core-tls", True),
        "/auth": ("core-auth", True),
    }
    app_environment = spec["services"]["app"].get("environment", {})
    assert app_environment["ZERO_TRUST_DB_PATH"] == "/data/zero-trust.sqlite3"
    assert app_environment["TRUSTED_SIGNAL_SOURCES_PATH"] == "/signals/sources.json"


def test_generated_compose_contains_no_raw_credentials_or_unsafe_fallback(spec):
    serialized = json.dumps(spec, sort_keys=True)
    assert "PRIVATE KEY" not in serialized
    assert "http://" not in serialized
    assert "SIGNAL_COLLECTOR_API_KEY" not in serialized
    assert "API_KEY_SHA256" not in serialized
    assert "host.docker.internal" not in serialized
    assert "network_mode: host" not in serialized


def test_explicit_labels_scope_every_service_and_network_to_the_generated_project(spec):
    for value in [*spec["services"].values(), *spec["networks"].values()]:
        assert value["labels"]["secops.runtime"] == PROJECT


def test_network_hops_launch_tls_servers_and_authenticated_upstreams(spec):
    services = spec["services"]
    gateway = command(services["gateway"])
    assert gateway[gateway.index("--profile") + 1] == "/tls/profile.json"
    assert gateway[gateway.index("--backend-profile") + 1] == "/tls/backend.json"
    assert "--secure-stats" in gateway
    bridge = command(services["bridge"])
    for flag in ("--core-tls-profile", "--server-tls-profile", "--consume-server-profile",
                 "--forwarded-profile"):
        assert bridge[bridge.index(flag) + 1].startswith("/tls/")
    resource = command(services["resource"])
    for flag in ("--server-tls-profile", "--consume-tls-profile"):
        assert resource[resource.index(flag) + 1].startswith("/tls/")
    assert "nginx" in command(services["proxy"])
    assert "/config/all-hops.conf" in command(services["proxy"])


@pytest.mark.parametrize("project", ["", "other", "kmtls-0123456789a", "kmtls-0123456789abc",
                                      "kmtls-0123456789AB", "kmtls-0123456789ab\n", "../kmtls-0123456789ab"])
def test_compose_rejects_project_names_outside_its_resource_scope(project):
    with pytest.raises(ValueError):
        compose_spec(project, APP_IMAGE, NGINX_IMAGE)


@pytest.mark.parametrize("path", ["other", "runtime", "runtime/c020/project", "runtime/c02/../../outside"])
def test_runtime_directory_cannot_escape_the_local_runtime_root(tmp_path, monkeypatch, path):
    monkeypatch.setattr(runtime, "ROOT", tmp_path)
    with pytest.raises(ValueError):
        runtime.Runtime(tmp_path / path)


def test_runtime_directory_scope_resolves_symlinks(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "ROOT", tmp_path)
    allowed = tmp_path / "runtime/c02"
    allowed.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (allowed / "escape").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is not supported by this host")
    with pytest.raises(ValueError):
        runtime.Runtime(allowed / "escape" / "project")


@pytest.fixture
def descriptor_runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "ROOT", tmp_path)
    directory = tmp_path / "runtime/c02/test-runtime"
    directory.mkdir(parents=True)
    instance = runtime.Runtime(directory)
    state = {"schema": "continuous-mtls-runtime-1", "project": PROJECT,
             "image": PROJECT + "-app", "volumes": {n: PROJECT + "-" + n for n in runtime.VOLUMES},
             "initialized": True}
    instance.descriptor.write_text(json.dumps(state), encoding="utf-8")
    return instance, state


@pytest.mark.parametrize("changed", ["schema", "project", "image", "volume"])
def test_descriptor_cannot_redirect_commands_to_another_project(descriptor_runtime, monkeypatch, changed):
    instance, state = descriptor_runtime
    if changed == "volume":
        state["volumes"]["data"] = "another-project-data"
    else:
        state[changed] = "another-project"
    instance.descriptor.write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(instance, "write_manifest", lambda: pytest.fail("invalid descriptor was used"))
    with pytest.raises(ValueError):
        instance.load()


def test_loading_validated_descriptor_rebuilds_public_manifest(descriptor_runtime, monkeypatch):
    instance, state = descriptor_runtime
    instance.manifest.write_text("untrusted previous compose content", encoding="utf-8")
    seen = []
    monkeypatch.setattr(instance, "write_manifest", lambda: seen.append(instance.state.copy()))
    assert instance.load() == state
    assert seen == [state]


def test_container_lookup_rejects_replaced_service_labels(descriptor_runtime, monkeypatch):
    instance, state = descriptor_runtime
    instance.state = state
    monkeypatch.setattr(instance, "compose", lambda *args: "a" * 64)
    monkeypatch.setattr(runtime, "command", lambda *args, **kwargs: json.dumps([
        {"Config": {"Labels": {"secops.runtime": "different-project",
                               "com.docker.compose.service": "collector"}}},
    ]))
    with pytest.raises(runtime.RuntimeFailure, match="runtime_container_replaced"):
        instance.container("collector")
    with pytest.raises(ValueError):
        instance.container("not-a-service")


def _require(condition, reason):
    # Do not let assertion rewriting dump an ephemeral credential on test failure.
    if not condition:
        raise AssertionError(reason)


class SecretBundle(dict):
    def __repr__(self):
        return "<ephemeral runtime assets; private contents withheld>"


@pytest.fixture(scope="module")
def material():
    return SecretBundle(helpers.assets())


def _fingerprint(certificate):
    der = x509.load_pem_x509_certificate(certificate.encode()).public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def test_collector_tls_identity_and_operator_signing_key_are_separated(material):
    private_files = {volume: {name for name, body in files.items() if "PRIVATE KEY" in body}
                     for volume, files in material.items()}
    assert private_files["collector-tls"] == {"collector.key"}
    assert private_files["operator-auth"] == {"session-private.pem"}
    assert private_files["registry"] == private_files["core-auth"] == set()
    assert "collector-state" not in material
    assert all("ca.key" not in names for names in private_files.values())
    key = serialization.load_pem_private_key(
        material["operator-auth"]["session-private.pem"].encode(), password=None,
    )
    registry = json.loads(material["registry"]["sources.json"])
    registered = serialization.load_pem_public_key(
        registry["sources"][0]["keys"][0]["public_key_pem"].encode(),
    )
    _require(key.public_key().public_bytes_raw() == registered.public_bytes_raw(),
             "operator signer does not match its public registration")
    _require(hashlib.sha256(material["collector-auth"]["api-key.txt"].encode()).hexdigest()
             == material["core-auth"]["api-key.sha256"], "API credential registration mismatch")


def test_mtls_roles_preserve_collector_and_native_core_boundaries(material):
    gateway = json.loads(material["gateway-tls"]["profile.json"])
    collector_pin = _fingerprint(material["collector-tls"]["collector.pem"])
    bridge_pin = _fingerprint(material["bridge-tls"]["pep-bridge.pem"])
    assert gateway["peers"] == {collector_pin: "collector", bridge_pin: "pep-bridge"}
    core = json.loads(material["core-tls"]["server.json"])
    gateway_pin = _fingerprint(material["gateway-tls"]["gateway-client.pem"])
    operator_pin = _fingerprint(material["operator-tls"]["core-operator.pem"])
    assert core["peers"] == {gateway_pin: "api-gateway", operator_pin: "core-operator"}


def test_client_profiles_authenticate_each_expected_peer_and_use_existing_tls_pep(material):
    for volume, filename, target_volume, certificate, host, port, server_name in [
        ("collector-tls", "profile.json", "gateway-tls", "gateway.pem", "gateway", 8443, "gateway"),
        ("gateway-tls", "backend.json", "core-tls", "core-a.pem", "core", 8000, "core-a"),
        ("bridge-tls", "core.json", "gateway-tls", "gateway.pem", "gateway", 8443, "gateway"),
        ("resource-tls", "consume.json", "bridge-tls", "bridge-consume.pem", "bridge", 8082, "bridge-consume"),
    ]:
        profile = json.loads(material[volume][filename])
        assert (profile["host"], profile["port"], profile["server_name"]) == (host, port, server_name)
        assert profile["server_pins"] == [_fingerprint(material[target_volume][certificate])]
        assert profile["cert"] in material[volume] and profile["key"] in material[volume]
    nginx = material["config"]["all-hops.conf"]
    assert "ssl_verify_client on;" in nginx and "proxy_ssl_verify on;" in nginx
    assert "proxy_pass https://resource:8083;" in nginx
    assert "proxy_pass https://bridge:8081;" in nginx
    assert "proxy_pass http://" not in nginx


class ExecCaptured(BaseException):
    pass


@pytest.mark.parametrize("role", ["app", "collector"])
def test_service_wrapper_executes_tls_daemon_and_keeps_credentials_out_of_argv(monkeypatch, role):
    monkeypatch.setattr(helpers, "_credential", lambda *args, **kwargs: "c" * 64)
    captured = []

    def capture(executable, argv):
        captured.append((executable, argv))
        raise ExecCaptured

    monkeypatch.setattr(helpers, "os", SimpleNamespace(
        environ={"APP_ENVIRONMENT": "test", "ANALYZER_MODE": "openai"}, execv=capture,
    ))
    with pytest.raises(ExecCaptured):
        helpers.service(role)
    argv = captured[0][1]
    assert "c" * 64 not in argv
    assert helpers.os.environ["ANALYZER_MODE"] == "rule"
    if role == "collector":
        assert "scripts.continuous_signal_collector" in argv and "run" in argv
        assert argv[argv.index("--directory") + 1] == str(Path("/collector/producer"))
        assert argv[argv.index("--base-url") + 1] == "https://gateway:8443"
        assert argv[argv.index("--tls-profile") + 1] == str(Path("/tls/profile.json"))
        assert helpers.os.environ["SIGNAL_COLLECTOR_API_KEY"] == "c" * 64
        assert "--once" not in argv
    else:
        assert "scripts.mtls_native" in argv and "api" in argv
        assert argv[argv.index("--profile") + 1] == str(Path("/tls/server.json"))
        assert helpers.os.environ["AUTH_MODE"] == "api_key"


def test_service_wrapper_refuses_production_before_loading_credentials(monkeypatch):
    monkeypatch.setenv("APP_ENVIRONMENT", "production")
    monkeypatch.setattr(helpers, "_credential", lambda *args, **kwargs: pytest.fail("credential read"))
    monkeypatch.setattr(helpers.os, "execv", lambda *args: pytest.fail("process exec"))
    with pytest.raises(ValueError):
        helpers.service("collector")


def test_probe_uses_only_allowlisted_tls_profile_and_replaces_caller_api_key(monkeypatch):
    seen = []
    monkeypatch.setattr(helpers, "_credential", lambda *args: "trusted-test-key")

    def request(profile, target, payload, headers, *, method, observed):
        seen.append(SimpleNamespace(profile=profile, target=target, headers=headers, method=method))
        observed["tls_version"] = "TLSv1.3"
        return 200, b'{"ok":true}'

    monkeypatch.setattr(helpers.tls, "request", request)
    result = helpers._request({"profile": "core", "path": "/health/live", "method": "GET",
                               "headers": {"x-api-key": "attacker", "X-Other": "allowed"}})
    assert result["status"] == 200 and result["tls_version"] == "TLSv1.3"
    assert seen[0].profile == Path("/tls/core.json")
    assert seen[0].headers == {"X-Other": "allowed", "X-API-Key": "trusted-test-key"}
    with pytest.raises(ValueError):
        helpers._request({"profile": "../../collector"})
    assert len(seen) == 1
