"""CA failover security boundaries and multi-node rotation commit barriers."""

import json
import ssl
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import ca_endpoints as transport
from scripts import certificate_controller as lifecycle
from scripts.authority_rotation_coordinator import Coordinator, DockerBackend
from scripts.test_private_key_rotation import verify_interrupted_rotation
from scripts.test_signal_compose import CheckFailed


def configure(directory, **changes):
    value = {"schema": "ca-endpoints-1", "hosts": ["ca-a", "ca-b"], "connect_timeout_seconds": 1}
    value.update(changes)
    lifecycle.save(directory / "ca-endpoints.json", value)
    return value


@pytest.mark.parametrize("changes", [
    {"schema": "unknown"}, {"hosts": []}, {"hosts": ["ca-a"]}, {"hosts": ["ca-a"] * 2},
    {"hosts": ["ca-a", "http://ca-b"]}, {"hosts": ["ca-a", "evil.example"]},
    {"hosts": ["ca-a", "ca-b:80"]}, {"hosts": ["ca-a", "ca-b/path"]},
    {"hosts": ["ca-a", "ca-b", "ca-c", "ca-d", "ca-e"]}, {"hosts": ["ca-a", None]},
    {"hosts": "ca-a"}, {"connect_timeout_seconds": True}, {"connect_timeout_seconds": .1},
    {"connect_timeout_seconds": 4}, {"insecure_skip_verify": True},
])
def test_unapproved_or_unbounded_endpoint_configuration_fails_closed(tmp_path, changes):
    configure(tmp_path, **changes)
    with pytest.raises(lifecycle.LifecycleError, match="configuration"):
        transport.endpoints(tmp_path)


def test_legacy_profile_keeps_original_single_ca(tmp_path):
    assert transport.endpoints(tmp_path) == (["ca"], 3)


@pytest.fixture
def connections(monkeypatch, tmp_path):
    configure(tmp_path)
    created, sent, faults = [], [], {}
    context = SimpleNamespace(load_cert_chain=lambda *a: None)
    class Connection:
        def __init__(self, host, port, **kwargs):
            assert port == 9000 and kwargs["context"] is context
            self.host, self.closed = host, False
            created.append(self)
        def connect(self):
            if self.host in faults:
                raise faults[self.host]
        def request(self, *args):
            sent.append((self.host, args))
            if "after_send" in faults:
                raise faults["after_send"]
        def getresponse(self):
            return SimpleNamespace(status=403, read=lambda limit: b'{"status":"denied"}')
        def close(self):
            self.closed = True
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", Connection)
    monkeypatch.setattr(lifecycle.ssl, "create_default_context", lambda **kwargs: context)
    return SimpleNamespace(created=created, sent=sent, faults=faults, context=context, directory=tmp_path)


@pytest.mark.parametrize("fault", [ConnectionRefusedError(), TimeoutError(), OSError("DNS unavailable")])
def test_connection_failure_selects_verified_survivor_before_any_token_is_sent(connections, fault):
    c = connections
    c.faults["ca-a"] = fault
    assert lifecycle.ca_post(c.directory, "/1.0/sign", {"ott": "RAM-only fixture"})[0] == 403
    assert [x.host for x in c.created] == ["ca-a", "ca-b"]
    assert [host for host, _ in c.sent] == ["ca-b"]
    assert all(x.closed for x in c.created)


@pytest.mark.parametrize("fault", [ssl.SSLCertVerificationError("wrong root/name/time"), ssl.SSLError("bad TLS")])
def test_tls_authentication_failure_does_not_hide_or_transmit_credential(connections, fault):
    c = connections
    c.faults["ca-a"] = fault
    with pytest.raises(ssl.SSLError):
        lifecycle.ca_post(c.directory, "/1.0/sign", {"ott": "RAM-only fixture"})
    assert [x.host for x in c.created] == ["ca-a"] and not c.sent
    assert c.created[0].closed


@pytest.mark.parametrize("fault", [TimeoutError(), ConnectionResetError()])
def test_ambiguous_sent_write_is_never_replayed_on_another_ca(connections, fault):
    c = connections
    c.faults["after_send"] = fault
    with pytest.raises(OSError):
        lifecycle.ca_post(c.directory, "/1.0/sign", {"ott": "RAM-only fixture"})
    assert [x.host for x in c.created] == ["ca-a"] and len(c.sent) == 1
    assert c.created[0].closed


def test_authorization_denial_does_not_search_for_more_permissive_replica(connections):
    c = connections
    assert lifecycle.ca_post(c.directory, "/1.0/sign", {}) == (403, {"status": "denied"})
    assert len(c.created) == len(c.sent) == 1


def test_no_registered_ca_available_returns_bounded_failure_without_sending_token(connections):
    c = connections
    c.faults.update({h: ConnectionRefusedError() for h in ["ca-a", "ca-b"]})
    with pytest.raises(lifecycle.LifecycleError, match="unavailable"):
        lifecycle.ca_post(c.directory, "/1.0/sign", {})
    assert not c.sent and len(c.created) == 2 and all(x.closed for x in c.created)


def test_direct_node_probe_cannot_escape_approved_hosts(connections):
    c = connections
    with pytest.raises(lifecycle.LifecycleError, match="not_registered"):
        lifecycle.ca_post(c.directory, "/1.0/sign", {}, endpoint="unrelated-service")
    assert not c.created


def test_direct_node_probe_cannot_fall_back_and_misattribute_a_denial(connections):
    c = connections
    c.faults["ca-b"] = ConnectionRefusedError()
    with pytest.raises(lifecycle.LifecycleError, match="unavailable"):
        lifecycle.ca_post(c.directory, "/1.0/sign", {}, endpoint="ca-b")
    assert [x.host for x in c.created] == ["ca-b"] and not c.sent


def test_ha_same_key_renewal_uses_mtls_through_common_transport(monkeypatch, tmp_path):
    configure(tmp_path)
    identity = {"purpose": "clientAuth", "key": "/private/key", "certificates": ["/private/cert"]}
    observed = []
    monkeypatch.setattr(lifecycle, "ca_post", lambda *args, **kw: observed.append((args, kw)) or (201, {"certChain": ["public-chain"]}))
    monkeypatch.setattr(lifecycle.subprocess, "run", lambda *a, **kw: pytest.fail("single-node CLI bypass"))
    assert lifecycle.renewal(identity, tmp_path) == "public-chain"
    assert observed[0][0][1:] == ("/1.0/renew", {}) and observed[0][1] == {"identity": identity}


@pytest.mark.parametrize("target", ["/1.0/renew", "/1.0/rekey"])
def test_renewal_never_falls_back_to_bearer_or_no_client_identity(tmp_path, target):
    with pytest.raises(lifecycle.LifecycleError, match="requires_mtls"):
        lifecycle.ca_post(tmp_path, target, {})


def profile():
    project = "c02-012345abcdef"
    replicas = [{"name": project + "-ca-" + label, "id": character * 64, "endpoint": "ca-" + label}
        for label, character in [("a", "a"), ("b", "b")]]
    return {"initial_root": "public root marker", "project": project, "image": "sha256:" + "c" * 64, "ca": {k: replicas[0][k] for k in ["name", "id"]},
        "ca_replicas": replicas, "leaf": {"name": project + "-leaf", "id": "d" * 64},
        "volumes": {k: project + "-" + k for k in ["vault", "ca", "renewal", "leaf"]}}


@pytest.mark.parametrize("attack", ["foreign_name", "duplicate_id", "duplicate_endpoint", "wrong_primary", "unfixed_id", "missing_replica"])
def test_multi_node_host_operations_require_unique_pinned_owned_replicas(attack):
    p = profile()
    second = p["ca_replicas"][1]
    if attack == "foreign_name":
        second["name"] = "unrelated-work"
    elif attack == "duplicate_id":
        second["id"] = p["ca_replicas"][0]["id"]
    elif attack == "duplicate_endpoint":
        second["endpoint"] = "ca-a"
    elif attack == "wrong_primary":
        p["ca"]["id"] = "f" * 64
    elif attack == "unfixed_id":
        second["id"] = "mutable"
    else:
        p["ca_replicas"].pop()
    with pytest.raises(lifecycle.LifecycleError, match="replica_scope"):
        DockerBackend(p)


@pytest.mark.parametrize("attack", ["writable_config", "foreign_volume", "replaced_secondary", "root_vault"])
def test_any_secondary_boundary_violation_prevents_restart_of_all_nodes(monkeypatch, attack):
    p, commands = profile(), []
    backend = DockerBackend(p)
    def command(args, *a):
        commands.append(args)
        if args[0] == "inspect":
            r = next(r for r in p["ca_replicas"] if r["name"] == args[1])
            record = {"Name": "/" + r["name"], "Id": r["id"], "Image": p["image"],
                "Mounts": [{"Name": p["volumes"]["ca"], "Destination": "/ca", "RW": False}]}
            if r["endpoint"] == "ca-b":
                if attack == "writable_config":
                    record["Mounts"][0]["RW"] = True
                elif attack == "foreign_volume":
                    record["Mounts"][0]["Name"] = "unrelated"
                elif attack == "replaced_secondary":
                    record["Id"] = "replaced"
                else:
                    record["Mounts"].append({"Destination": "/vault"})
            return json.dumps([record])
        pytest.fail("mutated a node before validating the complete replica set")
    monkeypatch.setattr(backend, "command", command)
    with pytest.raises(lifecycle.LifecycleError):
        backend.restart_ca()
    assert len(commands) == 2


def test_restart_waits_for_each_specific_node_and_never_stops_both_together(monkeypatch):
    p, events = profile(), []
    backend = DockerBackend(p)
    monkeypatch.setattr(backend, "owned_container", lambda r: events.append("inspect-" + r["endpoint"]) or r["name"])
    monkeypatch.setattr(backend, "command", lambda args: events.append("restart-" + args[-1].rsplit("-", 1)[-1]))
    monkeypatch.setattr(backend, "leaf", lambda op, **fields: events.append("healthy-" + fields["endpoint"]))
    backend.restart_ca()
    assert events == ["inspect-ca-a", "inspect-ca-b", "restart-a", "healthy-ca-a", "restart-b", "healthy-ca-b"]


def test_unhealthy_secondary_blocks_leaf_activation_and_keeps_phase_resumable(tmp_path):
    p = profile()
    events = []
    class Backend:
        healthy = False
        def leaf(self, operation, plan=None, **fields):
            events.append((operation, fields.get("endpoint")))
            if operation == "probe" and fields["endpoint"] == "ca-b" and not self.healthy:
                raise lifecycle.LifecycleError("new_jwk_issuance_denied")
            return {}
        def custodian(self, operation, payload=None):
            events.append((operation, None))
    backend = Backend()
    c = Coordinator(p, tmp_path, backend)
    c.state.update(phase="ca_activated", plan={}, evidence={})
    c.persist()
    with pytest.raises(lifecycle.LifecycleError):
        c.tick()
    assert c.state["phase"] == "ca_activated" and not any(op == "activate" for op, _ in events)
    backend.healthy = True
    resumed = Coordinator(p, tmp_path, backend)
    resumed.tick()
    assert resumed.state["phase"] == "leaf_activating"
    assert set(resumed.state["evidence"]["new_jwk_issuance"]["replicas"]) == {"ca-a", "ca-b"}
    assert sum(op == "probe" and endpoint is None for op, endpoint in events) == 4


def test_old_jwk_probes_use_fresh_generation_on_every_replica_before_commit(tmp_path):
    p = profile()
    events = []
    class Backend:
        def leaf(self, operation, plan=None, **fields):
            events.append((operation, fields.get("endpoint")))
            return {"denied": 66, "statuses": [401] * 66} if operation == "old_keys_denied" else {}
        def custodian(self, operation, payload=None):
            events.append((operation, None))
    c = Coordinator(p, tmp_path, Backend())
    c.state.update(phase="trust_retired", plan={"changed": {"jwk": True}}, evidence={})
    c.tick()
    assert c.state["phase"] == "committing"
    assert c.state["evidence"]["old_jwks"]["total_denied"] == 132
    old_events = [event for event in events if event[0] in {"old-probes", "old_keys_denied"}]
    assert old_events == [("old-probes", None), ("old_keys_denied", "ca-a"), ("old-probes", None), ("old_keys_denied", "ca-b")]


def test_every_contract_check_is_unique_and_does_not_claim_full_stack_ha():
    root = Path(__file__).resolve().parents[1]
    value = json.loads((root / "infra/mtls/ca-ha-contract.json").read_bytes())
    labels = value["expected_checks"] + value["rotation_checks"]
    assert len(labels) == len(set(labels)) == 25
    assert "single PostgreSQL" in value["scope"]
    assert "No database replication/failover or multi-host HA" in value["limitations"]


def test_empty_bootstrap_file_is_removed_even_when_resumed_publication_fails(tmp_path, monkeypatch):
    lifecycle.save(tmp_path / "bootstrap.json", {})
    def publish(*args):
        raise lifecycle.LifecycleError("publication_interrupted")
    monkeypatch.setattr(lifecycle, "publish", publish)
    with pytest.raises(lifecycle.LifecycleError, match="publication_interrupted"):
        lifecycle.tick({}, {"transaction": {"phase": "activated"}}, tmp_path)
    assert not (tmp_path / "bootstrap.json").exists()


def test_last_consumed_grant_is_unlinked_before_fallible_publication(tmp_path, monkeypatch):
    lifecycle.save(tmp_path / "bootstrap.json", {"id": {"token": "public unit fixture"}})
    (tmp_path / "issuer.pem").write_text("public issuer fixture")
    state = {"transaction": None, "credentials": {"id": {"generation": 0, "candidate": "already persisted public certificate"}}}
    monkeypatch.setattr(lifecycle, "selected", lambda *a: ["id"])
    monkeypatch.setattr(lifecycle, "plan", lambda *a: {})
    def publish(*args):
        raise lifecycle.LifecycleError("publication_interrupted")
    monkeypatch.setattr(lifecycle, "publish", publish)
    with pytest.raises(lifecycle.LifecycleError, match="publication_interrupted"):
        lifecycle.tick({}, state, tmp_path)
    assert not (tmp_path / "bootstrap.json").exists()


def test_partial_interrupted_publication_still_requires_all_active_keys_retained():
    verify_interrupted_rotation({"pending": {"a": {"old_keys_present": True}},
        "active_keys_present": {"a": True, "b": True}}, {"a", "b"})


@pytest.mark.parametrize("attack", ["no_pending", "foreign_pending", "missing_active", "unselected_key_deleted", "selected_key_deleted"])
def test_partial_batch_never_weakens_old_key_retention_or_identity_scope(attack):
    snapshot = {"pending": {"a": {"old_keys_present": True}}, "active_keys_present": {"a": True, "b": True}}
    if attack == "no_pending":
        snapshot["pending"] = {}
    elif attack == "foreign_pending":
        snapshot["pending"]["other"] = {"old_keys_present": True}
    elif attack == "missing_active":
        snapshot["active_keys_present"].pop("b")
    elif attack == "unselected_key_deleted":
        snapshot["active_keys_present"]["b"] = False
    else:
        snapshot["pending"]["a"]["old_keys_present"] = False
    with pytest.raises(CheckFailed, match="rekey_reload_retains_old_keys"):
        verify_interrupted_rotation(snapshot, {"a", "b"})
