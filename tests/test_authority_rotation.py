"""Authority scope/proof/timer/restart barriers; private test material stays in RAM."""

import base64
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from scripts import authority_custodian as authority
from scripts import authority_rotation_runtime as runtime
from scripts import certificate_authority as bootstrap
from scripts import certificate_controller as leaf
from scripts.authority_rotation_coordinator import Coordinator, DockerBackend, lease
from scripts.mtls_fixtures import leaf as fixture_leaf


@pytest.fixture
def hierarchy():
    root, issuer = bootstrap.hierarchy()
    provider, key = bootstrap.provisioner("collector", "clientAuth")
    server_key = ec.generate_private_key(ec.SECP256R1())
    server = bootstrap.server_renewal_provisioner("gateway", server_key.public_key())
    providers = [provider, server]
    private = {provider["name"]: key, server["name"]: server_key}
    files = authority.seed_files(root, issuer, providers, private, {"gateway": "sign-gateway.key"},
        policy={"periods": dict.fromkeys(["root", "issuer", "jwk"], 3600), "root_days": 2, "issuer_days": 2}, last_at=0)
    state = json.loads(files["state.json"])
    current = authority.unseal(files["authority-g0.sealed"].encode(), files["password"].encode())
    candidate = authority.rotate_bundle(current, state, time.time())
    ca_config = json.loads(bootstrap.ca_files(root, issuer, providers)["ca.json"])
    plan = authority.public_plan(current, candidate, ca_config, None)
    return SimpleNamespace(root=root, issuer=issuer, providers=providers, private=private, files=files,
        state=state, current=current, candidate=candidate, ca_config=ca_config, plan=plan)


def resign(h, plan):
    body = {k: v for k, v in plan.items() if k != "proof"}
    plan["proof"] = base64.b64encode(h.root[0].sign(authority.canonical(body), ec.ECDSA(hashes.SHA256()))).decode()


def verify(h, plan):
    return authority.verify_plan(plan, h.current["root"], epoch=1, previous=None)


def test_sealed_root_issuer_and_jwk_material_is_authenticated_and_not_public(hierarchy):
    h = hierarchy
    blob = h.files["authority-g0.sealed"].encode()
    assert b"PRIVATE KEY" not in blob
    assert authority.unseal(blob, h.files["password"].encode()) == h.current
    assert "PRIVATE KEY" not in json.dumps(h.plan)
    assert verify(h, h.plan) == authority.digest(h.plan)


@pytest.mark.parametrize("attack", ["wrong_password", "changed_ciphertext"])
def test_sealed_authorities_refuse_wrong_password_or_tampering(hierarchy, attack):
    h = hierarchy
    raw = base64.b64decode(h.files["authority-g0.sealed"])
    password = h.files["password"].encode()
    if attack == "wrong_password":
        password = b"unregistered password"
    else:
        raw = raw[:-1] + bytes([raw[-1] ^ 1])
    with pytest.raises(InvalidTag):
        authority.unseal(base64.b64encode(raw), password)


@pytest.mark.parametrize("field", ["root", "issuer", "created_at", "root_public_key_sha256"])
def test_unsigned_rotation_change_is_rejected(hierarchy, field):
    h = hierarchy
    plan = json.loads(json.dumps(h.plan))
    plan[field] = h.current[field] if field in {"root", "issuer"} else "tampered"
    with pytest.raises(leaf.LifecycleError):
        verify(h, plan)


@pytest.mark.parametrize("epoch,previous", [(0, None), (2, None), (1, "f" * 64)])
def test_signed_plan_cannot_skip_or_replay_manifest_sequence(hierarchy, epoch, previous):
    with pytest.raises(leaf.LifecycleError, match="sequence"):
        authority.verify_plan(hierarchy.plan, hierarchy.current["root"], epoch=epoch, previous=previous)


@pytest.mark.parametrize("attack", ["broaden_template", "change_subject", "extend_ca_policy", "foreign_ca_path", "private_jwk", "unchanged_root_key"])
def test_even_authorized_signature_must_preserve_scope_and_key_contract(hierarchy, attack):
    h = hierarchy
    plan = json.loads(json.dumps(h.plan))
    if attack == "broaden_template":
        plan["final_ca"]["authority"]["provisioners"][0]["options"]["x509"]["template"] = "{}"
    elif attack == "change_subject":
        plan["final_ca"]["authority"]["provisioners"][0]["name"] = "operator"
    elif attack == "extend_ca_policy":
        plan["final_ca"]["authority"]["claims"]["allowRenewalAfterExpiry"] = True
    elif attack == "foreign_ca_path":
        plan["final_ca"]["key"] = "/other/unregistered.key"
    elif attack == "private_jwk":
        plan["final_ca"]["authority"]["provisioners"][0]["key"]["d"] = "must never be public"
    else:
        plan["root_public_key_sha256"] = "0" * 64
    resign(h, plan)
    with pytest.raises(leaf.LifecycleError):
        verify(h, plan)


@pytest.mark.parametrize("part", ["root", "issuer", "jwk"])
def test_each_authority_timer_rotates_only_its_required_dependencies(hierarchy, part):
    h = hierarchy
    now = time.time()
    h.state["last_at"] = dict.fromkeys(["root", "issuer", "jwk"], now)
    h.state["last_at"][part] = 0
    new = authority.rotate_bundle(h.current, h.state, now)
    assert (new["root_key"] != h.current["root_key"]) == (part == "root")
    assert (new["issuer_key"] != h.current["issuer_key"]) == (part in {"root", "issuer"})
    assert (new["keys"] != h.current["keys"]) == (part == "jwk")
    if part == "jwk":
        assert all(p["key"] != q["key"] and p["name"] == q["name"] and p["options"] == q["options"]
                   for p, q in zip(new["providers"], h.current["providers"], strict=True))


def test_expiring_root_forces_issuer_rotation_even_before_timer(hierarchy):
    h = hierarchy
    now = time.time()
    h.state["last_at"] = dict.fromkeys(["root", "issuer", "jwk"], now)
    h.state["policy"]["expiry_margin_seconds"] = 3 * 86400
    assert authority.due_parts(h.state, h.current, now) == {"root": True, "issuer": True, "jwk": False}


def test_not_due_rotation_does_not_generate_an_authority_generation(hierarchy):
    h = hierarchy
    h.state["last_at"] = dict.fromkeys(["root", "issuer", "jwk"], time.time())
    assert authority.rotate_bundle(h.current, h.state, time.time()) is None


@pytest.mark.parametrize("period", [0, -1, True, "1", 86400 * 3651])
def test_invalid_authority_timer_policy_is_refused(hierarchy, period):
    h = hierarchy
    h.state["policy"]["periods"]["root"] = period
    with pytest.raises(leaf.LifecycleError, match="periods"):
        authority.rotate_bundle(h.current, h.state, time.time())


class FakeBackend:
    def __init__(self, plan):
        self.plan, self.calls = plan, []
        self.ready, self.paused, self.committed = False, False, False

    def leaf(self, operation, plan=None, **fields):
        self.calls.append(operation)
        if operation == "pause":
            self.paused = fields["value"]
        if operation == "status":
            return {"paused": self.paused}
        if operation == "migration":
            return {"ready": self.ready}
        if operation == "probe_csr":
            return {"csr": "public csr", "provisioner": "collector-clientAuth"}
        return {"ack": True}

    def custodian(self, operation, payload=None):
        self.calls.append(operation)
        if operation == "prepare":
            return {"due": True, "plan": self.plan}
        if operation == "finish":
            self.committed = True
        return {"ack": True}

    def restart_ca(self):
        self.calls.append("restart_ca")


def test_coordinator_waits_for_every_leaf_and_restarts_from_public_journal(hierarchy, tmp_path):
    backend = FakeBackend(hierarchy.plan)
    profile = {"initial_root": hierarchy.current["root"]}
    for _ in range(6):
        c = Coordinator(profile, tmp_path, backend)
        c.tick()
    assert c.state["phase"] == "migrating"
    for _ in range(3):
        c = Coordinator(profile, tmp_path, backend)
        c.tick()
    assert "retire" not in backend.calls and "finish" not in backend.calls
    backend.ready = True
    for _ in range(4):
        c = Coordinator(profile, tmp_path, backend)
        c.tick()
    assert c.state["epoch"] == 1 and c.state["phase"] == "idle"
    assert backend.calls.index("retire") > backend.calls.index("activate")
    assert backend.calls.count("prepare") == 1
    assert "PRIVATE KEY" not in c.path.read_text()


def test_restart_after_authority_commit_does_not_probe_new_key_as_if_retired(hierarchy, tmp_path):
    backend = FakeBackend(hierarchy.plan)
    backend.ready = True
    profile = {"initial_root": hierarchy.current["root"]}
    for _ in range(9):
        c = Coordinator(profile, tmp_path, backend)
        c.tick()
    assert c.state["phase"] == "committing"
    original = backend.custodian
    failed = False
    def interrupt(operation, payload=None):
        nonlocal failed
        result = original(operation, payload)
        if operation == "finish" and not failed:
            failed = True
            raise OSError("simulated response loss after durable commit")
        return result
    backend.custodian = interrupt
    with pytest.raises(OSError):
        c.tick()
    old_probe_calls = backend.calls.count("old-probes")
    recovered = Coordinator(profile, tmp_path, backend)
    recovered.tick()
    assert recovered.state["epoch"] == 1 and backend.committed
    assert backend.calls.count("old-probes") == old_probe_calls


def test_only_one_host_authority_coordinator_can_hold_lease(tmp_path):
    with lease(tmp_path), pytest.raises(OSError), lease(tmp_path):
        pytest.fail("second coordinator acquired lease")


def profile():
    project = "c02-012345abcdef"
    return {"project": project, "image": "sha256:" + "a" * 64,
        "ca": {"name": project + "-ca", "id": "expected"}, "leaf": {"name": project + "-leaf", "id": "expected"},
        "volumes": {name: project + "-" + name for name in ["ca", "vault", "leaf", "renewal"]}}


@pytest.mark.parametrize("attack", ["foreign_project", "foreign_container", "foreign_volume", "mutable_image"])
def test_host_coordinator_refuses_unowned_docker_targets(attack):
    p = profile()
    if attack == "foreign_project":
        p["project"] = "another-project"
    elif attack == "foreign_container":
        p["ca"]["name"] = "unrelated-work"
    elif attack == "foreign_volume":
        p["volumes"]["vault"] = "user-vault"
    else:
        p["image"] = "python:latest"
    with pytest.raises(leaf.LifecycleError, match="scope"):
        DockerBackend(p)


@pytest.mark.parametrize("attack", ["replaced_id", "changed_image", "online_root_vault", "socket"])
def test_online_identity_or_root_boundary_change_stops_ca_operations(attack, monkeypatch):
    p = profile()
    record = {"Id": "expected", "Name": "/" + p["ca"]["name"], "Image": p["image"], "Mounts": []}
    if attack == "replaced_id":
        record["Id"] = "other"
    elif attack == "changed_image":
        record["Image"] = "other"
    else:
        record["Mounts"] = [{"Destination": "/vault" if attack == "online_root_vault" else "/var/run/docker.sock"}]
    b = DockerBackend(p)
    monkeypatch.setattr(b, "command", lambda *a, **kw: json.dumps([record]))
    with pytest.raises(leaf.LifecycleError):
        b.owned("ca")


def test_root_custodian_command_has_no_network_socket_or_secret_arguments(monkeypatch):
    b = DockerBackend(profile())
    observed = []
    monkeypatch.setattr(b, "command", lambda args, payload=None: observed.append(args) or "{}")
    b.custodian("prepare")
    command = observed[0]
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--user") + 1] == "10001:10001"
    assert "--read-only" in command and "--cap-drop=ALL" in command
    assert not any("docker.sock" in value or "PRIVATE KEY" in value or value.startswith("eyJ") for value in command)


@pytest.fixture
def public_runtime(hierarchy, tmp_path, monkeypatch):
    h = hierarchy
    trust = tmp_path / "service"
    trust.mkdir()
    leaf.atomic(tmp_path / "root.pem", h.current["root"])
    leaf.atomic(trust / "ca.pem", h.current["root"] + h.current["issuer"])
    certificate = fixture_leaf(h.issuer, "collector")["cert"]
    cfg = {"roots": [str(trust)], "disabled": [], "paused": True}
    state = {"credentials": {"id": leaf.metadata(certificate) | {"current": certificate}}, "transaction": None, "paused_ack": True}
    leaf.save(tmp_path / "state.json", state)
    monkeypatch.setattr(runtime, "DIRECTORY", tmp_path)
    monkeypatch.setattr(leaf, "config", lambda *args: cfg)
    return SimpleNamespace(h=h, directory=tmp_path, trust=trust, cfg=cfg, state=state)


def test_partial_root_trust_publication_replays_ledger_without_adding_unregistered_roots(public_runtime, monkeypatch):
    r = public_runtime
    actual = leaf.atomic
    def interrupt(path, body):
        if Path(path) == r.trust / "ca.pem":
            raise OSError("interrupted after first trust store")
        actual(path, body)
    monkeypatch.setattr(leaf, "atomic", interrupt)
    with pytest.raises(OSError):
        runtime.dispatch({"operation": "stage", "plan": r.h.plan})
    monkeypatch.setattr(leaf, "atomic", actual)
    result = runtime.dispatch({"operation": "stage", "plan": r.h.plan})
    assert result["trust_stores"] == 2
    assert r.h.plan["root"] in (r.trust / "ca.pem").read_text()


def test_root_retirement_is_refused_until_all_registered_leafs_have_migrated(public_runtime):
    r = public_runtime
    runtime.dispatch({"operation": "stage", "plan": r.h.plan})
    before = (r.trust / "ca.pem").read_text()
    with pytest.raises(leaf.LifecycleError, match="migration_incomplete"):
        runtime.dispatch({"operation": "retire", "plan": r.h.plan})
    assert (r.trust / "ca.pem").read_text() == before


def test_operator_trust_change_during_rotation_is_not_overwritten(public_runtime):
    r = public_runtime
    runtime.dispatch({"operation": "stage", "plan": r.h.plan})
    (r.trust / "ca.pem").write_text("operator stopped this trust store")
    with pytest.raises(leaf.LifecycleError, match="conflict"):
        runtime.dispatch({"operation": "stage", "plan": r.h.plan})
    assert (r.trust / "ca.pem").read_text() == "operator stopped this trust store"


@pytest.mark.parametrize("attack", ["root_key", "issuer_key", "jwk_key", "generation", "root_certificate"])
def test_private_successor_bundle_must_match_the_verified_public_plan(hierarchy, attack):
    h = hierarchy
    candidate = json.loads(json.dumps(h.candidate))
    authority.verify_private_bundle(h.plan, candidate)
    if attack in {"root_key", "issuer_key"}:
        candidate[attack] = h.current[attack]
    elif attack == "jwk_key":
        name = next(iter(candidate["keys"]))
        candidate["keys"][name] = h.current["keys"][name]
    elif attack == "generation":
        candidate["generation"] = 0
    else:
        candidate["root"] = h.current["root"]
    with pytest.raises(leaf.LifecycleError):
        authority.verify_private_bundle(h.plan, candidate)


def test_signed_manifest_cannot_overwrite_the_live_ca_key_path(hierarchy):
    h = hierarchy
    plan = json.loads(json.dumps(h.plan))
    plan["final_ca"]["key"] = plan["before_ca"]["key"]
    resign(h, plan)
    with pytest.raises(leaf.LifecycleError, match="generation_path"):
        verify(h, plan)


def test_idle_scheduler_does_not_pause_issuance_before_next_policy_check(hierarchy, tmp_path):
    b = FakeBackend(hierarchy.plan)
    c = Coordinator({"initial_root": hierarchy.current["root"]}, tmp_path, b)
    c.state["next_due_at"] = time.time() + 300
    c.tick()
    assert b.calls == []


def test_not_due_policy_check_does_not_decrypt_or_even_open_root_bundle(hierarchy, tmp_path):
    h = hierarchy
    state = h.state | {"last_at": dict.fromkeys(["root", "issuer", "jwk"], time.time())}
    leaf.save(tmp_path / "state.json", state)
    result = authority.prepare(tmp_path, tmp_path / "unused-ca", tmp_path / "unused-renewal")
    assert result["due"] is False and result["next_due_at"] > time.time()


@pytest.mark.parametrize("expired", ["root", "issuer"])
def test_expired_authority_requires_explicit_recovery_not_automatic_reenrollment(hierarchy, expired):
    h = hierarchy
    key = h.root[0] if expired == "root" else h.issuer[0]
    certificate = authority.ca_certificate(key, "expired", None if expired == "root" else h.root, days=0,
                                           depth=1 if expired == "root" else 0)
    h.current[expired] = authority.pem_cert(certificate)
    with pytest.raises(leaf.LifecycleError, match="expired_authority"):
        authority.rotate_bundle(h.current, h.state, time.time())


def test_authority_period_updates_work_with_existing_tls_policy_attribute(monkeypatch):
    from scripts import test_authority_key_rotation as driver
    lab = driver.AuthorityLab.__new__(driver.AuthorityLab)
    lab.policy = {"peers": {}}  # Inherited TLSLab uses this instance attribute.
    lab.vault, lab.image = "owned-vault", "owned-image"
    seen = []
    monkeypatch.setattr(driver, "command", lambda args, **kwargs: seen.append((args, kwargs)))
    lab.update_authority_periods({"root": 3600, "issuer": 1, "jwk": 1})
    assert len(seen) == 1 and json.loads(seen[0][1]["input"])["issuer"] == 1
