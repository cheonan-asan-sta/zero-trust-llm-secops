"""Certificate validation and crash/policy boundaries; private test keys stay in RAM.

Real step-ca/CLI, NGINX/Go reloads, timers and expiry are tested separately in Docker.
"""

import hashlib
import json
import ssl
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts import certificate_authority as ca
from scripts import certificate_controller as controller


@pytest.fixture
def pki():
    root, issuer = ca.hierarchy()
    key = ec.generate_private_key(ec.SECP256R1())
    def cert(*, name="collector", purpose=ExtendedKeyUsageOID.CLIENT_AUTH, public_key=None,
             signer=None, expired=False, is_ca=False, sans=None, seconds=300):
        signer = signer or issuer
        now = datetime.now(UTC)
        result = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(signer[1].subject).public_key(public_key or key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(seconds=1))
            .not_valid_after(now - timedelta(seconds=1) if expired else now + timedelta(seconds=seconds))
            .add_extension(x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.SubjectAlternativeName(sans or [x509.DNSName(name)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([purpose]), critical=False)
            .sign(signer[0], hashes.SHA256()))
        return result.public_bytes(serialization.Encoding.PEM).decode()
    return SimpleNamespace(root=root, issuer=issuer, key=key, cert=cert, old=cert(), new=cert(),
        issuer_pem=issuer[1].public_bytes(serialization.Encoding.PEM).decode())


def test_online_ca_has_only_encrypted_intermediate_and_public_provisioner(pki):
    config, _key = ca.provisioner("collector", "clientAuth")
    files = ca.ca_files(pki.root, pki.issuer, [config])
    assert "root.key" not in files and "ENCRYPTED PRIVATE KEY" in files["issuer.key"]
    assert "d" not in config["key"]
    pki.issuer[1].verify_directly_issued_by(pki.root[1])
    assert pki.root[1].extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 1
    assert pki.issuer[1].extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0
    claims = json.loads(files["ca.json"])["authority"]["claims"]
    assert not claims["allowRenewalAfterExpiry"] and not claims["disableRenewal"]


def test_bootstrap_token_is_one_use_subject_audience_and_csr_bound(pki):
    config, key = ca.provisioner("collector", "clientAuth")
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "collector")]))
        .sign(pki.key, hashes.SHA256()))
    pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    token = ca.bootstrap_token(config, key, pem)
    decoded = jwt.decode(token, key.public_key(), algorithms=["ES256"], audience="https://ca:9000/1.0/sign")
    assert decoded["sub"] == "collector" and decoded["sans"] == ["collector"]
    assert decoded["exp"] - decoded["iat"] == 120
    assert decoded["cnf"]["x5rt#S256"] == ca.b64(hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).digest())
    another = jwt.decode(ca.bootstrap_token(config, key, pem), key.public_key(), algorithms=["ES256"], audience=decoded["aud"])
    assert another["jti"] != decoded["jti"]


def test_inventory_publishes_generation_zero_before_any_ca_request(tmp_path, pki, monkeypatch):
    certificate = tmp_path / "leaf.pem"
    certificate.write_text(pki.old)
    policy = tmp_path / "client.json"
    controller.save(policy, {"cert": "leaf.pem", "key": "ram-only.key"})
    key_path = tmp_path / "ram-only.key"
    key_bytes = pki.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    original = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda p: key_bytes if p == key_path else original(p))
    manifest = controller.inventory({"policies": [str(policy)], "extra_certificates": [],
        "allowed_provisioners": ["collector-clientAuth"], "scoped": Path}, tmp_path)
    status = json.loads((tmp_path / "status.json").read_bytes())
    assert len(manifest) == len(status["credentials"]) == 1
    assert all(c["generation"] == 0 for c in status["credentials"].values())
    assert status["phase"] is None and not key_path.exists()


@pytest.mark.parametrize("purpose", ["clientAuth", "serverAuth"])
def test_provisioner_template_cannot_take_identity_or_purpose_from_csr(purpose):
    config, _ = ca.provisioner("fixed-service", purpose)
    template = json.loads(config["options"]["x509"]["template"])
    assert template["subject"]["commonName"] == "fixed-service"
    assert template["sans"] == [{"type": "dns", "value": "fixed-service"}]
    assert template["extKeyUsage"] == [purpose] and not template["basicConstraints"]["isCA"]


@pytest.mark.parametrize("change", ["name", "purpose", "key", "issuer", "expired", "ca", "san", "lifetime", "same_serial"])
def test_invalid_candidate_never_becomes_service_identity(pki, change):
    arguments = {"name": {"name": "operator"}, "purpose": {"purpose": ExtendedKeyUsageOID.SERVER_AUTH},
        "key": {"public_key": ec.generate_private_key(ec.SECP256R1()).public_key()},
        "issuer": {"signer": ca.hierarchy()[1]}, "expired": {"expired": True}, "ca": {"is_ca": True},
        "san": {"sans": [x509.DNSName("collector"), x509.DNSName("operator")]}, "lifetime": {"seconds": 90000}}
    candidate = pki.old if change == "same_serial" else pki.cert(**arguments[change])
    with pytest.raises((ValueError, x509.ExtensionNotFound)):
        controller.validate_candidate(pki.old, candidate, pki.issuer_pem, pki.key)


def test_valid_candidate_preserves_key_identity_and_single_purpose(pki):
    result = controller.validate_candidate(pki.old, pki.new, pki.issuer_pem, pki.key)
    assert result["name"] == "collector" and result["purpose"] == "clientAuth"
    assert result["fingerprint"] != controller.fingerprint(pki.old)


@pytest.mark.parametrize("missing", ["purpose", "san", "common_name"])
def test_incomplete_identity_extensions_are_rejected_with_safe_error(pki, missing):
    now = datetime.now(UTC)
    builder = (x509.CertificateBuilder().subject_name(x509.Name([] if missing == "common_name" else [x509.NameAttribute(NameOID.COMMON_NAME, "collector")]))
        .issuer_name(pki.issuer[1].subject).public_key(pki.key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=1)).not_valid_after(now + timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
    if missing != "purpose":
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    if missing != "san":
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("collector")]), critical=False)
    cert = builder.sign(pki.issuer[0], hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
    with pytest.raises(controller.LifecycleError):
        controller.metadata(cert)


def test_pin_overlap_and_retirement_preserve_role_other_peers_and_non_policy_fields():
    old, new, other = "a" * 64, "b" * 64, "c" * 64
    original = {"peers": {old: "collector", other: "pep-bridge"}, "server_pins": [old], "forwarded_peers": [old],
                "unrelated": {"text": old}, "key": "unchanged.key"}
    staged = controller.change_pins(original, {old: new}, overlap=True)
    assert staged["peers"] == {old: "collector", new: "collector", other: "pep-bridge"}
    committed = controller.change_pins(staged, {old: new}, overlap=False)
    assert committed["peers"] == {new: "collector", other: "pep-bridge"}
    assert committed["server_pins"] == committed["forwarded_peers"] == [new]
    assert committed["unrelated"] == {"text": old} and original["server_pins"] == [old]


def test_missing_old_pin_is_never_automatically_reintroduced():
    document = {"peers": {"c" * 64: "pep-bridge"}, "server_pins": ["c" * 64]}
    assert controller.change_pins(document, {"a" * 64: "b" * 64}, overlap=True) == document


@pytest.mark.parametrize("document", [[], {"peers": []}, {"server_pins": "a" * 64}, {"peers": {"a" * 64: ["collector"]}}])
def test_malformed_policy_is_rejected_before_publication(document):
    with pytest.raises(controller.LifecycleError):
        controller.change_pins(document, {"a" * 64: "b" * 64}, overlap=True)


@pytest.mark.parametrize("document,mapping", [
    ({"peers": {"a" * 64: "collector", "b" * 64: "pep-bridge"}}, {"a" * 64: "b" * 64}),
    ({"peers": {f"{i:064x}": "collector" for i in range(16)}}, {"0" * 64: "f" * 64}),
    ({"server_pins": [f"{i:064x}" for i in range(16)]}, {"0" * 64: "f" * 64}),
    ({}, {"a" * 64: "a" * 64}), ({}, {"bad": "b" * 64}),
])
def test_role_collision_capacity_or_invalid_transition_fails_closed(document, mapping):
    with pytest.raises(controller.LifecycleError):
        controller.change_pins(document, mapping, overlap=True)


def transaction(tmp_path, pki):
    old, new = controller.fingerprint(pki.old), controller.fingerprint(pki.new)
    policies = []
    for number in range(2):
        path = tmp_path / f"policy-{number}.json"
        before = {"peers": {old: "collector"}}
        controller.save(path, before)
        policies.append({"path": str(path), "before": before,
                         "staged": {"peers": {old: "collector", new: "collector"}}, "committed": {"peers": {new: "collector"}}})
    certificate = tmp_path / "leaf.pem"
    controller.atomic(certificate, pki.old)
    c = controller.metadata(pki.old) | {"id": "credential", "generation": 1, "candidate": pki.new,
        "current": pki.old, "certificates": [str(certificate)], "bindings": [
            {"path": p["path"], "field": "peers", "role": "collector"} for p in policies], "retry_at": 0}
    state = {"credentials": {"credential": c}, "transaction": {"phase": "prepared", "credentials": ["credential"], "policies": policies}}
    controller.save(tmp_path / "state.json", state)
    return {"disabled": [], "overlap_seconds": 0}, state


@pytest.mark.parametrize("fail_at", ["stage_second", "activate_leaf", "retire_second"])
def test_publication_crash_replays_journal_without_losing_role_or_reenrolling(tmp_path, pki, monkeypatch, fail_at):
    cfg, state = transaction(tmp_path, pki)
    old, new = controller.fingerprint(pki.old), controller.fingerprint(pki.new)
    actual = controller.atomic
    tripped = False
    def fail(path, body):
        nonlocal tripped
        text = body.decode() if isinstance(body, bytes) else body
        trigger = ((fail_at == "activate_leaf" and Path(path).name == "leaf.pem") or
            (Path(path).name == "policy-1.json" and
             ((fail_at == "stage_second" and old in text and new in text) or
              (fail_at == "retire_second" and old not in text))))
        if trigger and not tripped:
            tripped = True
            raise OSError("simulated crash")
        actual(path, body)
    monkeypatch.setattr(controller, "atomic", fail)
    monkeypatch.setattr(controller, "readiness", lambda *a: None)
    with pytest.raises(OSError):
        controller.publish(cfg, state, tmp_path)
    recovered = json.loads((tmp_path / "state.json").read_bytes())
    monkeypatch.setattr(controller, "atomic", actual)
    controller.publish(cfg, recovered, tmp_path)
    assert recovered["transaction"] is None and recovered["credentials"]["credential"]["generation"] == 2
    assert (tmp_path / "leaf.pem").read_text() == pki.new
    for path in tmp_path.glob("policy-*.json"):
        assert json.loads(path.read_bytes())["peers"] == {new: "collector"}


def test_failed_reload_keeps_overlap_and_never_retires_working_leaf(tmp_path, pki, monkeypatch):
    cfg, state = transaction(tmp_path, pki)
    def missing(*args):
        raise controller.LifecycleError("not reloaded")
    monkeypatch.setattr(controller, "readiness", missing)
    with pytest.raises(controller.LifecycleError):
        controller.publish(cfg, state, tmp_path)
    assert state["transaction"]["phase"] == "activated"
    assert json.loads((tmp_path / "policy-0.json").read_bytes())["peers"] == {
        controller.fingerprint(pki.old): "collector", controller.fingerprint(pki.new): "collector"}


def test_explicit_policy_edit_during_publication_is_not_overwritten(tmp_path, pki):
    cfg, state = transaction(tmp_path, pki)
    policy = tmp_path / "policy-0.json"
    controller.save(policy, {"peers": {"f" * 64: "collector"}})
    with pytest.raises(controller.LifecycleError, match="publication_conflict"):
        controller.publish(cfg, state, tmp_path)
    assert json.loads(policy.read_bytes()) == {"peers": {"f" * 64: "collector"}}
    assert (tmp_path / "leaf.pem").read_text() == pki.old


def test_disabled_identity_cannot_activate_pending_candidate(tmp_path, pki):
    cfg, state = transaction(tmp_path, pki)
    cfg["disabled"] = ["credential"]
    with pytest.raises(controller.LifecycleError, match="disabled"):
        controller.publish(cfg, state, tmp_path)
    assert (tmp_path / "leaf.pem").read_text() == pki.old


def test_planning_does_not_restore_explicitly_retired_binding(tmp_path, pki):
    cfg, state = transaction(tmp_path, pki)
    paths = [p["path"] for p in state["transaction"]["policies"]]
    controller.save(Path(paths[0]), {"peers": {"f" * 64: "collector"}})
    before = [Path(p).read_bytes() for p in paths]
    cfg["policies"] = paths
    with pytest.raises(controller.LifecycleError, match="retired_binding"):
        controller.plan(cfg, state, ["credential"])
    assert state["credentials"]["credential"]["inhibited"]
    assert [Path(p).read_bytes() for p in paths] == before


@pytest.mark.parametrize("reason", ["expired", "disabled", "inhibited", "not_due", "retry_backoff"])
def test_scheduler_never_reenrolls_expired_or_retired_identity(reason):
    now = time.time()
    credential = {"name": "collector", "generation": 2, "not_after": now + 1000, "retry_at": 0,
                  "candidate": None, "certificates": ["/managed/collector/leaf.pem"]}
    cfg = {"renew_before": {"collector": 10}, "disabled": []}
    if reason == "expired":
        credential["not_after"] = now - 1
    elif reason == "disabled":
        cfg["disabled"] = ["id"]
    elif reason == "inhibited":
        credential["inhibited"] = True
    elif reason == "retry_backoff":
        credential.update(not_after=now + 5, retry_at=now + 100)
    assert controller.selected(cfg, {"credentials": {"id": credential}}, now) == []
    if reason == "expired":
        assert credential["status"] == "expired_reenrollment_required"


def test_ca_authentication_failure_sends_no_bootstrap_token(monkeypatch, tmp_path):
    sent = []
    class Connection:
        def __init__(self, *args, **kwargs):
            pass
        def connect(self):
            raise ssl.SSLError("bad CA")
        def request(self, *args, **kwargs):
            sent.append(True)
        def close(self):
            pass
    monkeypatch.setattr(controller.ssl, "create_default_context", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(controller.http.client, "HTTPSConnection", Connection)
    with pytest.raises(ssl.SSLError):
        controller.ca_post(tmp_path, "/1.0/sign", {"ott": "private test token"})
    assert not sent


def test_client_renewal_uses_mtls_without_exposing_key_or_token_in_arguments(tmp_path, pki, monkeypatch):
    observed = []
    def run(arguments, **kwargs):
        observed.append(arguments)
        Path(arguments[arguments.index("--out") + 1]).write_text(pki.new)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(controller.subprocess, "run", run)
    result = controller.renewal({"id": "id", "certificates": ["/managed/leaf.pem"], "key": "/managed/leaf.key", "purpose": "clientAuth"}, tmp_path)
    assert result == pki.new and not (tmp_path / "id.renew.pem").exists()
    assert "--mtls=false" not in observed[0]
    assert not any("PRIVATE KEY" in value or value.startswith("eyJ") for value in observed[0])


def test_server_only_certificate_is_not_used_as_client_renewal_credential(tmp_path, monkeypatch):
    monkeypatch.setattr(controller.subprocess, "run", lambda *a, **kw: pytest.fail("broadened purpose or attempted self-renewal"))
    with pytest.raises(controller.LifecycleError, match="scoped_renewal_identity"):
        controller.renewal({"purpose": "serverAuth"}, tmp_path)


def test_server_reissue_uses_separate_service_bound_proof_without_broadening_server_eku(tmp_path, pki, monkeypatch):
    helper_pem = pki.cert(name="renew-collector")
    helper_path = tmp_path / "renewal.pem"
    helper_path.write_text(helper_pem)
    helper_key = tmp_path / "ram-only.key"
    key_bytes = pki.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    original = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda p: key_bytes if p == helper_key else original(p))
    helper = {"id": "helper", "name": "renew-collector", "purpose": "clientAuth", "generation": 2,
        "not_after": time.time() + 3600, "certificates": [str(helper_path)], "key": str(helper_key)}
    seen = []
    def post(directory, target, payload):
        seen.append((target, payload))
        return 201, {"certChain": [pki.cert(purpose=ExtendedKeyUsageOID.SERVER_AUTH), pki.issuer_pem]}
    monkeypatch.setattr(controller, "ca_post", post)
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "collector")]))
        .sign(pki.key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
    new = controller.server_reissue({"name": "collector", "not_after": time.time() + 500, "csr": csr},
        {"credentials": {"helper": helper}}, {"server_renewal": {"collector": "renew-collector"}}, tmp_path)
    assert controller.metadata(new)["purpose"] == "serverAuth"
    proof = jwt.decode(seen[0][1]["ott"], pki.key.public_key(), algorithms=["ES256"], audience="https://ca:9000/1.0/sign")
    assert proof["iss"] == "server-renewal-collector" and proof["sans"] == ["collector"]
    header = jwt.get_unverified_header(seen[0][1]["ott"])
    assert "x5c" not in header and header["kid"] == ca.public_jwk(pki.key.public_key())["kid"]
    assert seen[0][1]["csr"] == csr and not helper_key.exists()
    assert proof["cnf"]["x5rt#S256"] == ca.b64(hashlib.sha256(x509.load_pem_x509_csr(csr.encode()).public_bytes(serialization.Encoding.DER)).digest())


@pytest.mark.parametrize("reason", ["missing", "expired", "disabled", "inhibited", "not_enrolled", "server_expired"])
def test_server_reissue_needs_current_authorized_dedicated_identity(tmp_path, monkeypatch, reason):
    server = {"name": "service", "not_after": time.time() + 500, "csr": "public CSR"}
    helper = {"id": "helper", "name": "renew-service", "purpose": "clientAuth", "generation": 2, "not_after": time.time() + 3600}
    cfg = {"server_renewal": {"service": "renew-service"}, "disabled": []}
    if reason == "expired":
        helper["not_after"] = 0
    elif reason == "disabled":
        cfg["disabled"] = ["helper"]
    elif reason == "inhibited":
        helper["inhibited"] = True
    elif reason == "not_enrolled":
        helper["generation"] = 0
    elif reason == "server_expired":
        server["not_after"] = 0
    monkeypatch.setattr(controller, "ca_post", lambda *a: pytest.fail("unauthorized server enrollment"))
    with pytest.raises(controller.LifecycleError):
        controller.server_reissue(server, {"credentials": {} if reason == "missing" else {"helper": helper}}, cfg, tmp_path)


def test_renewal_timeout_leaves_no_candidate_file(tmp_path, monkeypatch):
    def timeout(arguments, **kwargs):
        Path(arguments[arguments.index("--out") + 1]).write_text("partial public certificate")
        raise subprocess.TimeoutExpired(arguments, 4)
    monkeypatch.setattr(controller.subprocess, "run", timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        controller.renewal({"id": "id", "certificates": ["leaf.pem"], "key": "leaf.key", "purpose": "clientAuth"}, tmp_path)
    assert not (tmp_path / "id.renew.pem").exists()
