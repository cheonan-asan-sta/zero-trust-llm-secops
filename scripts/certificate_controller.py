"""Local certificate lifecycle controller: step-ca issuance, renewals, pin publication.

Trusted control plane, not a workload identity attestor. No Docker socket, CA
signing/root key, HTTP fallback or automatic expired re-enrollment. Delegated
server provisioner keys are restricted to this control plane's private volumes.
Renewal preserves the private key; rekey/root rotation are separate operations.
"""

import argparse
import hashlib
import http.client
import json
import os
import random
import re
import socket
import ssl
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts.certificate_authority import server_renewal_token


class LifecycleError(ValueError):
    pass


def atomic(path, body):
    path = Path(path)
    temporary = path.with_name(path.name + ".new")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as stream:
        stream.write(body.encode() if isinstance(body, str) else body)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def save(path, value):
    atomic(path, json.dumps(value, sort_keys=True))


def fingerprint(pem):
    return x509.load_pem_x509_certificate(pem.encode()).fingerprint(hashes.SHA256()).hex()


def metadata(pem):
    try:
        return certificate_metadata(pem)
    except (x509.ExtensionNotFound, x509.DuplicateExtension, IndexError):
        raise LifecycleError("certificate_identity_extensions") from None


def certificate_metadata(pem):
    cert = x509.load_pem_x509_certificate(pem.encode())
    purpose = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if list(purpose) == [ExtendedKeyUsageOID.CLIENT_AUTH]:
        kind = "clientAuth"
    elif list(purpose) == [ExtendedKeyUsageOID.SERVER_AUTH]:
        kind = "serverAuth"
    else:
        raise LifecycleError("ambiguous_purpose")
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if list(sans) != [x509.DNSName(name)] or cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise LifecycleError("identity_shape")
    return {"name": name, "purpose": kind, "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
            "serial": str(cert.serial_number), "not_after": cert.not_valid_after_utc.timestamp()}


def validate_candidate(old, candidate, issuer_pem, key):
    before, after = metadata(old), metadata(candidate)
    leaf = x509.load_pem_x509_certificate(candidate.encode())
    issuer = x509.load_pem_x509_certificate(issuer_pem.encode())
    try:
        leaf.verify_directly_issued_by(issuer)
    except InvalidSignature:
        raise LifecycleError("candidate_issuer_signature") from None
    now = datetime.now(UTC)
    try:
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        raise LifecycleError("candidate_key_usage_missing") from None
    if not usage.digital_signature or usage.key_cert_sign or usage.crl_sign:
        raise LifecycleError("candidate_key_usage")
    if (before["name"] != after["name"] or before["purpose"] != after["purpose"]
            or before["serial"] == after["serial"] or not leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc
            or (leaf.not_valid_after_utc - leaf.not_valid_before_utc).total_seconds() > 86400):
        raise LifecycleError("candidate_identity_or_validity")
    if leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
        raise LifecycleError("candidate_key_mismatch")
    return after


def bindings(document, old):
    validate_policy(document)
    result = []
    if old in document.get("peers", {}):
        result.append(("peers", document["peers"][old]))
    for field in ["server_pins", "forwarded_peers"]:
        if old in document.get(field, []):
            result.append((field, None))
    return result


def validate_policy(document):
    if not isinstance(document, dict) or not isinstance(document.get("peers", {}), dict):
        raise LifecycleError("policy_shape")
    for field in ["server_pins", "forwarded_peers"]:
        if not isinstance(document.get(field, []), list):
            raise LifecycleError("policy_pin_shape")
    for values in [document.get("peers", {}), document.get("server_pins", []), document.get("forwarded_peers", [])]:
        if len(values) > 16 or any(not isinstance(v, str) or not re.fullmatch(r"[a-f0-9]{64}", v) for v in values):
            raise LifecycleError("policy_pin_shape")
    if any(not isinstance(role, str) for role in document.get("peers", {}).values()):
        raise LifecycleError("policy_role_shape")


def change_pins(document, mapping, *, overlap):
    validate_policy(document)
    if any(not re.fullmatch(r"[a-f0-9]{64}", old) or not re.fullmatch(r"[a-f0-9]{64}", new) or old == new for old, new in mapping.items()):
        raise LifecycleError("pin_transition")
    result = json.loads(json.dumps(document))
    peers = result.get("peers", {})
    for old, new in mapping.items():
        if old in peers:
            if new in peers and peers[new] != peers[old]:
                raise LifecycleError("conflicting_service_role")
            peers[new] = peers[old]
            if not overlap:
                del peers[old]
        for field in ["server_pins", "forwarded_peers"]:
            values = result.get(field, [])
            if old in values:
                result[field] = list(dict.fromkeys([v for v in values if overlap or v != old] + [new]))
    if len(peers) > 16 or any(len(result.get(f, [])) > 16 for f in ["server_pins", "forwarded_peers"]):
        raise LifecycleError("pin_capacity")
    return result


def cas(path, before, after):
    current = json.loads(Path(path).read_bytes())
    if current == after:
        return  # Crash recovery can replay an already committed individual file.
    if current != before:
        raise LifecycleError("publication_conflict")
    save(path, after)


def ca_post(state_dir, target, payload):
    if target not in {"/1.0/sign", "/1.0/revoke"}:
        raise LifecycleError("ca_route")
    context = ssl.create_default_context(cafile=str(state_dir / "root.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = http.client.HTTPSConnection("ca", 9000, context=context, timeout=3)
    try:
        connection.connect()  # Server authentication precedes the one-time credential.
        connection.request("POST", target, json.dumps(payload).encode(), {"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read(131073)
        if len(raw) > 131072:
            raise LifecycleError("ca_response_size")
        return response.status, json.loads(raw)
    finally:
        connection.close()


def config(path):
    value = json.loads(path.read_bytes())
    roots = [Path(p).resolve() for p in value["roots"]]
    if not 1 <= len(roots) <= 32 or any(p.parent != Path("/managed") for p in roots):
        raise LifecycleError("managed_roots")
    def scoped(name):
        p = Path(name)
        if p.is_symlink() or p.resolve().parent not in roots or not re.fullmatch(r"[A-Za-z0-9_.-]+", p.name):
            raise LifecycleError("managed_asset_scope")
        return p
    for name in value["policies"] + [p for pair in value["extra_certificates"] for p in pair]:
        scoped(name)
    value["scoped"] = scoped
    return value


def inventory(cfg, state_dir):
    pairs = {tuple(pair) for pair in cfg["extra_certificates"]}
    documents = {p: json.loads(Path(p).read_bytes()) for p in cfg["policies"]}
    for path, data in documents.items():
        if path not in cfg.get("unmanaged_profiles", []) and isinstance(data.get("cert"), str) and isinstance(data.get("key"), str):
            root = Path(path).parent
            pairs.add((str(cfg["scoped"](root / data["cert"])), str(cfg["scoped"](root / data["key"]))))
    credentials = {}
    for certificate_path, key_path in sorted(pairs):
        old = Path(certificate_path).read_text()
        info = metadata(old)
        if info["name"] + "-" + info["purpose"] not in cfg["allowed_provisioners"]:
            raise LifecycleError("unregistered_identity")
        key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
        leaf = x509.load_pem_x509_certificate(old.encode())
        if leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
            raise LifecycleError("live_key_mismatch")
        uid = info["fingerprint"]
        if uid not in credentials:
            csr = (x509.CertificateSigningRequestBuilder().subject_name(leaf.subject)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(info["name"])]), critical=False)
                .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
            credentials[uid] = info | {"id": uid, "csr": csr, "key": key_path, "certificates": [],
                "bindings": [{"path": p, "field": field, "role": role} for p, data in documents.items()
                             for field, role in bindings(data, uid)], "generation": 0,
                "current": old, "candidate": None, "failures": 0, "retry_at": 0}
        credentials[uid]["certificates"].append(certificate_path)
    if not credentials or len(credentials) > 64:
        raise LifecycleError("credential_count")
    state = {"schema": "certificate-lifecycle-1", "credentials": credentials, "transaction": None}
    save(state_dir / "state.json", state)
    status(state, state_dir)  # Publish generation zero before the first concurrent CA round.
    return {uid: {k: c[k] for k in ["name", "purpose", "csr", "certificates", "fingerprint"]} for uid, c in credentials.items()}


def renewal(c, state_dir):
    if c["purpose"] != "clientAuth":
        raise LifecycleError("server_requires_scoped_renewal_identity")
    output = state_dir / (c["id"] + ".renew.pem")
    command = ["/tools/step", "ca", "renew", c["certificates"][0], c["key"], "--force", "--out", str(output),
               "--ca-url", "https://ca:9000", "--root", str(state_dir / "root.pem")]
    try:
        result = subprocess.run(command, capture_output=True, timeout=4, check=False)
        if result.returncode != 0:
            raise LifecycleError("renewal_denied")
        return output.read_text()
    finally:
        output.unlink(missing_ok=True)


def server_reissue(c, state, cfg, state_dir):
    expected = cfg["server_renewal"][c["name"]]
    helpers = [helper for helper in state["credentials"].values() if helper["name"] == expected and helper["purpose"] == "clientAuth"]
    if len(helpers) != 1:
        raise LifecycleError("server_renewal_identity_missing")
    helper = helpers[0]
    if (helper["id"] in cfg.get("disabled", []) or helper.get("inhibited") or helper["generation"] < 1
            or helper["not_after"] <= time.time() or c["not_after"] <= time.time()):
        raise LifecycleError("server_renewal_identity_unavailable")
    proof = Path(helper["certificates"][0]).read_text()
    key = serialization.load_pem_private_key(Path(helper["key"]).read_bytes(), password=None)
    token = server_renewal_token(c["name"], proof, key, c["csr"])
    code, response = ca_post(state_dir, "/1.0/sign", {"csr": c["csr"], "ott": token, "notAfter": "20m"})
    if code != 201:
        raise LifecycleError("server_reissue_denied")
    return issued_chain(response)


def issued_chain(response):
    values = response.get("certChain") or [response["crt"], response["ca"]]
    if not isinstance(values, list) or not 1 <= len(values) <= 4 or not all(isinstance(v, str) for v in values):
        raise LifecycleError("ca_chain_shape")
    return "\n".join(values)


def selected(cfg, state, now):
    chosen = set()
    for uid, c in state["credentials"].items():
        if uid in cfg.get("disabled", []):
            c["status"] = "disabled"
            continue
        if c.get("inhibited"):
            continue
        if c["generation"] and c["not_after"] <= now:
            c["status"] = "expired_reenrollment_required"
            continue
        if c["candidate"] or (c["retry_at"] <= now and (c["generation"] == 0 or c["not_after"] - now <= cfg["renew_before"].get(c["name"], 400))):
            chosen.add(uid)
    # Reloading clients and servers in one process is one publication group.
    for group in cfg.get("reload_groups", []):
        related = {uid for uid, c in state["credentials"].items()
                   if any(str(Path(p).parent) == group["root"] for p in c["certificates"])}
        if chosen & related:
            chosen |= {uid for uid in related if uid not in cfg.get("disabled", []) and not state["credentials"][uid].get("inhibited")}
    return sorted(chosen)


def plan(cfg, state, identifiers):
    documents = {p: json.loads(Path(p).read_bytes()) for p in cfg["policies"]}
    mapping = {}
    for uid in identifiers:
        c = state["credentials"][uid]
        for binding in c["bindings"]:
            if (binding["field"], binding["role"]) not in bindings(documents[binding["path"]], c["fingerprint"]):
                c.update(inhibited=True, status="retired_binding")
                raise LifecycleError("retired_binding")
        mapping[c["fingerprint"]] = fingerprint(c["candidate"])
    policies = []
    for path, old in documents.items():
        staged = change_pins(old, mapping, overlap=True)
        if staged != old:
            policies.append({"path": path, "before": old, "staged": staged,
                             "committed": change_pins(staged, mapping, overlap=False)})
    return {"phase": "prepared", "credentials": identifiers, "policies": policies, "created_at": time.time()}


def probe_server(probe, expected, state_dir):
    context = ssl.create_default_context(cafile=str(state_dir / "root.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    path = Path(probe["profile"])
    client = json.loads(path.read_bytes())
    context.load_cert_chain(path.parent / client["cert"], path.parent / client["key"])
    with socket.create_connection((probe["host"], probe["port"]), timeout=1) as raw, context.wrap_socket(raw, server_hostname=probe["server_name"]) as sock:
        if hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest() != expected:
            raise LifecycleError("server_not_reloaded")
        return {"fingerprint": expected, "tls_version": sock.version(), "at": time.time()}


def readiness(cfg, state, state_dir):
    pending = [state["credentials"][uid] for uid in state["transaction"]["credentials"]]
    paths = {p for c in pending for p in c["certificates"]}
    for group in cfg.get("reload_groups", []):
        if any(str(Path(p).parent) == group["root"] for p in paths):
            digest = hashlib.sha256(b"".join(Path(p).read_bytes() for p in group["files"])).hexdigest()
            if Path(group["ack"]).read_text().strip() != digest:
                raise LifecycleError("reload_ack_missing")
    for c in pending:
        if c["purpose"] == "serverAuth":
            probes = [p for p in cfg["probes"] if p["server_name"] == c["name"]]
            if not probes:
                raise LifecycleError("server_probe_missing")
            for probe in probes:
                observed = probe_server(probe, fingerprint(c["candidate"]), state_dir)
                state.setdefault("server_observations", {})[c["name"]] = observed


def publish(cfg, state, state_dir):
    txn = state["transaction"]
    if set(txn["credentials"]) & set(cfg.get("disabled", [])):
        raise LifecycleError("identity_disabled_during_publication")
    if txn["phase"] != "retiring" and any(metadata(state["credentials"][uid]["candidate"])["not_after"] <= time.time() for uid in txn["credentials"]):
        raise LifecycleError("candidate_expired_during_publication")
    if txn["phase"] == "prepared":
        for policy in txn["policies"]:
            cas(policy["path"], policy["before"], policy["staged"])
        txn["phase"] = "staged"
        save(state_dir / "state.json", state)
    if txn["phase"] == "staged":
        for policy in txn["policies"]:
            if json.loads(Path(policy["path"]).read_bytes()) != policy["staged"]:
                raise LifecycleError("publication_conflict")
        for uid in txn["credentials"]:
            c = state["credentials"][uid]
            if metadata(c["candidate"])["not_after"] <= time.time():
                raise LifecycleError("candidate_expired_before_activation")
            for path in c["certificates"]:
                if fingerprint(Path(path).read_text()) not in {c["fingerprint"], fingerprint(c["candidate"])}:
                    raise LifecycleError("certificate_changed")
                atomic(path, c["candidate"])
        txn.update(phase="activated", activated_at=time.time())
        save(state_dir / "state.json", state)
    if txn["phase"] == "activated":
        readiness(cfg, state, state_dir)
        if time.time() - txn["activated_at"] < cfg.get("overlap_seconds", 1):
            return
        txn["phase"] = "retiring"
        save(state_dir / "state.json", state)
    if txn["phase"] == "retiring":
        for policy in txn["policies"]:
            cas(policy["path"], policy["staged"], policy["committed"])
        for uid in txn["credentials"]:
            c = state["credentials"][uid]
            c.update(metadata(c["candidate"]))
            c.update(current=c["candidate"], candidate=None, generation=c["generation"] + 1,
                     status="active", failures=0, retry_at=0)
        state["transaction"] = None
        save(state_dir / "state.json", state)


def status(state, state_dir):
    save(state_dir / "status.json", {"at": time.time(), "phase": (state.get("transaction") or {}).get("phase"),
        "paused": state.get("paused_ack", False),
        "server_observations": state.get("server_observations", {}),
        "last_error": state.get("last_error"), "credentials": {uid: {k: c.get(k) for k in
            ["name", "purpose", "fingerprint", "serial", "not_after", "generation", "status", "failures"]}
            for uid, c in state["credentials"].items()}})


def tick(cfg, state, state_dir):
    if state["transaction"]:
        publish(cfg, state, state_dir)
        return
    chosen = selected(cfg, state, time.time())
    bootstrap_path = state_dir / "bootstrap.json"
    bootstrap = json.loads(bootstrap_path.read_bytes()) if bootstrap_path.exists() else {}
    issuer = (state_dir / "issuer.pem").read_text()
    def get_candidate(uid):
        c = state["credentials"][uid]
        if c["candidate"]:
            return uid, c["candidate"], None
        try:
            if c["generation"] == 0:
                grant = bootstrap[uid]
                code, response = ca_post(state_dir, "/1.0/sign", {"csr": c["csr"], "ott": grant["token"], "notAfter": grant.get("duration", "20m")})
                if code != 201:
                    raise LifecycleError("enrollment_denied")
                new = issued_chain(response)
            else:
                new = server_reissue(c, state, cfg, state_dir) if c["purpose"] == "serverAuth" else renewal(c, state_dir)
            key = serialization.load_pem_private_key(Path(c["key"]).read_bytes(), password=None)
            validate_candidate(c["current"], new, issuer, key)
            return uid, new, None
        except (OSError, ValueError, TypeError, KeyError, http.client.HTTPException, subprocess.SubprocessError):
            return uid, None, "enrollment_or_renewal_failed"
    with ThreadPoolExecutor(max_workers=8) as pool:
        for uid, new, error in pool.map(get_candidate, chosen):
            c = state["credentials"][uid]
            if error:
                c["failures"] += 1
                c.update(status=error, retry_at=time.time() + min(30, 2 ** min(c["failures"], 4)) + random.random())
            else:
                c["candidate"] = new
                save(state_dir / "state.json", state)  # Persist candidate before deleting its used bootstrap token.
                bootstrap.pop(uid, None)
                if bootstrap_path.exists():
                    save(bootstrap_path, bootstrap)
            save(state_dir / "state.json", state)
    ready = [uid for uid in chosen if state["credentials"][uid]["candidate"]]
    if ready:
        state["transaction"] = plan(cfg, state, ready)
        save(state_dir / "state.json", state)
        publish(cfg, state, state_dir)
    if not bootstrap and bootstrap_path.exists():
        bootstrap_path.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["init", "run", "rpc"])
    parser.add_argument("--config", type=Path, default=Path("/state/config.json"))
    args = parser.parse_args()
    state_dir = args.config.parent
    cfg = config(args.config)
    if args.mode == "init":
        if (state_dir / "state.json").exists():
            raise LifecycleError("already_initialized")
        print(json.dumps(inventory(cfg, state_dir)))
        return
    if args.mode == "rpc":
        request = json.load(sys.stdin)
        if request["operation"] == "ca_post":
            code, result = ca_post(state_dir, request["path"], request["payload"])
            print(json.dumps({"status": code, "result": result}))
        elif request["operation"] == "status":
            print((state_dir / "status.json").read_text())
        elif request["operation"] in {"revoke", "renew_attempt"}:
            state = json.loads((state_dir / "state.json").read_bytes())
            c = state["credentials"][request["id"]]
            if request["operation"] == "renew_attempt":
                try:
                    renewal(c, state_dir)
                    print(json.dumps({"allowed": True}))
                except (OSError, ValueError, subprocess.SubprocessError):
                    print(json.dumps({"allowed": False}))
            else:
                result = subprocess.run(["/tools/step", "ca", "revoke", "--cert", c["certificates"][0],
                    "--key", c["key"], "--ca-url", "https://ca:9000", "--root", str(state_dir / "root.pem")],
                    capture_output=True, timeout=5, check=False)
                print(json.dumps({"revoked": result.returncode == 0}))
        else:
            raise LifecycleError("rpc_operation")
        return
    import fcntl  # Linux only: one publisher owns the shared control-plane state.
    with (state_dir / "controller.lock").open("a") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = json.loads((state_dir / "state.json").read_bytes())
        while True:
            cfg = config(args.config)
            try:
                state["paused_ack"] = bool(cfg.get("paused") and not state["transaction"])
                if not state["paused_ack"]:
                    tick(cfg, state, state_dir)
                state["last_error"] = None
            except (OSError, ValueError, TypeError, KeyError, http.client.HTTPException, subprocess.SubprocessError):
                state["last_error"] = "publication_or_configuration_failed"
            save(state_dir / "state.json", state)
            status(state, state_dir)
            time.sleep(max(.2, min(10, cfg.get("interval_seconds", 2))))


if __name__ == "__main__":
    main()
