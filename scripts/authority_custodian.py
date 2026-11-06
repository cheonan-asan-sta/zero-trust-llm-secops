"""Network-isolated software custodian for local root/issuer/JWK rotation.

Only encrypted authority bundles persist in /vault. The CA and leaf controller
never mount that vault. Initial import and Docker orchestration are trusted host
administration, not a hardware/air-gapped root or workload attestation.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

from scripts.certificate_authority import bootstrap_token, public_jwk
from scripts.certificate_controller import LifecycleError, atomic, fingerprint, remove_file, save
from scripts.certificate_key_rotation import public_hash


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def pem_key(key, password=None):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()).decode()


def load_key(value):
    return serialization.load_pem_private_key(value.encode(), password=None)


def pem_cert(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def seal(bundle, password):
    nonce = secrets.token_bytes(12)
    key = hashlib.sha256(password + b"authority-bundle-v1").digest()
    return base64.b64encode(nonce + AESGCM(key).encrypt(nonce, canonical(bundle), b"authority-bundle-v1"))


def unseal(body, password):
    raw = base64.b64decode(body, validate=True)
    key = hashlib.sha256(password + b"authority-bundle-v1").digest()
    return json.loads(AESGCM(key).decrypt(raw[:12], raw[12:], b"authority-bundle-v1"))


def ca_certificate(key, name, root, *, days, depth):
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    signer, issuer = (key, subject) if root is None else (root[0], root[1].subject)
    end = now + timedelta(days=days)
    if root:
        end = min(end, root[1].not_valid_after_utc)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(seconds=30)).not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=depth), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
        .sign(signer, hashes.SHA256()))


def seed_files(root, issuer, providers, private_keys, signers, *, policy, last_at=None):
    if set(private_keys) != {p["name"] for p in providers}:
        raise LifecycleError("authority_registration_set")
    for p in providers:
        if p["type"] != "JWK" or p["key"] != public_jwk(private_keys[p["name"]].public_key()):
            raise LifecycleError("authority_registration_key")
    password = secrets.token_urlsafe(48).encode()
    bundle = {"generation": 0, "root": pem_cert(root[1]), "root_key": pem_key(root[0]),
        "issuer": pem_cert(issuer[1]), "issuer_key": pem_key(issuer[0]),
        "providers": providers, "keys": {name: pem_key(key) for name, key in private_keys.items()},
        "signers": signers, "created_at": time.time(), "changed": {}, "previous": None}
    state = {"schema": "authority-custodian-1", "generation": 0, "bundle": "authority-g0.sealed",
        "root": bundle["root"], "issuer": bundle["issuer"],
        "manifest_hash": None, "last_at": dict.fromkeys(["root", "issuer", "jwk"], time.time() if last_at is None else last_at),
        "policy": policy, "pending": None}
    return {"password": password.decode(), "authority-g0.sealed": seal(bundle, password).decode(), "state.json": json.dumps(state)}


def due_parts(state, current, now):
    policy = state["policy"]
    if set(policy["periods"]) != {"root", "issuer", "jwk"} or any(
            type(n) not in {float, int} or not 1 <= n <= 86400 * 3650 for n in policy["periods"].values()):
        raise LifecycleError("authority_periods")
    changed = {name: now - state["last_at"][name] >= period for name, period in policy["periods"].items()}
    for name in ["root", "issuer"]:
        changed[name] |= x509.load_pem_x509_certificate(current[name].encode()).not_valid_after_utc.timestamp() - now <= policy.get("expiry_margin_seconds", 3600)
    changed["issuer"] |= changed["root"]
    return changed


def rotate_bundle(current, state, now):
    if any(x509.load_pem_x509_certificate(current[name].encode()).not_valid_after_utc.timestamp() <= now for name in ["root", "issuer"]):
        raise LifecycleError("expired_authority_requires_recovery")
    changed = due_parts(state, current, now)
    if not any(changed.values()):
        return None
    result = json.loads(json.dumps(current))
    generation = state["generation"] + 1
    result.update(generation=generation, previous=state["manifest_hash"], changed=changed, created_at=now)
    if changed["root"]:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = ca_certificate(key, f"Local rotation root {generation}", None, days=state["policy"].get("root_days", 730), depth=1)
        result.update(root=pem_cert(cert), root_key=pem_key(key))
    if changed["issuer"]:
        key = ec.generate_private_key(ec.SECP256R1())
        root = (load_key(result["root_key"]), x509.load_pem_x509_certificate(result["root"].encode()))
        cert = ca_certificate(key, f"Local rotation issuer {generation}", root, days=state["policy"].get("issuer_days", 90), depth=0)
        result.update(issuer=pem_cert(cert), issuer_key=pem_key(key))
    if changed["jwk"]:
        for provider in result["providers"]:
            key = ec.generate_private_key(ec.SECP256R1())
            result["keys"][provider["name"]] = pem_key(key)
            provider["key"] = public_jwk(key.public_key())
        result["signers"] = {name: f"sign-{name}-g{generation}.key" for name in result["signers"]}
    return result


def next_due(state):
    deadlines = [state["last_at"][name] + period for name, period in state["policy"]["periods"].items()]
    deadlines += [x509.load_pem_x509_certificate(state[name].encode()).not_valid_after_utc.timestamp()
                  - state["policy"].get("expiry_margin_seconds", 3600) for name in ["root", "issuer"]]
    return min(deadlines)


def public_plan(current, candidate, ca_config, previous_hash):
    epoch = candidate["generation"]
    if ca_config["authority"]["provisioners"] != current["providers"]:
        raise LifecycleError("authority_provider_configuration_changed")
    updated = json.loads(json.dumps(ca_config))
    changed = candidate["changed"]
    root_path = f"/ca/root-g{epoch}.pem" if changed["root"] else ca_config["root"]
    if not isinstance(root_path, str) or not isinstance(ca_config["root"], str):
        raise LifecycleError("authority_single_owned_root_required")
    updated["root"] = root_path
    if changed["issuer"]:
        updated.update(crt=f"/ca/issuer-g{epoch}.pem", key=f"/ca/issuer-g{epoch}.key")
    updated["authority"]["provisioners"] = candidate["providers"]
    overlap = updated | {"root": [ca_config["root"], root_path]} if changed["root"] else updated
    plan = {"schema": "authority-plan-1", "epoch": epoch, "previous": previous_hash,
        "changed": changed, "created_at": candidate["created_at"],
        "old_root": current["root"], "root": candidate["root"], "old_issuer": current["issuer"], "issuer": candidate["issuer"],
        "before_ca": ca_config, "overlap_ca": overlap, "final_ca": updated,
        "old_signers": current["signers"], "signers": candidate["signers"],
        "root_public_key_sha256": public_hash(load_key(candidate["root_key"]).public_key()),
        "issuer_public_key_sha256": public_hash(load_key(candidate["issuer_key"]).public_key())}
    plan["proof"] = base64.b64encode(load_key(current["root_key"]).sign(canonical(plan), ec.ECDSA(hashes.SHA256()))).decode()
    return plan


def verify_plan(plan, trusted_root, *, epoch, previous):
    body = {k: v for k, v in plan.items() if k != "proof"}
    if plan["epoch"] != epoch or plan["previous"] != previous or fingerprint(plan["old_root"]) != fingerprint(trusted_root):
        raise LifecycleError("authority_plan_sequence_or_anchor")
    root = x509.load_pem_x509_certificate(trusted_root.encode())
    try:
        root.public_key().verify(base64.b64decode(plan["proof"], validate=True), canonical(body), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise LifecycleError("authority_plan_proof") from None
    issuer = x509.load_pem_x509_certificate(plan["issuer"].encode())
    new_root = x509.load_pem_x509_certificate(plan["root"].encode())
    new_root.verify_directly_issued_by(new_root)
    issuer.verify_directly_issued_by(new_root)
    for certificate, depth in [(new_root, 1), (issuer, 0)]:
        constraint = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        if (not constraint.ca or constraint.path_length != depth or not usage.key_cert_sign
                or not usage.crl_sign or not certificate.not_valid_before_utc <= datetime.now(UTC) < certificate.not_valid_after_utc):
            raise LifecycleError("authority_ca_constraints")
    for name, certificate in [("root", new_root), ("issuer", issuer)]:
        actual = public_hash(certificate.public_key())
        old = public_hash(x509.load_pem_x509_certificate(plan["old_" + name].encode()).public_key())
        if actual != plan[name + "_public_key_sha256"] or (actual != old) != plan["changed"][name]:
            raise LifecycleError("authority_ca_key_transition")
    before, after = plan["before_ca"]["authority"]["provisioners"], plan["final_ca"]["authority"]["provisioners"]
    if [{k: v for k, v in p.items() if k != "key"} for p in before] != [{k: v for k, v in p.items() if k != "key"} for p in after]:
        raise LifecycleError("authority_scope_change")
    if any(p["type"] != "JWK" or "d" in p["key"] for p in after):
        raise LifecycleError("authority_public_jwk_shape")
    if any((old["key"] != new["key"]) != plan["changed"]["jwk"] for old, new in zip(before, after, strict=True)):
        raise LifecycleError("authority_jwk_key_transition")
    def unchanged(config):
        result = json.loads(json.dumps(config))
        for field in ["root", "crt", "key"]:
            result.pop(field)
        result["authority"]["provisioners"] = [{k: v for k, v in p.items() if k != "key"} for p in result["authority"]["provisioners"]]
        return result
    if unchanged(plan["before_ca"]) != unchanged(plan["final_ca"]):
        raise LifecycleError("authority_ca_policy_change")
    for field in ["root", "crt", "key"]:
        if not re.fullmatch(r"/ca/[A-Za-z0-9_-]+\.(?:pem|key)", plan["final_ca"][field]):
            raise LifecycleError("authority_ca_path")
        part = "root" if field == "root" else "issuer"
        expected = (f"/ca/{part}-g{epoch}.{'key' if field == 'key' else 'pem'}" if plan["changed"][part]
                    else plan["before_ca"][field])
        if plan["final_ca"][field] != expected:
            raise LifecycleError("authority_ca_generation_path")
    expected_overlap = plan["final_ca"] | {"root": [plan["before_ca"]["root"], plan["final_ca"]["root"]]} if plan["changed"]["root"] else plan["final_ca"]
    if plan["overlap_ca"] != expected_overlap or set(plan["signers"]) != set(plan["old_signers"]):
        raise LifecycleError("authority_overlap_or_signer_scope")
    for name, filename in plan["signers"].items():
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or filename != (f"sign-{name}-g{epoch}.key" if plan["changed"]["jwk"] else plan["old_signers"][name]):
            raise LifecycleError("authority_signer_generation_path")
    return digest(plan)


def verify_private_bundle(plan, bundle):
    if (bundle["generation"] != plan["epoch"] or bundle["previous"] != plan["previous"]
            or bundle["providers"] != plan["final_ca"]["authority"]["provisioners"] or bundle["signers"] != plan["signers"]
            or any(bundle[name] != plan[name] for name in ["root", "issuer"])):
        raise LifecycleError("authority_private_bundle_identity")
    for name in ["root", "issuer"]:
        if public_hash(load_key(bundle[name + "_key"]).public_key()) != plan[name + "_public_key_sha256"]:
            raise LifecycleError("authority_private_bundle_key")
    for provider in bundle["providers"]:
        if public_jwk(load_key(bundle["keys"][provider["name"]]).public_key()) != provider["key"]:
            raise LifecycleError("authority_private_bundle_jwk")


def scoped(root, name):
    path = Path(name)
    if path.is_symlink() or path.parent != root or path.resolve().parent != root.resolve():
        raise LifecycleError("authority_file_scope")
    return path


def prepare(vault, ca, renewal):
    state = json.loads((vault / "state.json").read_bytes())
    if not state["pending"] and not (vault / f"authority-g{state['generation'] + 1}.sealed").exists() and not any(due_parts(state, state, time.time()).values()):
        return {"due": False, "epoch": state["generation"], "next_due_at": next_due(state)}
    password = (vault / "password").read_bytes()
    current = unseal((vault / state["bundle"]).read_bytes(), password)
    pending_path = vault / f"authority-g{state['generation'] + 1}.sealed"
    if pending_path.exists():
        candidate = unseal(pending_path.read_bytes(), password)
        if candidate["generation"] != state["generation"] + 1 or candidate["previous"] != state["manifest_hash"]:
            raise LifecycleError("authority_pending_sequence")
    else:
        candidate = rotate_bundle(current, state, time.time())
        if candidate is None:
            return {"due": False, "epoch": state["generation"], "next_due_at": next_due(state)}
        atomic(pending_path, seal(candidate, password))
    ca_config = json.loads((ca / "ca.json").read_bytes())
    if state["pending"]:
        plan = state["pending"]
    else:
        plan = public_plan(current, candidate, ca_config, state["manifest_hash"])
        state["pending"] = plan
        retired = [("vault", vault / state["bundle"])]
        if candidate["changed"]["root"]:
            retired.append(("ca", scoped(ca, ca_config["root"])))
        if candidate["changed"]["issuer"]:
            retired += [("ca", scoped(ca, ca_config[field])) for field in ["crt", "key"]]
        if candidate["changed"]["jwk"]:
            retired += [("renewal", scoped(renewal, renewal / name)) for name in current["signers"].values()]
        state["retirement_files"] = [{"root": label, "name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                                     for label, path in retired]
        save(vault / "state.json", state)
    verify_plan(plan, current["root"], epoch=state["generation"] + 1, previous=state["manifest_hash"])
    if candidate["changed"]["root"]:
        atomic(scoped(ca, plan["final_ca"]["root"]), candidate["root"])
    if candidate["changed"]["issuer"]:
        atomic(scoped(ca, plan["final_ca"]["crt"]), candidate["issuer"])
        atomic(scoped(ca, plan["final_ca"]["key"]), pem_key(load_key(candidate["issuer_key"]), (ca / "password.txt").read_bytes()))
    if candidate["changed"]["jwk"]:
        for name, filename in candidate["signers"].items():
            atomic(scoped(renewal, renewal / filename), candidate["keys"]["server-renewal-" + name])
    return {"due": True, "plan": plan}


def finish(vault, ca, renewal, receipt):
    state = json.loads((vault / "state.json").read_bytes())
    plan = state["pending"]
    if plan is None:
        if receipt["plan_hash"] == state["manifest_hash"]:
            return {"committed": True, "epoch": state["generation"], "next_due_at": next_due(state)}
        raise LifecycleError("authority_missing_pending")
    if (receipt["plan_hash"] != digest(plan) or not receipt.get("migration_verified") or not receipt.get("retired_trust_verified")
            or json.loads((ca / "ca.json").read_bytes()) != plan["final_ca"]):
        raise LifecycleError("authority_retirement_barrier")
    old_bundle = state["bundle"]
    new_bundle = f"authority-g{plan['epoch']}.sealed"
    candidate = unseal((vault / new_bundle).read_bytes(), (vault / "password").read_bytes())
    verify_private_bundle(plan, candidate)
    for field, name in [("root", "root"), ("crt", "issuer")]:
        if fingerprint(scoped(ca, plan["final_ca"][field]).read_text()) != fingerprint(plan[name]):
            raise LifecycleError("authority_successor_file_changed")
    issuer_key = serialization.load_pem_private_key(scoped(ca, plan["final_ca"]["key"]).read_bytes(), password=(ca / "password.txt").read_bytes())
    if public_hash(issuer_key.public_key()) != plan["issuer_public_key_sha256"]:
        raise LifecycleError("authority_successor_file_changed")
    for name, filename in candidate["signers"].items():
        key = serialization.load_pem_private_key(scoped(renewal, renewal / filename).read_bytes(), password=None)
        if public_jwk(key.public_key()) != public_jwk(load_key(candidate["keys"]["server-renewal-" + name]).public_key()):
            raise LifecycleError("authority_successor_file_changed")
    # Persist cleanup intent before advancing or deleting any authority secret.
    state.update(generation=plan["epoch"], manifest_hash=digest(plan), bundle=new_bundle, root=plan["root"], issuer=plan["issuer"],
                 cleanup=state.get("cleanup") or {"old_bundle": old_bundle, "plan": plan})
    for name, changed in plan["changed"].items():
        if changed:
            state["last_at"][name] = time.time()
    save(vault / "state.json", state)
    for retired in state["retirement_files"]:
        root = {"vault": vault, "ca": ca, "renewal": renewal}[retired["root"]]
        path = scoped(root, root / retired["name"])
        if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() != retired["sha256"]:
            raise LifecycleError("authority_retired_file_changed")
        remove_file(path, missing_ok=True)
    state.update(pending=None, cleanup=None)
    save(vault / "state.json", state)
    return {"committed": True, "epoch": state["generation"], "next_due_at": next_due(state)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["prepare", "install", "finish", "probe", "old-probes", "status"])
    args = parser.parse_args()
    vault, ca, renewal = Path("/vault"), Path("/ca"), Path("/renewal")
    if args.operation == 'status':
        state = json.loads((vault / 'state.json').read_bytes())
        bundles = list(vault.glob('authority-g*.sealed'))
        result = {'epoch': state['generation'], 'pending': state['pending'] is not None,
                  'only_current_sealed_bundle': len(bundles) == 1 and bundles[0].name == state['bundle'],
                  'ca_private_key_files': len(list(ca.glob('*.key'))),
                  'server_signing_key_files': len(list(renewal.glob('sign-*.key')))}
    elif args.operation == "prepare":
        result = prepare(vault, ca, renewal)
        result["custody"] = {"uid": os.getuid(), "interfaces": sorted(p.name for p in Path("/sys/class/net").iterdir()),
            "vault_mode": (vault / "password").stat().st_mode & 0o777,
            "docker_socket": Path("/var/run/docker.sock").exists()}
    elif args.operation == "finish":
        result = finish(vault, ca, renewal, json.load(sys.stdin))
    elif args.operation == "install":
        request = json.load(sys.stdin)
        state = json.loads((vault / "state.json").read_bytes())
        plan = state["pending"]
        if request["phase"] not in {"overlap", "final"}:
            raise LifecycleError("authority_ca_install_phase")
        target = plan["overlap_ca" if request["phase"] == "overlap" else "final_ca"]
        current_ca = json.loads((ca / "ca.json").read_bytes())
        if current_ca not in [plan["before_ca"], plan["overlap_ca"], plan["final_ca"]]:
            raise LifecycleError("authority_ca_configuration_conflict")
        save(ca / "ca.json", target)
        result = {"installed": True}
    elif args.operation == "old-probes":
        state = json.loads((vault / "state.json").read_bytes())
        bundle = unseal((vault / state["bundle"]).read_bytes(), (vault / "password").read_bytes())
        probes = []
        for provider in bundle["providers"]:
            name = json.loads(provider["options"]["x509"]["template"])["subject"]["commonName"]
            key = ec.generate_private_key(ec.SECP256R1())
            csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
                .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
            probes.append({"csr": csr, "ott": bootstrap_token(provider, load_key(bundle["keys"][provider["name"]]), csr, seconds=60), "notAfter": "20m"})
        save(Path("/controller/authority-old-probes.json"), probes)
        result = {"staged": len(probes)}
    else:
        request = json.load(sys.stdin)
        state = json.loads((vault / "state.json").read_bytes())
        bundle = unseal((vault / f"authority-g{state['pending']['epoch']}.sealed").read_bytes(), (vault / "password").read_bytes())
        provider = next(p for p in bundle["providers"] if p["name"] == request["provisioner"])
        csr = x509.load_pem_x509_csr(request["csr"].encode())
        template = json.loads(provider["options"]["x509"]["template"])
        if not csr.is_signature_valid or csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != template["subject"]["commonName"]:
            raise LifecycleError("authority_probe_scope")
        token = bootstrap_token(provider, load_key(bundle["keys"][provider["name"]]), request["csr"], seconds=60)
        save(Path("/controller/authority-probe.json"), {"csr": request["csr"], "ott": token, "notAfter": "20m"})
        result = {"staged": True}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
