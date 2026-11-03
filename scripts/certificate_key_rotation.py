"""Opt-in leaf rekey: immutable pairs, journaled profile/config switches and cleanup.

Private PEM is confined to managed Linux volumes, never the JSON journal/status.
CA and delegated JWK signing keys are deliberately outside this leaf rotation.
"""

import hashlib
import json
import secrets
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from scripts import certificate_controller as lifecycle


def public_hash(public_key):
    return hashlib.sha256(public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def prepare_key(c, cfg, state, state_dir):
    if c["not_after"] <= time.time() or c.get("inhibited") or c["id"] in cfg.get("disabled", []):
        raise lifecycle.LifecycleError("rekey_identity_unavailable")
    if not c.get("assets"):
        raise lifecycle.LifecycleError("rekey_inventory_upgrade_required")
    old = x509.load_pem_x509_certificate(c["current"].encode())
    for asset in c["assets"]:
        cfg["scoped"](asset["cert"])
        cfg["scoped"](asset["key"])
        if (lifecycle.fingerprint(Path(asset["cert"]).read_text()) != c["fingerprint"]
                or public_hash(serialization.load_pem_private_key(Path(asset["key"]).read_bytes(), password=None).public_key())
                != public_hash(old.public_key())):
            raise lifecycle.LifecycleError("active_asset_changed")
    if not c.get("pending_key"):
        stem = c["name"] + "-r" + secrets.token_hex(12)
        assets = [{"cert": str(Path(a["cert"]).parent / (stem + ".pem")),
                   "key": str(Path(a["key"]).parent / (stem + ".key"))} for a in c["assets"]]
        c["pending_key"] = {"key": assets[0]["key"], "assets": assets}
        # Record every intended private-file name before any private byte is written.
        lifecycle.save(state_dir / "state.json", state)
    pending = c["pending_key"]
    assets = pending["assets"]
    for asset in assets:
        for value in asset.values():
            cfg["scoped"](value)
    first = Path(pending["key"])
    key = (serialization.load_pem_private_key(first.read_bytes(), password=None) if first.exists()
           else ec.generate_private_key(ec.SECP256R1()))
    if public_hash(key.public_key()) == public_hash(old.public_key()):
        raise lifecycle.LifecycleError("rekey_requires_new_key")
    # Generate once per root; several profiles/volumes may share an identity.
    for asset in assets:
        lifecycle.atomic(asset["key"], key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    csr = (x509.CertificateSigningRequestBuilder().subject_name(old.subject)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(c["name"])]), critical=False)
        .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
    pending.update(csr=csr, public_key_sha256=public_hash(key.public_key()))


def request_certificate(c, state, cfg, state_dir):
    if c["not_after"] <= time.time():
        raise lifecycle.LifecycleError("expired_rekey_denied")
    pending = c["pending_key"]
    if c["purpose"] == "serverAuth":
        new = lifecycle.server_reissue(c | {"csr": pending["csr"]}, state, cfg, state_dir)
    else:
        code, response = lifecycle.ca_post(state_dir, "/1.0/rekey", {"csr": pending["csr"]}, identity=c)
        if code != 201:
            raise lifecycle.LifecycleError("rekey_denied")
        new = lifecycle.issued_chain(response)
    key = serialization.load_pem_private_key(Path(pending["key"]).read_bytes(), password=None)
    lifecycle.validate_candidate(c["current"], new, (state_dir / "issuer.pem").read_text(), key)
    if public_hash(x509.load_pem_x509_certificate(new.encode()).public_key()) == public_hash(
            x509.load_pem_x509_certificate(c["current"].encode()).public_key()):
        raise lifecycle.LifecycleError("rekey_requires_new_key")
    for asset in pending["assets"]:
        lifecycle.atomic(asset["cert"], new)
    return new


def plan_rotation(cfg, state, identifiers):
    # Reuse the ordinary role/pin retirement checks, without recursing into here.
    shadows = {uid: {k: v for k, v in c.items() if k != "pending_key"}
               for uid, c in state["credentials"].items()}
    try:
        base = lifecycle.plan(cfg, state | {"credentials": shadows}, identifiers)
    except lifecycle.LifecycleError:
        for uid, shadow in shadows.items():
            if shadow.get("inhibited"):
                state["credentials"][uid].update(inhibited=True, status=shadow["status"])
        raise
    replacements = {}
    retired = []
    for uid in identifiers:
        c = state["credentials"][uid]
        if not c.get("pending_key"):
            raise lifecycle.LifecycleError("mixed_key_publication")
        for old, new in zip(c["assets"], c["pending_key"]["assets"], strict=True):
            for field in ["cert", "key"]:
                replacements[old[field]] = new[field]
            retired.append({"cert": old["cert"], "key": old["key"], "fingerprint": c["fingerprint"],
                            "purpose": c["purpose"], "serial": c["serial"], "not_after": c["not_after"],
                            "public_key_sha256": public_hash(x509.load_pem_x509_certificate(c["current"].encode()).public_key())})
    policies = {p["path"]: p for p in base["policies"]}
    for path in cfg["policies"]:
        before = json.loads(Path(path).read_bytes())
        policy = policies.get(path, {"path": path, "before": before, "staged": before, "committed": before})
        for phase in ["activated", "committed"]:
            document = json.loads(json.dumps(policy["staged"] if phase == "activated" else policy["committed"]))
            for field in ["cert", "key"]:
                old = str(Path(path).parent / document.get(field, ""))
                if old in replacements:
                    document[field] = Path(replacements[old]).name
            policy[phase] = document
        if policy["activated"] != before or policy["staged"] != before:
            policies[path] = policy
    files = []
    for path in cfg["key_rotation"].get("configuration_files", []):
        before = Path(path).read_text()
        after = before
        for old, new in replacements.items():
            if Path(old).parent == Path(path).parent:
                after = after.replace("/service-tls/" + Path(old).name, "/service-tls/" + Path(new).name)
        if after != before:
            files.append({"path": path, "before": before, "after": after})
    return base | {"kind": "key_rotation", "policies": list(policies.values()), "files": files,
                   "retired": retired}


def cas_text(path, before, after):
    current = Path(path).read_text()
    if current == after:
        return
    if current != before:
        raise lifecycle.LifecycleError("configuration_publication_conflict")
    lifecycle.atomic(path, after)


def publish_rotation(cfg, state, state_dir):
    txn = state["transaction"]
    if set(txn["credentials"]) & set(cfg.get("disabled", [])):
        raise lifecycle.LifecycleError("identity_disabled_during_publication")
    if txn["phase"] not in {"retiring", "revoking", "cleaning"}:
        for uid in txn["credentials"]:
            c = state["credentials"][uid]
            if lifecycle.metadata(c["candidate"])["not_after"] <= time.time():
                raise lifecycle.LifecycleError("candidate_expired_during_publication")
            pending = c["pending_key"]
            for asset in pending["assets"]:
                key = serialization.load_pem_private_key(Path(asset["key"]).read_bytes(), password=None)
                lifecycle.validate_candidate(c["current"], Path(asset["cert"]).read_text(),
                    (state_dir / "issuer.pem").read_text(), key)
                if lifecycle.fingerprint(Path(asset["cert"]).read_text()) != lifecycle.fingerprint(c["candidate"]):
                    raise lifecycle.LifecycleError("candidate_changed")
    if txn["phase"] == "prepared":
        for policy in txn["policies"]:
            lifecycle.cas(policy["path"], policy["before"], policy["staged"])
        txn["phase"] = "staged"
        lifecycle.save(state_dir / "state.json", state)
    if txn["phase"] == "staged":
        for policy in txn["policies"]:
            lifecycle.cas(policy["path"], policy["staged"], policy["activated"])
        for file in txn["files"]:
            cas_text(file["path"], file["before"], file["after"])
        txn.update(phase="activated", activated_at=time.time())
        lifecycle.save(state_dir / "state.json", state)
    if txn["phase"] == "activated":
        lifecycle.readiness(cfg, state, state_dir)
        if time.time() - txn["activated_at"] < cfg.get("overlap_seconds", 1):
            return
        txn["phase"] = "retiring"
        lifecycle.save(state_dir / "state.json", state)
    if txn["phase"] == "retiring":
        for policy in txn["policies"]:
            lifecycle.cas(policy["path"], policy["activated"], policy["committed"])
        for uid in txn["credentials"]:
            c = state["credentials"][uid]
            pending = c["pending_key"]
            c.update(lifecycle.metadata(c["candidate"]))
            c.update(current=c["candidate"], candidate=None, key=pending["key"], csr=pending["csr"],
                certificates=[a["cert"] for a in pending["assets"]], assets=pending["assets"],
                generation=c["generation"] + 1, key_generation=c.get("key_generation", 0) + 1,
                public_key_sha256=pending["public_key_sha256"], pending_key=None,
                authority_epoch=cfg.get("authority_epoch", 0),
                last_key_rotation=time.time(), status="active", failures=0, retry_at=0)
        txn.update(phase="revoking", committed_at=time.time())
        lifecycle.save(state_dir / "state.json", state)
    if txn["phase"] == "revoking":
        for old in txn["retired"]:
            if old["purpose"] != "clientAuth" or old.get("revoked"):
                continue
            if any(other["serial"] == old["serial"] and other.get("revoked") for other in txn["retired"]):
                old["revoked"] = True  # Several read-only service volumes can share a leaf.
            elif old["not_after"] <= time.time():
                old["revoked"] = "expired_no_reenrollment"
            else:
                identity = {"certificates": [old["cert"]], "key": old["key"]}
                code, response = lifecycle.ca_post(state_dir, "/1.0/revoke",
                    {"serial": old["serial"], "passive": True}, identity=identity)
                if code == 200 and response.get("status") == "ok":
                    old["revoked"] = True
                elif code == 403 and "already revoked" in response.get("message", "").lower():
                    old["revoked"] = True  # CA committed before a lost response/journal write.
                else:
                    raise lifecycle.LifecycleError("old_client_revocation_unconfirmed")
            lifecycle.save(state_dir / "state.json", state)
        txn["phase"] = "cleaning"
        lifecycle.save(state_dir / "state.json", state)
    if txn["phase"] == "cleaning":
        if time.time() - txn["committed_at"] < cfg["key_rotation"]["cleanup_grace_seconds"]:
            return
        for old in txn["retired"]:
            cert, key = cfg["scoped"](old["cert"]), cfg["scoped"](old["key"])
            if cert.exists() and lifecycle.fingerprint(cert.read_text()) != old["fingerprint"]:
                raise lifecycle.LifecycleError("retired_asset_changed")
            if key.exists() and public_hash(serialization.load_pem_private_key(key.read_bytes(), password=None).public_key()) != old["public_key_sha256"]:
                raise lifecycle.LifecycleError("retired_asset_changed")
            key.unlink(missing_ok=True)
            cert.unlink(missing_ok=True)
        state["transaction"] = None
        lifecycle.save(state_dir / "state.json", state)
