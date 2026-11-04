"""Trusted Docker-exec control bridge; no listening management API or CA keys."""

import json
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from scripts import certificate_controller as leaf
from scripts.authority_custodian import digest, verify_plan
from scripts.ca_endpoints import connect, endpoints

DIRECTORY = Path("/state")


def paused(cfg, state):
    if not cfg.get("paused") or not state.get("paused_ack") or state["transaction"]:
        raise leaf.LifecycleError("authority_requires_leaf_quiescence")


def active(cfg, state):
    return sorted(uid for uid, c in state["credentials"].items() if uid not in cfg.get("disabled", [])
                  and not c.get("inhibited") and c["not_after"] > time.time())


def trust_paths(cfg):
    return [DIRECTORY / "root.pem", *[Path(root) / "ca.pem" for root in cfg["roots"] if (Path(root) / "ca.pem").exists()]]


def migrated(plan, ledger, cfg, state):
    if sorted(ledger["identities"]) != active(cfg, state) or state["transaction"]:
        return False
    issuer = x509.load_pem_x509_certificate(plan["issuer"].encode())
    for uid in ledger["identities"]:
        c = state["credentials"][uid]
        if c.get("authority_epoch") != plan["epoch"]:
            return False
        try:
            x509.load_pem_x509_certificate(c["current"].encode()).verify_directly_issued_by(issuer)
        except (ValueError, TypeError):
            return False
    return True


def wire_ready(cfg, state, identifiers):
    shadows = {uid: c | {"candidate": c["current"]} for uid, c in state["credentials"].items()}
    shadow_state = state | {"credentials": shadows, "transaction": {"credentials": identifiers}, "server_observations": {}}
    leaf.readiness(cfg, shadow_state, DIRECTORY)
    return shadow_state["server_observations"]


def ca_health(plan):
    context = ssl.create_default_context(cafile=str(DIRECTORY / "root.pem"))
    hosts, _ = endpoints(DIRECTORY)
    observations = {}
    for host in hosts:
        connection, _ = connect(DIRECTORY, context, endpoint=host)
        try:
            certificate = x509.load_der_x509_certificate(connection.sock.getpeercert(binary_form=True))
            certificate.verify_directly_issued_by(x509.load_pem_x509_certificate(plan["issuer"].encode()))
            observations[host] = {"tls_version": connection.sock.version(), "issuer": leaf.fingerprint(plan["issuer"])}
        finally:
            connection.close()
    return observations["ca"] if hosts == ["ca"] else {"replicas": observations}


def dispatch(request):
    from scripts.control_mirror import guard
    guard()
    operation = request["operation"]
    cfg = leaf.config(DIRECTORY / "config.json")
    state = json.loads((DIRECTORY / "state.json").read_bytes())
    if operation == "pause":
        document = {k: v for k, v in cfg.items() if k != "scoped"}
        document["paused"] = request["value"]
        leaf.save(DIRECTORY / "config.json", document)
        return {"paused": bool(state.get("paused_ack") and not state["transaction"])}
    if operation == "status":
        return {"paused": bool(state.get("paused_ack") and not state["transaction"])}
    if operation == "endpoint_health":
        context = ssl.create_default_context(cafile=str(DIRECTORY / "root.pem"))
        connection, host = connect(DIRECTORY, context, endpoint=request["endpoint"])
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            if response.status != 200 or json.loads(response.read(4096)).get("status") != "ok":
                raise leaf.LifecycleError("authority_replica_unhealthy")
            return {"endpoint": host, "healthy": True}
        finally:
            connection.close()
    plan = request["plan"]
    ledger_path = DIRECTORY / "authority-transition.json"
    ledger = json.loads(ledger_path.read_bytes()) if ledger_path.exists() else None
    if operation == "stage":
        paused(cfg, state)
        replay = bool(ledger and ledger["plan_hash"] == digest(plan))
        root = ledger["trust"][0]["before"] if replay else (DIRECTORY / "root.pem").read_text()
        certificates = x509.load_pem_x509_certificates(root.encode())
        verify_plan(plan, certificates[0].public_bytes(serialization.Encoding.PEM).decode(),
                    epoch=cfg.get("authority_epoch", 0) + 1, previous=cfg.get("authority_manifest_hash"))
        allowed = {leaf.fingerprint(plan["old_root"]), leaf.fingerprint(plan["old_issuer"])}
        trust = ledger["trust"] if replay else []
        overlap = "".join(dict.fromkeys([plan["old_root"], plan["old_issuer"], plan["root"], plan["issuer"]]))
        for path in ([] if replay else trust_paths(cfg)):
            before = path.read_text()
            if not {c.fingerprint(hashes.SHA256()).hex()
                    for c in x509.load_pem_x509_certificates(before.encode())} <= allowed:
                raise leaf.LifecycleError("authority_unexpected_trust_anchor")
            trust.append({"path": str(path), "before": before, "overlap": overlap})
        ledger = ledger if replay else {"plan_hash": digest(plan), "identities": active(cfg, state), "trust": trust}
        if not ledger["identities"]:
            raise leaf.LifecycleError("authority_no_active_identities")
        leaf.save(ledger_path, ledger)  # Snapshot all expected public bundles before any publication.
        for asset in trust:
            if Path(asset["path"]).read_text() not in {asset["before"], asset["overlap"]}:
                raise leaf.LifecycleError("authority_trust_publication_conflict")
            leaf.atomic(asset["path"], asset["overlap"])
        return {"staged": True, "identities": len(ledger["identities"]), "trust_stores": len(trust)}
    if not ledger or ledger["plan_hash"] != digest(plan):
        raise leaf.LifecycleError("authority_transition_not_staged")
    if operation == "ready":
        paused(cfg, state)
        return {"servers": wire_ready(cfg, state, ledger["identities"])}
    if operation == "health":
        return ca_health(plan)
    if operation == "probe_csr":
        paused(cfg, state)
        c = next(c for c in state["credentials"].values() if c["name"] == "collector" and c["purpose"] == "clientAuth")
        return {"provisioner": "collector-clientAuth", "csr": c["csr"]}
    if operation == "probe":
        paused(cfg, state)
        payload_path = DIRECTORY / "authority-probe.json"
        try:
            options = {"endpoint": request["endpoint"]} if request.get("endpoint") else {}
            code, response = leaf.ca_post(DIRECTORY, "/1.0/sign", json.loads(payload_path.read_bytes()), **options)
            if code != 201:
                raise leaf.LifecycleError("new_jwk_issuance_denied")
            certificate = leaf.issued_chain(response)
            x509.load_pem_x509_certificate(certificate.encode()).verify_directly_issued_by(x509.load_pem_x509_certificate(plan["issuer"].encode()))
            if leaf.metadata(certificate)["name"] != "collector" or leaf.metadata(certificate)["purpose"] != "clientAuth":
                raise leaf.LifecycleError("authority_probe_identity")
            return {"issued": True}
        finally:
            leaf.remove_file(payload_path, missing_ok=True)
    if operation == "activate":
        if cfg.get("authority_epoch") == plan["epoch"]:
            return {"activated": True}
        paused(cfg, state)
        if cfg["server_signers"] != {name: "/managed/renewal/" + filename for name, filename in plan["old_signers"].items()}:
            raise leaf.LifecycleError("authority_signer_configuration_changed")
        leaf.atomic(DIRECTORY / "issuer.pem", plan["issuer"])
        document = {k: v for k, v in cfg.items() if k != "scoped"}
        document.update(server_signers={name: "/managed/renewal/" + filename for name, filename in plan["signers"].items()},
                        authority_epoch=plan["epoch"], paused=False)
        leaf.save(DIRECTORY / "config.json", document)
        return {"activated": True}
    if operation == "migration":
        return {"ready": migrated(plan, ledger, cfg, state), "identities": len(ledger["identities"])}
    if operation == "retire":
        paused(cfg, state)
        if not migrated(plan, ledger, cfg, state):
            raise leaf.LifecycleError("authority_migration_incomplete")
        wire_ready(cfg, state, ledger["identities"])
        final = plan["root"] + plan["issuer"]
        for asset in ledger["trust"]:
            path = Path(asset["path"])
            if path.read_text() not in {asset["overlap"], final}:
                raise leaf.LifecycleError("authority_trust_publication_conflict")
            leaf.atomic(path, final)
        return {"retired": True, "trust_stores": len(ledger["trust"])}
    if operation == "verify":
        paused(cfg, state)
        if not migrated(plan, ledger, cfg, state):
            raise leaf.LifecycleError("authority_migration_incomplete")
        return {"servers": wire_ready(cfg, state, ledger["identities"]), "identities": len(ledger["identities"])}
    if operation == "old_keys_denied":
        path = DIRECTORY / "authority-old-probes.json"
        try:
            requests = json.loads(path.read_bytes())
            options = {"endpoint": request["endpoint"]} if request.get("endpoint") else {}
            with ThreadPoolExecutor(max_workers=8) as pool:
                statuses = list(pool.map(lambda payload: leaf.ca_post(DIRECTORY, "/1.0/sign", payload, **options)[0], requests))
            if not statuses or any(code not in {401, 403} for code in statuses):
                raise leaf.LifecycleError("retired_jwk_still_authorized")
            return {"denied": len(statuses), "statuses": statuses}
        finally:
            leaf.remove_file(path, missing_ok=True)
    if operation == "finish":
        if cfg.get("authority_manifest_hash") == digest(plan):
            return {"finished": True}
        paused(cfg, state)
        document = {k: v for k, v in cfg.items() if k != "scoped"}
        document.update(authority_manifest_hash=digest(plan), paused=False)
        leaf.save(DIRECTORY / "config.json", document)
        return {"finished": True}
    raise leaf.LifecycleError("authority_operation")


def main():
    print(json.dumps(dispatch(json.load(sys.stdin))))


if __name__ == "__main__":
    main()
