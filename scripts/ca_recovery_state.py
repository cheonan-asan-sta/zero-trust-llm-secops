"""Local CA TCP admission journal, encrypted security checkpoint and backup format.

Gateways preserve end-to-end TLS. Only their isolated backend network can reach
the CA listeners; the journal is outside both service-host failure domains.
"""

import argparse
import base64
import contextlib
import hashlib
import json
import os
import secrets
import selectors
import socket
import socketserver
import sys
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scripts.certificate_controller import LifecycleError
from scripts.certificate_controller import atomic as replace_file

TABLES = ("used_ott", "revoked_x509_certs", "x509_certs", "x509_certs_data")
DIRECTORY = Path("/witness")


def atomic(path, body):
    replace_file(path, body)
    if os.name != "nt":
        descriptor = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def save(path, value):
    atomic(path, json.dumps(value, sort_keys=True))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sealed(value, key, manifest):
    nonce = secrets.token_bytes(12)
    return {"schema": "ca-recovery-sealed-1", "manifest": manifest, "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(AESGCM(key).encrypt(nonce, canonical(value), canonical(manifest))).decode()}


def opened(envelope, key):
    try:
        if envelope["schema"] != "ca-recovery-sealed-1" or len(envelope["ciphertext"]) > 128 * 1024**2:
            raise ValueError
        raw = AESGCM(key).decrypt(base64.b64decode(envelope["nonce"], validate=True),
            base64.b64decode(envelope["ciphertext"], validate=True), canonical(envelope["manifest"]))
        return json.loads(raw)
    except (InvalidTag, ValueError, KeyError, TypeError):
        raise LifecycleError("recovery_authentication_failed") from None


@contextlib.contextmanager
def locked(directory):
    with (directory / "journal.lock").open("a+b") as stream:
        if os.name == "nt":
            import msvcrt
            stream.seek(0)
            if not stream.read(1):
                stream.write(b"0"); stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def state(directory):
    return json.loads((directory / "state.json").read_bytes())


def validate_rows(tables):
    if set(tables) != set(TABLES):
        raise LifecycleError("recovery_security_table_scope")
    for rows in tables.values():
        if not isinstance(rows, list) or len(rows) > 100000:
            raise LifecycleError("recovery_row_limit")
        keys = set()
        for row in rows:
            if not isinstance(row, list) or len(row) != 2:
                raise LifecycleError("recovery_row_shape")
            try:
                key, value = [bytes.fromhex(part) for part in row]
            except (ValueError, TypeError):
                raise LifecycleError("recovery_row_encoding") from None
            if not key or len(key) > 255 or len(value) > 131072 or row[0] in keys:
                raise LifecycleError("recovery_row_identity")
            keys.add(row[0])


def snapshot(dsn):
    import psycopg
    try:
        with psycopg.connect(dsn, connect_timeout=2, options="-c statement_timeout=3000") as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            result = {name: [[bytes(k).hex(), bytes(v).hex()] for k, v in
                connection.execute('SELECT nkey,nvalue FROM "' + name + '" ORDER BY nkey')] for name in TABLES}
            lsn = str(connection.execute("SELECT pg_current_wal_lsn()").fetchone()[0])
    except psycopg.Error:
        raise LifecycleError("recovery_checkpoint_database_unavailable") from None
    validate_rows(result)
    return {"tables": result, "lsn": lsn, "sha256": digest(result)}


def checkpoint(directory):
    s = state(directory)
    if s["pending"]:
        raise LifecycleError("recovery_connections_pending")
    config = json.loads((directory / "config.json").read_bytes())
    data = snapshot(config["dsn"])
    manifest = {"sequence": s["sequence"], "authority": s["authority"], "incarnation": s["incarnation"],
        "lsn": data["lsn"], "sha256": data["sha256"]}
    name = f"security-{s['sequence']}-{secrets.token_hex(6)}.sealed"
    save(directory / name, sealed(data, (directory / "security.key").read_bytes(), manifest))
    s.update(checkpoint=name, checkpoint_sequence=s["sequence"], checkpoint_hash=data["sha256"], checkpoint_lsn=data["lsn"], error=None)
    save(directory / "state.json", s)
    return manifest


def begin(directory, node):
    with locked(directory):
        s = state(directory)
        if s["frozen"] or node not in s["enabled"]:
            raise LifecycleError("recovery_admission_closed")
        token = secrets.token_hex(16)
        s["sequence"] += 1
        s["pending"][token] = {"node": node, "at": time.time()}
        save(directory / "state.json", s)  # Intent is durable before any TLS byte reaches CA.
        return token


def finish(directory, token):
    with locked(directory):
        s = state(directory)
        if token not in s["pending"]:
            raise LifecycleError("recovery_unknown_connection")
        del s["pending"][token]
        save(directory / "state.json", s)
        if not s["pending"]:
            try:
                checkpoint(directory)
            except (OSError, ValueError):
                s = state(directory)
                s["error"] = "security_checkpoint_unavailable"
                save(directory / "state.json", s)


def freeze(directory):
    with locked(directory):
        s = state(directory)
        s["frozen"] = True
        save(directory / "state.json", s)
        if s["pending"]:
            raise LifecycleError("recovery_connections_pending")
        return s


def verify_restore(envelope, backup_key, witness, security_envelope, security_key):
    backup = opened(envelope, backup_key)
    security = opened(security_envelope, security_key)
    m = envelope["manifest"]
    sm = security_envelope["manifest"]
    if (not witness["frozen"] or witness["pending"] or witness["checkpoint_sequence"] != witness["sequence"]
            or witness.get("settled_sequence", -1) != witness["sequence"]
            or m["authority"] != witness["authority"] or m["incarnation"] != witness["incarnation"]
            or sm["authority"] != witness["authority"] or sm["incarnation"] != witness["incarnation"]
            or sm["sequence"] != witness["sequence"] or m["sequence"] > sm["sequence"]
            or sm["sha256"] != digest(security["tables"]) or witness["checkpoint_hash"] != sm["sha256"]):
        raise LifecycleError("recovery_restore_barrier")
    validate_rows(security["tables"])
    if hashlib.sha256(base64.b64decode(backup["database"], validate=True)).hexdigest() != m["database_sha256"]:
        raise LifecycleError("recovery_database_digest")
    return backup, security


def replay_sql(tables):
    validate_rows(tables)
    statements = ["BEGIN;"]
    for table in TABLES:
        statements.append('DELETE FROM "' + table + '";')
        for key, value in tables[table]:
            statements.append(f'INSERT INTO "{table}"(nkey,nvalue) VALUES(decode(\'{key}\',\'hex\'),decode(\'{value}\',\'hex\'));')
    statements.append("COMMIT;")
    return "\n".join(statements)


def asset_tree(root):
    result = {}
    for path in sorted(root.iterdir()):
        if root.name == "ca" and path.name == "db" and path.is_dir() and not path.is_symlink():
            continue  # Unused initial Badger directory; the supported DB is pg_dump.
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024**2:
            raise LifecycleError("recovery_asset_scope")
        result[path.name] = base64.b64encode(path.read_bytes()).decode()
    return result


def backup_job(request):
    """Network-none job. Only sealed archives persist; private stdout is a pipe."""
    backup_root, key_root = Path("/backups"), Path("/backup-key")
    name = request["name"]
    import re
    if not re.fullmatch(r"backup-[a-z0-9-]{1,70}\.sealed", name):
        raise LifecycleError("recovery_backup_name")
    key_path = key_root / "key"
    if request["operation"] == "backup":
        if not key_path.exists():
            atomic(key_path, secrets.token_bytes(32))
        witness = state(DIRECTORY)
        if (not witness["frozen"] or witness["pending"] or witness["checkpoint_sequence"] != witness["sequence"]
                or witness.get("settled_sequence", -1) != witness["sequence"]):
            raise LifecycleError("recovery_backup_not_quiescent")
        raw = base64.b64decode(request["database"], validate=True)
        if len(raw) > 64 * 1024**2:
            raise LifecycleError("recovery_backup_size")
        manifest = {"sequence": witness["sequence"], "authority": witness["authority"], "incarnation": witness["incarnation"],
            "database_sha256": hashlib.sha256(raw).hexdigest(), "checkpoint_hash": witness["checkpoint_hash"], "created_at": time.time()}
        folders = {name: asset_tree(Path("/" + name)) for name in ["ca", "vault", "renewal", "controller"]}
        body = {"database": request["database"], "node_tls": request["node_tls"], "folders": folders}
        document = sealed(body, key_path.read_bytes(), manifest)
        save(backup_root / name, document)
        return {"name": name, "manifest": manifest, "ciphertext_sha256": digest(document)}
    envelope = json.loads((backup_root / name).read_bytes())
    witness = state(DIRECTORY)
    if not witness["checkpoint"]:
        raise LifecycleError("recovery_checkpoint_missing")
    security_envelope = json.loads((DIRECTORY / witness["checkpoint"]).read_bytes())
    backup, security = verify_restore(envelope, key_path.read_bytes(), witness, security_envelope, (DIRECTORY / "security.key").read_bytes())
    # Validate encrypted offline key state against the current public CA config.
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from scripts.authority_custodian import load_key, public_jwk, unseal
    files = {n: base64.b64decode(v) for n, v in backup["folders"]["ca"].items()}
    config = json.loads(files["ca.json"])
    if hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest() != witness["authority"]:
        raise LifecycleError("recovery_authority_config_mismatch")
    issuer = x509.load_pem_x509_certificate(files[Path(config["crt"]).name])
    key = serialization.load_pem_private_key(files[Path(config["key"]).name], password=files["password.txt"])
    if public_jwk(issuer.public_key()) != public_jwk(key.public_key()):
        raise LifecycleError("recovery_issuer_key_mismatch")
    vault = {n: base64.b64decode(v) for n, v in backup["folders"]["vault"].items()}
    vault_state = json.loads(vault["state.json"])
    bundle = unseal(vault[vault_state["bundle"]], vault["password"])
    root_cert = x509.load_pem_x509_certificate(bundle["root"].encode())
    if (public_jwk(root_cert.public_key()) != public_jwk(load_key(bundle["root_key"]).public_key())
            or public_jwk(issuer.public_key()) != public_jwk(load_key(bundle["issuer_key"]).public_key())
            or bundle["providers"] != config["authority"]["provisioners"]):
        raise LifecycleError("recovery_offline_key_mismatch")
    from datetime import UTC, datetime
    if any(not cert.not_valid_before_utc <= datetime.now(UTC) < cert.not_valid_after_utc for cert in [root_cert, issuer]):
        raise LifecycleError("recovery_expired_authority")
    for provider in config["authority"]["provisioners"]:
        if public_jwk(load_key(bundle["keys"][provider["name"]]).public_key()) != provider["key"]:
            raise LifecycleError("recovery_jwk_key_mismatch")
    return {"backup": backup, "security": security, "manifest": envelope["manifest"], "replay_sql": replay_sql(security["tables"])}


class Gateway(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        token = None
        try:
            token = begin(DIRECTORY, self.server.node)
            with socket.create_connection((self.server.backend, 9000), timeout=2) as remote:
                self.request.setblocking(False)
                remote.setblocking(False)
                with selectors.DefaultSelector() as selector:
                    selector.register(self.request, selectors.EVENT_READ, remote)
                    selector.register(remote, selectors.EVENT_READ, self.request)
                    last = time.monotonic()
                    while time.monotonic() - last < 15:
                        for key, _ in selector.select(.3):
                            data = key.fileobj.recv(65536)
                            if not data:
                                return
                            key.data.setblocking(True)
                            key.data.settimeout(3)
                            key.data.sendall(data)
                            key.data.setblocking(False)
                            last = time.monotonic()
        except (OSError, ValueError):
            pass
        finally:
            if token is not None:
                with contextlib.suppress(OSError, ValueError):
                    finish(DIRECTORY, token)


def dispatch(request, directory=DIRECTORY):
    operation = request["operation"]
    if operation == "status":
        s = state(directory)
        return {k: s[k] for k in ["sequence", "checkpoint_sequence", "checkpoint_hash", "checkpoint_lsn",
            "authority", "incarnation", "frozen", "enabled", "error"]} | {"pending": len(s["pending"]), "settled_sequence": s.get("settled_sequence", -1)}
    if operation == "freeze":
        freeze(directory)
        return {"frozen": True}
    with locked(directory):
        s = state(directory)
        if operation == "checkpoint":
            return checkpoint(directory)
        if operation == "settle":
            if not request.get("verified_writers_stopped") or not s["frozen"] or s["pending"]:
                raise LifecycleError("recovery_writer_stop_required")
            result = checkpoint(directory)
            s = state(directory)
            s["settled_sequence"] = s["sequence"]
            save(directory / "state.json", s)
            return result
        if operation == "unfreeze":
            if s["pending"] or s["checkpoint_sequence"] != s["sequence"]:
                raise LifecycleError("recovery_checkpoint_required")
            s["frozen"] = False
        elif operation == "fence":
            # Host coordinator supplies/retains the independently checked Docker
            # stop receipt. This trusted operation is never a listening API.
            if not request.get("verified_stopped"):
                raise LifecycleError("recovery_fence_required")
            node = request["node"]
            s["enabled"] = [n for n in s["enabled"] if n != node]
            s["pending"] = {k: v for k, v in s["pending"].items() if v["node"] != node}
        elif operation in {"authority", "adopt", "enable"}:
            if not s["frozen"] or s["pending"]:
                raise LifecycleError("recovery_requires_quiescence")
            if operation == "authority":
                s["authority"] = request["authority"]
            elif operation == "adopt":
                s["incarnation"] = request["incarnation"]
                s["restore_generation"] = s.get("restore_generation", 0) + 1
            else:
                s["enabled"] = sorted(set(s["enabled"] + [request["node"]]))
        else:
            raise LifecycleError("recovery_operation")
        save(directory / "state.json", s)
        return {"updated": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["gateway", "rpc", "backup-job"])
    parser.add_argument("--node", choices=["a", "b"])
    parser.add_argument("--backend")
    args = parser.parse_args()
    if args.mode == "backup-job":
        print(json.dumps(backup_job(json.load(sys.stdin))))
    elif args.mode == "rpc":
        print(json.dumps(dispatch(json.load(sys.stdin))))
    else:
        with Gateway(("0.0.0.0", 9000), Handler) as server:
            server.node, server.backend = args.node, args.backend
            server.serve_forever()


if __name__ == "__main__":
    main()
