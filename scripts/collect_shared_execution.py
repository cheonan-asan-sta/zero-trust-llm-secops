"""Collect current Linux service evidence with a collector-only key on stdin."""

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts.f1_lab.capture_store import capture_store_lock
from scripts.f1_lab.collector_freshness import (
    CollectorScope,
    atomic_capture,
    inspect_capture,
    runtime_authority,
)
from scripts.f1_lab.collector_security import current_security_status
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_collector import (
    collect_current_systemd,
    collect_latest_systemd,
)
from scripts.f1_lab.shared_execution_evidence import PinnedServiceRegistry, proof_bytes
from scripts.f1_lab.systemd_credential_reader import read_systemd_key


def collect_payload(args, key, phase=lambda _value: None, *, clock=lambda: datetime.now(UTC)):
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    scope = CollectorScope(
        tenant_id=args.tenant,
        server_id=args.server,
        unit=args.unit,
        source_id=args.source,
        key_id=args.key_id,
    )
    phase("registry")
    pinned = PinnedServiceRegistry(args.registry, args.registry_sha256)
    registry = pinned.current(clock())
    phase("signing_scope")
    runtime_authority(registry, scope, clock(), public_key=public)
    phase("collector_security")
    security = current_security_status()
    phase("native_collection")
    collect = (
        collect_current_systemd
        if args.collection_basis == "manager_snapshot"
        else collect_latest_systemd
    )
    event, proof = collect(
        args.unit,
        key,
        tenant_id=args.tenant,
        server_id=args.server,
        source_id=args.source,
        key_id=args.key_id,
    )
    phase("post_collection_trust")
    now = clock()
    current = pinned.current(now)
    require(current == registry, "collector_registry_changed")
    authority = runtime_authority(current, scope, now, public_key=public)
    # Never issue a proof whose validity extends beyond its signing authority.
    if proof.expires_at > authority.expires_at:
        proof = proof.model_copy(update={"expires_at": authority.expires_at})
        proof = proof.model_copy(
            update={
                "signature": base64.urlsafe_b64encode(key.sign(proof_bytes(proof)))
                .decode()
                .rstrip("=")
            }
        )
    payload = {
        "schema": "zt-service-capture-1",
        "event": event.model_dump(mode="json"),
        "runtime_proof": proof.model_dump(mode="json"),
        "authorization_proof_included": False,
    }
    require(
        inspect_capture(payload, scope, pinned, now=clock()).state == "fresh",
        "collector_fresh_capture_required",
    )
    return payload, security


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "tenant",
        "server",
        "unit",
        "source",
        "key-id",
        "registry",
        "registry-sha256",
        "output",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument(
        "--collection-basis",
        choices=["manager_snapshot", "native_journal"],
        default="manager_snapshot",
    )
    parser.add_argument(
        "--systemd-credential",
        action="store_true",
        help="Read the system manager's runtime-key credential; no stdin fallback",
    )
    parser.add_argument(
        "--latest", type=Path, help="Atomically publish the signed capture to a trusted latest file"
    )
    args = parser.parse_args()
    stage = "key_input"
    security = None
    try:
        secret = read_systemd_key() if args.systemd_credential else sys.stdin.buffer.read(33)
        require(len(secret) == 32, "service_collector_key_input")
        key = Ed25519PrivateKey.from_private_bytes(secret)

        def phase(value):
            nonlocal stage
            stage = value

        payload, security = collect_payload(args, key, phase)
        stage = "output"
        output = Path(args.output)
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        body = canonical(payload) + b"\n"
        managed = (
            args.latest is not None and args.latest.parent.resolve() == output.parent.resolve()
        )
        with capture_store_lock(output.parent) if managed else nullcontext():
            if managed:
                stage = "publication_trust"
                scope = CollectorScope(
                    tenant_id=args.tenant,
                    server_id=args.server,
                    unit=args.unit,
                    source_id=args.source,
                    key_id=args.key_id,
                )
                require(
                    inspect_capture(
                        payload, scope, PinnedServiceRegistry(args.registry, args.registry_sha256)
                    ).state
                    == "fresh",
                    "collector_publication_freshness",
                )
            stage = "output"
            atomic_capture(output / "capture.json", body)
            if args.latest is not None:
                atomic_capture(args.latest, body)
        print(
            json.dumps(
                {
                    "completed": True,
                    "capture_sha256": hashlib.sha256(body).hexdigest(),
                    "command_plaintext_persisted": False,
                    "private_key_persisted": False,
                    "collector_security": security,
                }
            )
        )
    except (ValueError, TypeError, OSError, OverflowError, subprocess.SubprocessError) as error:
        public_codes = {
            "native_source_service_manager_unavailable",
            "native_source_service_manager_fields",
            "native_source_service_manager_binding",
            "native_source_service_manager_event_mismatch",
            "native_source_service_manager_changed",
            "native_source_service_process_changed_during_collection",
            "native_source_service_boot_id",
            "native_source_service_collection_bound",
            "native_source_service_proc_state",
            "native_source_service_proc_identity",
            "native_source_service_capture_window",
        }
        code = str(error) if type(error) is ValueError and str(error) in public_codes else None
        print(
            json.dumps(
                {
                    "completed": False,
                    "failure_type": type(error).__name__,
                    "failure_stage": stage,
                    "failure_code": code,
                    "collector_security": security,
                    "execution_evidence_available": False,
                }
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
