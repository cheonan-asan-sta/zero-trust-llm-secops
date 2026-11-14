"""Collect current Linux service evidence with a collector-only key on stdin."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts.f1_lab.collector_security import current_security_status
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_collector import (
    collect_current_systemd,
    collect_latest_systemd,
)
from scripts.f1_lab.shared_execution_evidence import PinnedServiceRegistry
from scripts.f1_lab.systemd_credential_reader import read_systemd_key
from scripts.f1_lab.web_verified_context import public_bytes


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
    args = parser.parse_args()
    stage = "key_input"
    security = None
    try:
        secret = read_systemd_key() if args.systemd_credential else sys.stdin.buffer.read(33)
        require(len(secret) == 32, "service_collector_key_input")
        key = Ed25519PrivateKey.from_private_bytes(secret)
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        stage = "registry"
        registry = PinnedServiceRegistry(args.registry, args.registry_sha256).current(
            datetime.now(UTC)
        )
        stage = "signing_scope"
        authorities = [
            a
            for a in registry.authorities
            if (a.tenant_id, a.server_id, a.source_id, a.key_id, a.kind, a.mode)
            == (args.tenant, args.server, args.source, args.key_id, "runtime", "systemd")
        ]
        require(
            len(authorities) == 1
            and authorities[0].enabled
            and args.unit in authorities[0].units
            and public_bytes(authorities[0].public_key) == public,
            "service_collector_signing_scope",
        )
        stage = "collector_security"
        security = current_security_status()
        stage = "native_collection"
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
        stage = "output"
        output = Path(args.output)
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        body = (
            canonical(
                {
                    "schema": "zt-service-capture-1",
                    "event": event.model_dump(mode="json"),
                    "runtime_proof": proof.model_dump(mode="json"),
                    "authorization_proof_included": False,
                }
            )
            + b"\n"
        )
        fd = os.open(output / "capture.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
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
            "native_source_service_manager_unavailable", "native_source_service_manager_fields",
            "native_source_service_manager_binding", "native_source_service_manager_event_mismatch",
            "native_source_service_manager_changed", "native_source_service_process_changed_during_collection",
            "native_source_service_boot_id", "native_source_service_collection_bound",
            "native_source_service_proc_state", "native_source_service_proc_identity",
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
