"""Worker for a fixed privileged oneshot unit; never expose as a public API."""

import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.f1_lab.exec_history import collect_owned_exec
from scripts.f1_lab.exec_history_launcher import private_read, private_write
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.service_caller_identity import ServiceRequest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    body = decode(private_read(args.directory / "request.json", 65536))
    require(set(body) == {"request", "argv", "source_id", "key_id"}, "exec_history_worker_input")
    key_dir = Path(os.environ["CREDENTIALS_DIRECTORY"])
    raw_key = private_read(key_dir / "runtime-key", 32)
    require(len(raw_key) == 32, "exec_history_worker_key")
    request = ServiceRequest.model_validate(body["request"])
    event, proof, status = collect_owned_exec(
        request,
        body["argv"],
        Ed25519PrivateKey.from_private_bytes(raw_key),
        source_id=body["source_id"],
        key_id=body["key_id"],
    )
    private_write(
        args.directory / "capture.json",
        canonical(
            {
                "request_sha256": request.authentication_nonce,
                "event": event.model_dump(mode="json"),
                "proof": proof.model_dump(mode="json"),
                "exit_code": status,
            }
        ),
    )


if __name__ == "__main__":
    main()
