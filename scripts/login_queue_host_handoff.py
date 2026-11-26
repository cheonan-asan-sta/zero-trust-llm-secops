"""Move a quiesced login queue to a prepared Linux standby after retiring its source."""

import argparse
import json
import os
import re
from pathlib import Path
from time import time
from uuid import uuid4

from pydantic import Field

from app.models import StrictModel
from scripts import login_queue_activation as activation
from scripts import login_queue_backup as backup
from scripts.f1_lab.capture_backup import fresh_file, pinned, private_directory, private_file, sha


class Handoff(StrictModel):
    generation: int = Field(strict=True, ge=1, lt=2**63 - 1)
    standby_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    approval_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    package_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    origin: str = Field(min_length=1, max_length=512)
    tenant_id: str = Field(pattern=r"^[a-zA-Z0-9._-]{1,64}$")
    collector_subject: str = Field(min_length=1, max_length=128)
    retired_uid: int = Field(strict=True, ge=0)
    retired_at: int = Field(strict=True, gt=0)

    def scope(self):
        return self.model_dump(include={"origin", "tenant_id", "collector_subject"})


def prepare(root):
    root = private_directory(root)
    with activation._private_fd(root / "active.lock", create=True):
        pass
    with activation._lock(root, "active.lock"):
        if activation._present(root / "selection.sqlite3"):
            with activation._state(root) as con:
                if con.execute("SELECT 1 FROM sqlite_master WHERE name = 'generation'").fetchone():
                    raise activation.ActivationConflict("A selected host cannot be prepared as standby")
        marker = root / "standby-id"
        if not activation._present(marker):
            fresh_file(marker, uuid4().hex.encode())
        return private_file(marker, 32).decode("ascii")


def retire(root, identifier, package, key, standby_id):
    root = private_directory(root)
    if not re.fullmatch(r"[a-f0-9]{32}", standby_id):
        raise ValueError("Invalid prepared standby ID")
    with activation._lock(root, "active.lock"), activation._state(root, write=True) as con:
        current, approval, candidate, _ = activation._approved_candidate(con, identifier)
        scope = activation._scope(con)
        backup.verify_candidate(package, approval["package_sha256"], candidate, key, **scope)
        activation._predecessor(root, current, candidate, allow_missing=False)
        receipt = Handoff(
            generation=current["number"], standby_id=standby_id, approval_id=identifier,
            package_sha256=approval["package_sha256"], retired_uid=os.geteuid(),
            retired_at=int(time()), **scope,
        )
        activation._record_handoff(con, "outgoing", receipt.model_dump())


def publish(root, output):
    with activation._state(private_directory(root)) as con:
        entry = activation._handoff(con)
        if entry is None or entry["direction"] != "outgoing":
            raise activation.ActivationConflict("No committed source retirement to publish")
        receipt = Handoff.model_validate(entry["receipt"])
    raw = receipt.model_dump_json().encode() + b"\n"
    fresh_file(output, raw)
    return sha(raw)


def receive(root, receipt_path, receipt_pin, package, key, candidate):
    root = private_directory(root)
    receipt = Handoff.model_validate_json(pinned(receipt_path, receipt_pin, 4096))
    if private_file(root / "standby-id", 32) != receipt.standby_id.encode():
        raise activation.ActivationConflict("The receipt names a different prepared standby")
    candidate = private_directory(candidate)
    backup.verify_candidate(package, receipt.package_sha256, candidate, key, **receipt.scope())
    activation.initialize(root, candidate / backup.QUEUE, candidate / backup.AUDIT,
                          handoff=receipt.model_dump(), **receipt.scope())
    return receipt.generation + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("control", type=Path)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("prepare")
    retire_command = commands.add_parser("retire")
    retire_command.add_argument("approval")
    retire_command.add_argument("standby_id")
    publish_command = commands.add_parser("publish")
    publish_command.add_argument("output", type=Path)
    receive_command = commands.add_parser("receive")
    receive_command.add_argument("receipt", type=Path)
    receive_command.add_argument("receipt_pin")
    receive_command.add_argument("candidate", type=Path)
    for command in (retire_command, receive_command):
        command.add_argument("package", type=Path)
        command.add_argument("--key-file", type=Path, required=True)
    args = parser.parse_args()
    root = args.control
    if args.action == "prepare":
        result = {"standby_id": prepare(root)}
    elif args.action == "retire":
        retire(root, args.approval, args.package, args.key_file, args.standby_id)
        result = {"retired": True}
    elif args.action == "publish":
        result = {"receipt_sha256": publish(root, args.output)}
    else:
        result = {"generation": receive(root, args.receipt, args.receipt_pin, args.package, args.key_file, args.candidate)}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
