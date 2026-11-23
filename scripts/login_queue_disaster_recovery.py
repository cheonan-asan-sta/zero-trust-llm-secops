"""Authorize recovery at a prepared standby using an independent fencing receipt."""

import argparse
import json
from pathlib import Path
from time import time
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field

from app.models import StrictModel
from app.services.audit_transfer import canonical
from scripts import login_queue_activation as activation
from scripts import login_queue_backup as backup
from scripts import login_queue_host_handoff as handoff
from scripts.f1_lab.capture_backup import fresh_file, pinned, private_directory, private_file, sha

AUTHORITY_PROFILE = "authority-profile.json"
PROFILE = "disaster-profile.json"
APPROVAL = "fenced-recovery.json"
SCHEMA = "zt-login-disaster-recovery-1"
MAX_EVIDENCE_AGE = 900
MAX_DOCUMENT = 8192


class Checkpoint(StrictModel):
    source_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")
    generation: int = Field(strict=True, ge=1, lt=2**63 - 1)
    package_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    origin: str = Field(min_length=1, max_length=512)
    tenant_id: str = Field(pattern=r"^[a-zA-Z0-9._-]{1,64}$")
    collector_subject: str = Field(min_length=1, max_length=128)

    def scope(self):
        return self.model_dump(include={"origin", "tenant_id", "collector_subject"})


class FenceConfirmation(StrictModel):
    source_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")
    method: Literal["power_inhibited", "hypervisor_disabled", "exact_instance_removed"]
    record_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,160}$")
    observed_at: int = Field(strict=True, gt=0)
    restart_inhibited: Literal[True]


class RecoveryProfile(StrictModel):
    checkpoint: Checkpoint
    authority_public_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class Decision(StrictModel):
    schema_version: Literal["zt-login-disaster-recovery-1"]
    checkpoint: Checkpoint
    confirmation: FenceConfirmation
    standby_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    issued_at: int = Field(strict=True, gt=0)


class Receipt(StrictModel):
    decision: Decision
    signature: str = Field(pattern=r"^[a-f0-9]{128}$")


def _message(decision):
    return SCHEMA.encode() + b"\0" + canonical(decision.model_dump())


def enroll_authority(root, checkpoint, authority_public_key_sha256):
    root = private_directory(root)
    profile = RecoveryProfile(checkpoint=checkpoint, authority_public_key_sha256=authority_public_key_sha256)
    fresh_file(root / AUTHORITY_PROFILE, canonical(profile.model_dump()))


def enroll_standby(root, checkpoint, authority_public_key_sha256):
    root = private_directory(root)
    profile = RecoveryProfile(checkpoint=checkpoint, authority_public_key_sha256=authority_public_key_sha256)
    standby_id = handoff.prepare(root)
    raw = canonical(profile.model_dump())
    with activation._lock(root, "active.lock"):
        if activation._present(root / "selection.sqlite3"):
            with activation._state(root) as con:
                if con.execute("SELECT 1 FROM sqlite_master WHERE name = 'generation'").fetchone():
                    raise activation.ActivationConflict("A selected host cannot be enrolled as standby")
        path = root / PROFILE
        if not activation._present(path):
            fresh_file(path, raw)
        if private_file(path, MAX_DOCUMENT) != raw:
            raise activation.ActivationConflict("Standby is already pinned to a different recovery checkpoint")
    return standby_id


def issue(root, signing_key, standby_id, confirmation):
    """Issue once after the off-host authority has verified a persistent fence."""
    root = private_directory(root)
    profile = RecoveryProfile.model_validate_json(private_file(root / AUTHORITY_PROFILE, MAX_DOCUMENT))
    checkpoint = profile.checkpoint
    now = int(time())
    if confirmation.source_id != checkpoint.source_id:
        raise activation.ActivationConflict("Fence identifies a different source")
    if not 0 <= now - confirmation.observed_at <= MAX_EVIDENCE_AGE:
        raise activation.ActivationConflict("Fence confirmation is outside the issue window")
    decision = Decision(schema_version=SCHEMA, checkpoint=checkpoint, confirmation=confirmation,
                        standby_id=standby_id, issued_at=now)
    key = Ed25519PrivateKey.from_private_bytes(private_file(signing_key, 32))
    if sha(key.public_key().public_bytes_raw()) != profile.authority_public_key_sha256:
        raise activation.ActivationConflict("Signing key does not match the authority enrollment")
    receipt = Receipt(decision=decision, signature=key.sign(_message(decision)).hex())
    # Exclusive publication is the authority's durable one-destination decision.
    fresh_file(root / APPROVAL, canonical(receipt.model_dump()))
    return sha(private_file(root / APPROVAL, MAX_DOCUMENT))


def verify_receipt(receipt_path, authority_public_key, profile, standby_id):
    key = Ed25519PublicKey.from_public_bytes(pinned(authority_public_key, profile.authority_public_key_sha256, 32))
    receipt_raw = private_file(receipt_path, MAX_DOCUMENT)
    receipt = Receipt.model_validate_json(receipt_raw)
    decision = receipt.decision
    try:
        key.verify(bytes.fromhex(receipt.signature), _message(decision))
    except InvalidSignature as error:
        raise activation.ActivationConflict("Fence receipt signature is invalid") from error
    if decision.checkpoint != profile.checkpoint or decision.confirmation.source_id != profile.checkpoint.source_id:
        raise activation.ActivationConflict("Fence receipt belongs to a different source checkpoint")
    if standby_id != decision.standby_id:
        raise activation.ActivationConflict("Fence receipt names a different standby")
    if not 0 <= decision.issued_at - decision.confirmation.observed_at <= MAX_EVIDENCE_AGE:
        raise activation.ActivationConflict("Fence receipt did not confirm a recent fence when issued")
    return decision, sha(receipt_raw)


def receive(root, receipt_path, authority_public_key, package, recovery_key, candidate):
    root = private_directory(root)
    profile = RecoveryProfile.model_validate_json(private_file(root / PROFILE, MAX_DOCUMENT))
    standby_id = private_file(root / "standby-id", 32).decode("ascii")
    decision, receipt_hash = verify_receipt(receipt_path, authority_public_key, profile, standby_id)
    checkpoint = profile.checkpoint
    candidate = private_directory(candidate)
    backup.verify_candidate(package, checkpoint.package_sha256, candidate, recovery_key, **checkpoint.scope())
    history = {
        **decision.model_dump(), "generation": checkpoint.generation, "receipt_sha256": receipt_hash,
        "authority_public_key_sha256": profile.authority_public_key_sha256,
    }
    activation.initialize(root, candidate / backup.QUEUE, candidate / backup.AUDIT, handoff=history,
                          fenced_recovery=True, **checkpoint.scope())
    return checkpoint.generation + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    commands = parser.add_subparsers(dest="action", required=True)
    authority = commands.add_parser("enroll-authority")
    standby = commands.add_parser("enroll-standby")
    for command in (authority, standby):
        command.add_argument("checkpoint", type=Path)
        command.add_argument("checkpoint_sha256")
        command.add_argument("authority_public_key_sha256")
    seal = commands.add_parser("issue")
    seal.add_argument("signing_key", type=Path)
    seal.add_argument("standby_id")
    seal.add_argument("confirmation", type=Path)
    seal.add_argument("confirmation_sha256")
    recover = commands.add_parser("receive")
    for name in ("receipt", "authority_public_key", "package", "recovery_key", "candidate"):
        recover.add_argument(name, type=Path)
    args = parser.parse_args()
    root = args.directory
    if args.action in ("enroll-authority", "enroll-standby"):
        checkpoint = Checkpoint.model_validate_json(pinned(args.checkpoint, args.checkpoint_sha256, MAX_DOCUMENT))
        if args.action == "enroll-authority":
            enroll_authority(root, checkpoint, args.authority_public_key_sha256)
            result = {"enrolled": True}
        else:
            result = {"standby_id": enroll_standby(root, checkpoint, args.authority_public_key_sha256)}
    elif args.action == "issue":
        confirmation = FenceConfirmation.model_validate_json(
            pinned(args.confirmation, args.confirmation_sha256, MAX_DOCUMENT),
        )
        result = {"receipt_sha256": issue(root, args.signing_key, args.standby_id, confirmation)}
    else:
        result = {"generation": receive(
            root, args.receipt, args.authority_public_key, args.package, args.recovery_key, args.candidate,
        )}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
