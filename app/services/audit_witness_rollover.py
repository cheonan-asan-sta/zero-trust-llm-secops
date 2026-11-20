"""Operator-approved continuation of a full local audit witness generation."""

import os
import re
import shutil
import tempfile
from pathlib import Path

from app.services import audit_witness as witness
from app.services import audit_witness_observer as observer
from app.services.audit_transfer import (
    AuditTransferError,
    canonical,
    decode,
    fresh_stage,
    publish,
    require,
    sha,
)
from app.services.sqlite_audit import SQLiteAuditStore

SCHEMA = "local-witness-rollover-1"
CONTROL_ROOT = re.compile(r"\.witness-generation-[a-z0-9_]+")


def _reservation(profile):
    return Path(profile["witness_directory"]) / "rollover.approval"


def _proposal(old_control, old_profile, old_terminal, new_signer, new_key, destination):
    old_control, profile, public = observer._load(old_control, old_profile)
    with observer._database(old_control) as con:
        state = observer._read(con, profile, public, old_terminal)
    require(
        state["pending"] is None and state["receipt"] is not None
        and state["receipt_sha256"] == old_terminal
        and state["receipt"]["body"]["number"] == witness.MAX_RECEIPTS,
        "rollover requires the exact full, settled observer head",
    )
    old_signer = Path(profile["witness_directory"])
    old = witness.status(old_signer, profile["public_key_sha256"], minimum_receipt=old_terminal)
    require(old["receipt"] == state["receipt"], "rollover signer and observer disagree")

    destination = Path(destination).absolute()
    new_signer = witness._directory(new_signer)
    database = Path(profile["database"])
    observer._separate(old_control, new_signer, database)
    require(new_key != profile["public_key_sha256"], "rollover requires a fresh signing key")
    parent = destination.parent
    require(
        parent.is_dir() and not any(path.is_symlink() for path in (parent, *parent.parents)),
        "rollover requires an existing output parent without links",
    )
    for protected in (old_control, old_signer, new_signer, database):
        require(not parent.resolve().is_relative_to(protected.resolve())
                and not destination.resolve().is_relative_to(protected.resolve())
                and not protected.resolve().is_relative_to(destination.resolve()),
                "rollover output overlaps protected storage")
    require(not (new_signer.resolve().is_relative_to(old_signer.resolve())
                 or old_signer.resolve().is_relative_to(new_signer.resolve())),
            "rollover signers must be separate")

    _, new_public = witness._public(new_signer, new_key)
    with witness._journal(new_signer) as con:
        stream, locator, last, _, _ = witness._history(
            con, new_public, expected_receipt=witness.GENESIS, exact=False,
        )
    require(stream == profile["stream_id"] and locator == profile["source_locator_sha256"],
            "rollover target must use the same stream and audit source")
    proposal = {
        "schema": SCHEMA,
        "destination": str(destination),
        "old_control": str(old_control),
        "old_profile_sha256": old_profile,
        "old_terminal_receipt": state["receipt"],
        "old_terminal_sha256": old_terminal,
        "new_signer": str(new_signer),
        "new_key_sha256": new_key,
    }
    return proposal, profile, last


def plan(old_control, old_profile, old_terminal, new_signer, new_key, destination):
    proposal, profile, last = _proposal(
        old_control, old_profile, old_terminal, new_signer, new_key, destination,
    )
    reservation = _reservation(profile)
    require(last is None and not Path(destination).exists() and not Path(destination).is_symlink(),
            "rollover plan requires a fresh signer and output")
    require(not reservation.exists() and not reservation.is_symlink(),
            "previous generation already has a rollover reservation")
    body = proposal["old_terminal_receipt"]["body"]
    witness.inspect(
        profile["database"], proposal["old_terminal_receipt"],
        (Path(proposal["old_control"]) / "public.key").read_bytes(),
        public_key_sha256=profile["public_key_sha256"], stream_id=body["stream_id"],
        expected_receipt=old_terminal,
    )
    return {"proposal": proposal, "approval_sha256": sha(canonical(proposal))}


def _read_record(path):
    path = Path(path).absolute()
    # The atomic publisher may temporarily retain its private staging link,
    # including after abrupt process loss. The caller verifies the content pin.
    witness._file(path, 65536, links=(1, 2))
    raw = path.read_bytes()
    return raw, decode(raw)


def _require_reservation(path, approval):
    witness._file(path, 65, links=(1, 2))
    require(path.read_bytes() == (approval + "\n").encode("ascii"),
            "previous generation already reserved for another rollover")


def _reserve(path, approval):
    if not path.exists() and not path.is_symlink():
        try:
            with fresh_stage(path) as (stage, target):
                observer._write(stage, (approval + "\n").encode("ascii"))
                publish(stage, target)
        except (FileExistsError, AuditTransferError):
            if not path.exists():
                raise
    _require_reservation(path, approval)


def verify(destination, expected_sha256):
    """Read the linked generations using the operator's external record pin."""
    raw, record = _read_record(destination)
    require(witness._hex(expected_sha256) and sha(raw) == expected_sha256,
            "rollover record pin mismatch")
    proposal = record["proposal"]
    require(proposal["destination"] == str(Path(destination).absolute()),
            "rollover record destination mismatch")
    current, old_profile, _ = _proposal(
        proposal["old_control"], proposal["old_profile_sha256"],
        proposal["old_terminal_sha256"], proposal["new_signer"],
        proposal["new_key_sha256"], destination,
    )
    approval = sha(canonical(current))
    require(proposal == current and approval == record["approval_sha256"],
            "rollover proposal mismatch")
    _require_reservation(_reservation(old_profile), approval)
    root = record["control_root"]
    require(isinstance(root, str) and CONTROL_ROOT.fullmatch(root),
            "rollover control path rejected")
    parent = Path(destination).absolute().parent / root
    witness._directory(parent)
    control, profile, public = observer._load(parent / "control", record["profile_sha256"])
    old_body = current["old_terminal_receipt"]["body"]
    first = profile["bootstrap_receipt"]
    first_sha = record["minimum_receipt"]
    body = witness.verify_receipt(first, public, stream_id=old_profile["stream_id"],
                                  expected_receipt=first_sha)
    require(
        profile["bootstrap_sha256"] == first_sha and body["number"] == 1
        and body.get("observation_id") == approval[:32]
        and body["previous_receipt"] == witness.GENESIS
        and profile["witness_directory"] == current["new_signer"]
        and profile["public_key_sha256"] == current["new_key_sha256"]
        and all(profile[key] == old_profile[key] for key in (
            "database", "source_locator_sha256", "interval_seconds",
            "max_age_seconds", "capacity_warning",
        ))
        and observer._time(body["observed_at"]) >= observer._time(old_body["observed_at"]),
        "rollover bootstrap does not match approved lineage",
    )
    require(body["head"]["seq"] >= old_body["head"]["seq"],
            "rollover bootstrap predates the previous audit head")
    with observer._database(control) as con:
        observer._read(con, profile, public, first_sha)
    witness.status(current["new_signer"], current["new_key_sha256"], minimum_receipt=first_sha)
    store = SQLiteAuditStore.open_existing(profile["database"])
    with store._transaction() as con:
        witness._verified_head(store, con, old_body["head"])
        witness._verified_head(store, con, body["head"])
    return {
        "approval_sha256": approval,
        "record_sha256": expected_sha256,
        "directory": str(control),
        "profile_sha256": record["profile_sha256"],
        "minimum_receipt": first_sha,
    }


def _existing(destination, approval):
    raw, record = _read_record(destination)
    require(record["approval_sha256"] == approval, "rollover output belongs to another approval")
    return verify(destination, sha(raw))


def approve(old_control, old_profile, old_terminal, new_signer, new_key, destination, approval):
    proposal, profile, _ = _proposal(
        old_control, old_profile, old_terminal, new_signer, new_key, destination,
    )
    require(witness._hex(approval) and sha(canonical(proposal)) == approval,
            "explicit matching operator approval required")
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        return _existing(destination, approval)
    old_body = proposal["old_terminal_receipt"]["body"]
    _reserve(_reservation(profile), approval)
    # A retry can recover exactly this first committed signature after process loss.
    try:
        first = witness.observe(
            new_signer, profile["database"], new_key, expected_receipt=witness.GENESIS,
            observation_id=approval[:32], minimum_observed_at=old_body["observed_at"],
            initial_audit_head=old_body["head"],
        )
    except AuditTransferError:
        if not destination.exists():
            raise
        return _existing(destination, approval)
    require(first["receipt"]["body"]["number"] == 1, "rollover first receipt required")
    if destination.exists() or destination.is_symlink():
        return _existing(destination, approval)

    # The descriptor is the commit point. A private unique directory prevents
    # a concurrent retry from replacing any other observer's state.
    root = Path(tempfile.mkdtemp(prefix=".witness-generation-", dir=destination.parent))
    published = False
    try:
        new_profile = observer.initialize(
            root / "control", new_signer, profile["database"], new_key,
            expected_receipt=first["receipt_sha256"],
            interval_seconds=profile["interval_seconds"], max_age_seconds=profile["max_age_seconds"],
            capacity_warning=profile["capacity_warning"],
        )
        if os.name == "posix":
            for directory in (root / "control", root):
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        record = {
            "proposal": proposal, "approval_sha256": approval, "control_root": root.name,
            "profile_sha256": new_profile["profile_sha256"],
            "minimum_receipt": first["receipt_sha256"],
        }
        raw = canonical(record) + b"\n"
        with fresh_stage(destination) as (stage, target):
            observer._write(stage, raw)
            # If linking succeeds but the final sync fails, the descriptor may
            # already name this tree. Preserve it when the outcome is uncertain.
            published = True
            try:
                publish(stage, target)
            except FileExistsError:
                published = False
                raise
    except (OSError, AuditTransferError):
        if not destination.exists() and not destination.is_symlink():
            raise
        return _existing(destination, approval)
    finally:
        if not published:
            shutil.rmtree(root)
    return verify(destination, sha(raw))
