"""Render an operator-reviewed drop-in and the matching exporter profile."""

import re
from pathlib import Path

from app.services import audit_witness_observer as observer
from app.services import audit_witness_rollover as rollover
from app.services.audit_transfer import require, sha
from scripts.f1_lab import witness_observer_status as bridge


def unit_path(path):
    path = Path(path)
    require(re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path))
            and ".." not in path.parts and path == path.resolve(),
            "use an absolute, canonical systemd path without spaces or specifiers")
    return path


def configuration(record, record_pin, minimum_receipt, status_directory):
    record = unit_path(record)
    cache = unit_path(status_directory)
    require(cache.is_dir(), "witness status directory must exist")
    control, profile_pin, profile = rollover.collection_target(record, record_pin, minimum_receipt)
    _, transition = rollover._read_record(record)
    previous = transition["proposal"]
    _, old_profile, _ = observer._load(
        previous["old_control"], previous["old_profile_sha256"],
    )
    return render_configuration(
        control, profile_pin, profile, cache, record_pin, minimum_receipt,
        f"scripts.audit_witness_rollover watch --record {record} --record-sha256 {record_pin}",
        protected=(record, Path(previous["old_control"]), Path(old_profile["witness_directory"])),
    )


def render_configuration(control, profile_pin, profile, cache, record_pin, minimum_receipt,
                         command, *, protected=(), writable=()):
    control = unit_path(control)
    signer = unit_path(profile["witness_directory"])
    cache = unit_path(cache)
    require(cache.is_dir(), "witness status directory must exist")
    for location in (control, signer, Path(profile["database"]), *protected, *writable):
        require(not cache.is_relative_to(location) and not location.is_relative_to(cache),
                "witness cache overlaps witness history or input")
    cache_scope = sha((record_pin + minimum_receipt).encode("ascii"))
    status = cache / f"observer-{cache_scope}.json"
    audit_parent = unit_path(Path(profile["database"]).parent)
    drop_in = (
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart=/opt/secops/.venv/bin/python -m {command} --profile-sha256 {profile_pin} "
        f"--minimum-receipt {minimum_receipt} --status-file {status}\n"
        "ReadOnlyPaths=\n"
        f"ReadOnlyPaths={audit_parent} {signer}/private.key {signer}/public.key\n"
        "ReadWritePaths=\n"
        "ReadWritePaths=" + " ".join(str(path) for path in (control, signer, cache, *writable)) + "\n"
    )
    return {
        "systemd_drop_in": drop_in,
        "metrics_profile": {
            "schema": bridge.GENERATION_PROFILE_SCHEMA,
            "profile_sha256": profile_pin,
            "minimum_receipt": minimum_receipt,
            "record_sha256": record_pin,
            "status_file": str(status),
        },
    }
