"""Bounded self-observation for local collector sandbox acceptance."""

import os
import re
from pathlib import Path

from scripts.f1_lab.native_jsonl import require


def security_status(path=Path("/proc/self/status")):
    with Path(path).open("rb") as stream:
        raw = stream.read(65537)
    require(len(raw) <= 65536, "collector_status_bound")
    fields = {}
    for line in raw.decode("ascii").splitlines():
        name, _, value = line.partition(":")
        if name in {"Uid", "CapEff", "CapBnd", "NoNewPrivs"}:
            require(name not in fields, "collector_status_duplicate")
            fields[name] = value.strip()
    require(set(fields) == {"Uid", "CapEff", "CapBnd", "NoNewPrivs"}, "collector_status_missing")
    uids = fields["Uid"].split()
    require(
        len(uids) == 4 and all(re.fullmatch(r"\d{1,10}", v) for v in uids), "collector_status_uid"
    )
    require(
        all(re.fullmatch(r"[a-fA-F0-9]{16}", fields[k]) for k in ("CapEff", "CapBnd"))
        and fields["NoNewPrivs"] in {"0", "1"},
        "collector_status_values",
    )
    return {
        "effective_uid": int(uids[1]),
        "effective_capabilities": int(fields["CapEff"], 16),
        "bounding_capabilities": int(fields["CapBnd"], 16),
        "no_new_privileges": fields["NoNewPrivs"] == "1",
    }


def current_security_status():
    require(os.name == "posix", "collector_status_linux")
    return security_status()
