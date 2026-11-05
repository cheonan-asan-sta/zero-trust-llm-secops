"""Public local runtime input lock; trusted host record, not a signature or approval."""

import hashlib
import json
import re
from pathlib import Path

DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
NGINX = re.compile(r"nginx@sha256:[a-f0-9]{64}\Z")
FIXED = ("Dockerfile", ".dockerignore", "pyproject.toml", "infra/pep/tools.lock.json",
         "infra/mtls/all-hops-nginx.conf")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_digest(path):
    # Git CRLF checkout differences are not deployment changes. These inputs are
    # text source/configuration only; runtime images are checked by Docker ID.
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("release_regular_file_required")
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def capture(root, topology, extra_files=()):
    root = Path(root).resolve()
    files = set(FIXED) | set(extra_files)
    for folder in ("app", "scripts", "infra/runtime"):
        for path in (root / folder).rglob("*"):
            if "__pycache__" in path.parts:
                continue
            if path.is_symlink():
                raise ValueError("release_symlink_forbidden")
            if path.is_file() and (folder != "scripts" or path.suffix == ".py"):
                files.add(path.relative_to(root).as_posix())
    hashes = {name: file_digest(root / name) for name in sorted(files)}
    lock = json.loads((root / "infra/pep/tools.lock.json").read_text(encoding="utf-8"))
    image = lock["tools"]["nginx"]["image"]
    if lock["platform"] != "linux/amd64" or not NGINX.fullmatch(image):
        raise ValueError("release_nginx_digest_platform_required")
    payload = {"schema": "local-runtime-release-1", "platform": "linux/amd64", "nginx_reference": image,
               "files": hashes, "topology_sha256": digest(topology)}
    return {"payload": payload, "sha256": digest(payload)}


def verify(saved, current):
    if (not isinstance(saved, dict) or set(saved) != {"payload", "sha256"}
            or digest(saved["payload"]) != saved["sha256"] or saved != current):
        raise ValueError("runtime_release_changed_or_missing")
    return saved["sha256"]


def image_identity(detail, expected_id=None, reference=None):
    if (not isinstance(detail, dict) or not DIGEST.fullmatch(detail.get("Id", ""))
            or detail.get("Os") != "linux" or detail.get("Architecture") != "amd64"
            or (expected_id is not None and detail["Id"] != expected_id)
            or (reference is not None and reference not in (detail.get("RepoDigests") or []))):
        raise ValueError("runtime_image_identity_mismatch")
    return detail["Id"]
