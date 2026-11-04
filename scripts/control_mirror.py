"""Opt-in, fenced, peer-first writes for local management replica volumes.

This is synchronous local filesystem replication, not consensus or a network
filesystem. Only a trusted host executor may change the immutable role record.
"""

import json
import os
from pathlib import Path

ENV = "SECOPS_CONTROL_MIRROR"


def failure(code):
    from scripts.certificate_controller import LifecycleError
    raise LifecycleError("control_" + code)


def configuration():
    raw = os.environ.get(ENV)
    if raw is None:
        return None
    try:
        cfg = json.loads(raw)
        if not isinstance(cfg, dict) or not isinstance(cfg.get('mirrors'), dict):
            raise TypeError
        if set(cfg) != {"expected", "roles", "mirrors", "shared"} or len(cfg["roles"]) != 2 or not cfg["mirrors"]:
            raise ValueError
        if len(set(cfg["roles"])) != 2 or not isinstance(cfg["shared"], list):
            raise ValueError
        expected=cfg['expected']
        if (not isinstance(expected,dict) or type(expected.get('epoch')) is not int or expected['epoch']<1
                or expected.get('active') not in {'a','b'}):
            raise ValueError
        paths = [*cfg["roles"], *cfg["mirrors"], *cfg["mirrors"].values(), *cfg["shared"]]
        if any(not isinstance(p, str) or not Path(p).is_absolute() or ".." in Path(p).parts for p in paths):
            raise ValueError
        if any(a == b or Path(a).is_relative_to(b) or Path(b).is_relative_to(a) for a,b in cfg["mirrors"].items()):
            raise ValueError
        return cfg
    except (ValueError, TypeError, KeyError):
        failure("mirror_configuration")


def guard(cfg=None):
    cfg = configuration() if cfg is None else cfg
    if cfg is None:
        return None
    try:
        for name in cfg["roles"]:
            path = Path(name)
            if path.is_symlink() or json.loads(path.read_bytes()) != cfg["expected"]:
                failure("stale_or_incomplete_role")
    except (OSError, ValueError, TypeError):
        failure("stale_or_incomplete_role")
    return cfg


def scoped(path, root):
    path, root = Path(path).absolute(), Path(root).absolute()
    if ".." in path.parts or not path.is_relative_to(root):
        failure("mirror_path_scope")
    for p in [path, *path.parents]:
        if p.is_symlink():
            failure("mirror_symlink")
        if p == root:
            break
    return path


def counterpart(path, cfg):
    path = Path(path).absolute()
    for source in sorted(cfg["mirrors"], key=len, reverse=True):
        if path.is_relative_to(source):
            scoped(path, source)
            peer = Path(cfg["mirrors"][source]) / path.relative_to(source)
            return scoped(peer, cfg["mirrors"][source])
    for source in cfg["shared"]:
        if path.is_relative_to(source):
            scoped(path, source)
            return None
    failure("mirror_path_scope")


def durable_parent(path):
    if os.name != "nt":
        descriptor = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def write(path, body, replace):
    cfg = guard()
    if cfg is None:
        replace(path, body)
        return
    peer = counterpart(path, cfg)
    if peer is not None:
        if not peer.parent.is_dir():
            failure("mirror_parent_missing")
        replace(peer, body)
        durable_parent(peer)
    # A write is never acknowledged before its peer copy is durable.
    replace(path, body)
    durable_parent(path)


def remove(path, *, missing_ok=False):
    cfg = guard()
    if cfg is not None:
        peer = counterpart(path, cfg)
        if peer is not None:
            peer.unlink(missing_ok=missing_ok)
            durable_parent(peer)
    Path(path).unlink(missing_ok=missing_ok)
    if cfg is not None:
        durable_parent(path)


def activity(directory, busy):
    if configuration() is not None:
        from scripts.certificate_controller import save
        save(Path(directory) / "management-activity.json", {"busy": busy})
