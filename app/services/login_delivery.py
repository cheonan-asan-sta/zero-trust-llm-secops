"""Stable identity and exact request binding for a durable login delivery."""

import hashlib
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass

from app.zero_trust_models import LoginDeliveryRequest


class LoginDeliveryBusy(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class LoginDeliveryIdentity:
    analysis_id: str
    payload_sha256: str

    @classmethod
    def from_request(cls, request: LoginDeliveryRequest):
        identity = ["zt-login-delivery-v1", request.tenant_id, request.collector_subject, request.event.event_id]
        payload = request.model_dump(mode="json")
        return cls(_digest(identity), _digest(payload))


def _digest(value):
    wire = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(wire.encode()).hexdigest()


@contextmanager
def lock_login_delivery(audit_path, analysis_id):
    """Serialize analysis on the same audit host, releasing the lock on process exit."""
    lane = int(analysis_id[:2], 16) % 64
    path = audit_path.with_name(f".{audit_path.name}.login-{lane:02d}.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags, 0o600), "r+b", buffering=0) as handle:
        if os.name == "nt":
            import msvcrt

            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise LoginDeliveryBusy("login delivery is in progress") from exc
        else:
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise LoginDeliveryBusy("login delivery is in progress") from exc
        yield
