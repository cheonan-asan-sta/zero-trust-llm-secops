"""App-owned bounded initial identity I/O, safe across thread/event-loop callers."""

import asyncio
import math
import threading
from contextlib import asynccontextmanager

from fastapi import HTTPException
from starlette.datastructures import State


class AuthenticationAdmission:
    def __init__(self, limit):
        if type(limit) is not int or not 1 <= limit <= 16:
            raise ValueError("authentication admission limit rejected")
        self.limit = limit
        self._active = 0
        self._lock = threading.Lock()

    def acquire_nowait(self):
        with self._lock:
            if self._active >= self.limit:
                return False
            self._active += 1
            return True

    def release(self):
        with self._lock:
            if self._active <= 0:
                raise RuntimeError("authentication admission release without ownership")
            self._active -= 1

    def snapshot(self):
        with self._lock:
            return {
                "limit": self.limit,
                "active": self._active,
                "available": self.limit - self._active,
            }


_creation_lock = threading.Lock()
_standalone_state = State()


def authentication_admission(request, limit):
    app = request.scope.get("app")
    state = app.state if app is not None else _standalone_state
    with _creation_lock:
        value = getattr(state, "_authentication_admission", None)
        if value is None:
            value = AuthenticationAdmission(limit)
            state._authentication_admission = value
        if not isinstance(value, AuthenticationAdmission):
            raise TypeError("authentication admission owner rejected")
        return value


@asynccontextmanager
async def authentication_slot(request, settings):
    limit = settings.authentication_max_concurrency
    timeout = settings.authentication_queue_timeout_seconds
    try:
        if (
            type(limit) is not int
            or not 1 <= limit <= 16
            or type(timeout) not in {int, float}
            or not math.isfinite(timeout)
            or not 0.01 <= timeout <= 2
        ):
            raise ValueError("authentication admission configuration rejected")
        capacity = authentication_admission(request, limit)
    except (ValueError, TypeError) as error:
        raise HTTPException(503, "Authentication admission configuration is unavailable") from error
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not capacity.acquire_nowait():
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise HTTPException(
                503,
                "Authentication capacity is temporarily exhausted",
                headers={"Retry-After": "1"},
            )
        # Do not enqueue blocked executor threads just to wait for admission.
        await asyncio.sleep(min(0.005, remaining))
    try:
        yield
    finally:
        # Keep ownership of this exact instance if an operator replaces app state.
        capacity.release()
