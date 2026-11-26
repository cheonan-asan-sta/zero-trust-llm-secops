"""Thread-safe app/process admission counters, independent of event-loop identity."""

import threading

from starlette.datastructures import State


class WorkAdmission:
    def __init__(self, limit):
        if type(limit) is not int or not 1 <= limit <= 16:
            raise ValueError("work admission limit rejected")
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
                raise RuntimeError("work admission release without ownership")
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


def admission_for(request, attribute, limit):
    app = request.scope.get("app")
    state = app.state if app is not None else _standalone_state
    with _creation_lock:
        value = getattr(state, attribute, None)
        if value is None:
            value = WorkAdmission(limit)
            setattr(state, attribute, value)
        if not isinstance(value, WorkAdmission):
            raise TypeError("work admission owner rejected")
        return value
