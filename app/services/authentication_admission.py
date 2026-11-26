"""App-owned bounded initial identity I/O, safe across thread/event-loop callers."""

import asyncio
import math
from contextlib import asynccontextmanager

from fastapi import HTTPException

from app.services.work_admission import WorkAdmission as AuthenticationAdmission  # noqa: F401
from app.services.work_admission import admission_for


def authentication_admission(request, limit):
    return admission_for(request, "_authentication_admission", limit)


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
