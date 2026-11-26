"""Bounded request-owned evaluation setup, use, and cancellation-safe disposal."""

import asyncio
import math
from contextlib import asynccontextmanager

from fastapi import HTTPException

from app.services.settled_io import settled_awaitable, settled_io
from app.services.work_admission import admission_for


class EvaluationRuntimeUnavailable(RuntimeError):
    pass


@asynccontextmanager
async def evaluation_runtime(request, settings, factory, revalidate):
    limit = settings.evaluation_max_concurrency
    timeout = settings.evaluation_queue_timeout_seconds
    try:
        if (
            type(limit) is not int
            or not 1 <= limit <= 4
            or type(timeout) not in {int, float}
            or not math.isfinite(timeout)
            or not 0.01 <= timeout <= 2
        ):
            raise ValueError("evaluation admission configuration rejected")
        capacity = admission_for(request, "_evaluation_admission", limit)
    except (ValueError, TypeError) as error:
        raise HTTPException(503, "Evaluation admission configuration is unavailable") from error
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not capacity.acquire_nowait():
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise HTTPException(
                503, "Evaluation capacity is temporarily exhausted", headers={"Retry-After": "1"}
            )
        await asyncio.sleep(min(0.005, remaining))

    owned = []

    def construct():
        try:
            # Assign before returning to the event loop: cancellation of the
            # awaiting caller cannot discard the newly constructed owner.
            owned.append(factory())
        except Exception as error:
            raise EvaluationRuntimeUnavailable("evaluation setup failed") from error

    try:
        await revalidate()
        await settled_io(construct)
        await revalidate()
        yield owned[0]
    finally:
        try:
            if owned:
                closer = getattr(owned[0], "close", None)
                if closer is not None:
                    try:
                        await settled_awaitable(closer())
                    except Exception as error:
                        raise EvaluationRuntimeUnavailable(
                            "evaluation client cleanup failed"
                        ) from error
        finally:
            capacity.release()
