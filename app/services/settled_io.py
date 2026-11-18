"""Keep request resource ownership until a non-cancellable thread settles."""

import asyncio


async def settled_io(function, *args, **kwargs):
    return await settled_awaitable(asyncio.to_thread(function, *args, **kwargs))


async def settled_awaitable(awaitable):
    """Finish owned async cleanup despite repeated cancellation of its caller."""
    worker = asyncio.ensure_future(awaitable)
    cancelled = None
    while True:
        try:
            result = await asyncio.shield(worker)
            break
        except asyncio.CancelledError as error:
            if worker.cancelled():
                raise
            cancelled = error
        except BaseException as error:
            if cancelled is not None:
                raise cancelled from error
            raise
    if cancelled is not None:
        raise cancelled
    return result
