"""Keep request resource ownership until a non-cancellable thread settles."""

import asyncio


async def settled_io(function, *args, **kwargs):
    worker = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
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
