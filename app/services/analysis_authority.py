"""Task-local server authority for an analyzer invocation, never prompt data."""

from collections.abc import Awaitable, Callable
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field


class AnalysisAuthorityClosed(RuntimeError):
    pass


@dataclass
class AnalysisAuthority:
    _check: Callable[[], Awaitable[None]] = field(repr=False)
    _active: bool = field(default=True, init=False, repr=False)

    async def revalidate(self):
        if not self._active:
            raise AnalysisAuthorityClosed("analysis caller authority scope is closed")
        await self._check()
        if not self._active:
            raise AnalysisAuthorityClosed(
                "analysis caller authority scope closed during validation"
            )


_authority: ContextVar[AnalysisAuthority | None] = ContextVar("analysis_authority", default=None)


def current_analysis_authority():
    return _authority.get()


@contextmanager
def bind_analysis_authority(check):
    authority = AnalysisAuthority(check)
    token = _authority.set(authority)
    try:
        yield authority
    finally:
        # Child Tasks inherit the object. They must not use it after this owner
        # finishes, even though resetting a ContextVar only changes this Task.
        authority._active = False
        _authority.reset(token)
