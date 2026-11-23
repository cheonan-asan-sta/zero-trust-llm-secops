"""Relative changes against earlier successful logins for one verified account."""

from collections import deque
from dataclasses import dataclass, field
from enum import IntFlag

HISTORY_LIMIT = 12
WINDOW_MINUTES = (2, 10, 60, 720, 1440)


class Change(IntFlag):
    PRIOR_SUCCESS = 1
    NEW_ADDRESS = 2
    CHANGED_COUNTRY = 4
    NEW_COUNTRY = 8
    NEW_ASN = 16
    CHANGED_DEVICE = 32
    CHANGED_OS = 64
    CHANGED_BROWSER = 128
    NEW_PROFILE = 256
    MULTIPLE_SUCCESSES = 512
    CHANGED_ASN = 1024


@dataclass(frozen=True, slots=True)
class Environment:
    address: bytes | None
    country: bytes | None
    asn: bytes | None
    browser: bytes | None
    os: bytes | None
    device: bytes | None

    @property
    def profile(self):
        return self.browser, self.os, self.device


@dataclass(slots=True)
class _Prior:
    moment: int
    pending: Environment | None
    earlier: deque = field(default_factory=lambda: deque(maxlen=HISTORY_LIMIT))


def changed(current, previous):
    return current is not None and previous is not None and current != previous


def novel(field, current, earlier):
    value = getattr(current, field)
    known = {getattr(environment, field) for _, environment in earlier} - {None}
    return bool(value is not None and known and value not in known)


class SuccessfulEnvironments:
    """Compare to strictly earlier successful events in a single identity namespace."""

    def __init__(self):
        self._accounts = {}

    def observe(self, account, moment, current):
        state = self._accounts.get(account)
        if state is None:
            self._accounts[account] = _Prior(moment, current)
            return 0, len(WINDOW_MINUTES)
        if moment < state.moment:
            raise ValueError("environment history is out of order")
        if moment > state.moment:
            if state.pending is not None:
                state.earlier.append((state.moment, state.pending))
            state.moment = moment
            state.pending = current
        elif state.pending != current:
            state.pending = None

        if not state.earlier:
            return 0, len(WINDOW_MINUTES)
        earlier_time, previous = state.earlier[-1]
        profile = current.profile
        profiles = {value.profile for _, value in state.earlier if None not in value.profile}
        flags = Change.PRIOR_SUCCESS
        for signal, present in (
            (Change.NEW_ADDRESS, novel("address", current, state.earlier)),
            (Change.CHANGED_COUNTRY, changed(current.country, previous.country)),
            (Change.NEW_COUNTRY, novel("country", current, state.earlier)),
            (Change.CHANGED_ASN, changed(current.asn, previous.asn)),
            (Change.NEW_ASN, novel("asn", current, state.earlier)),
            (Change.CHANGED_DEVICE, changed(current.device, previous.device)),
            (Change.CHANGED_OS, changed(current.os, previous.os)),
            (Change.CHANGED_BROWSER, changed(current.browser, previous.browser)),
            (
                Change.NEW_PROFILE,
                None not in profile and bool(profiles) and profile not in profiles,
            ),
            (Change.MULTIPLE_SUCCESSES, len(state.earlier) >= 3),
        ):
            if present:
                flags |= signal
        delay = sum(moment - earlier_time > minutes * 60_000 for minutes in WINDOW_MINUTES)
        return int(flags), delay
