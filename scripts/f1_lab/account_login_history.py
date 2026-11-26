"""Causal login history for preverified events in one identity namespace."""

from dataclasses import dataclass

FAILURE_WINDOW_MS = 10 * 60 * 1000
FAMILIAR_SUCCESS_WINDOW_MS = 24 * 60 * 60 * 1000
REPEATED_FAILURE_THRESHOLD = 3


@dataclass(frozen=True, slots=True)
class LoginContext:
    prior_failures: int
    same_recent_client: bool
    failures_since_success: bool


@dataclass(slots=True)
class _Account:
    moment: int
    failures: tuple[int, ...] = ()
    last_failure: int | None = None
    previous_success: int | None = None
    previous_client: bytes | None = None
    pending_failures: int = 0
    pending_success: bool = False
    pending_client: bytes | None = None

    def advance(self, moment):
        if moment < self.moment:
            raise ValueError("account history is out of order")
        if moment == self.moment:
            return
        if self.pending_failures:
            self.failures = (*self.failures, *((self.moment,) * self.pending_failures))[
                -REPEATED_FAILURE_THRESHOLD:
            ]
            self.last_failure = self.moment
        if self.pending_success:
            self.previous_success = self.moment
            self.previous_client = self.pending_client
        if self.failures and self.failures[0] < moment - FAILURE_WINDOW_MS:
            self.failures = tuple(
                when for when in self.failures if when >= moment - FAILURE_WINDOW_MS
            )
        self.moment = moment
        self.pending_failures = 0
        self.pending_success = False
        self.pending_client = None

    def observe(self, moment, success, client):
        self.advance(moment)
        prior = LoginContext(
            prior_failures=len(self.failures),
            same_recent_client=(
                client is not None
                and client == self.previous_client
                and self.previous_success is not None
                and moment - self.previous_success <= FAMILIAR_SUCCESS_WINDOW_MS
            ),
            failures_since_success=(
                self.last_failure is not None
                and (self.previous_success is None or self.last_failure >= self.previous_success)
            ),
        )
        if success:
            if not self.pending_success:
                self.pending_client = client
            elif client != self.pending_client:
                self.pending_client = None
            self.pending_success = True
        else:
            self.pending_failures = min(self.pending_failures + 1, REPEATED_FAILURE_THRESHOLD)
        return prior


class AccountLoginHistory:
    """Use a separate instance per issuer/tenant/client, with verified stable account IDs."""

    def __init__(self, *, max_accounts):
        if type(max_accounts) is not int or max_accounts < 1:
            raise ValueError("invalid account history limit")
        self.max_accounts = max_accounts
        self._accounts = {}

    @property
    def account_count(self):
        return len(self._accounts)

    def observe(self, *, account, moment, success, client):
        if (
            not isinstance(account, bytes)
            or not account
            or len(account) > 256
            or type(moment) is not int
            or moment < 0
            or type(success) is not bool
            or (
                client is not None and (not isinstance(client, bytes) or not 0 < len(client) <= 256)
            )
        ):
            raise ValueError("invalid verified login observation")
        state = self._accounts.get(account)
        if state is None:
            if len(self._accounts) >= self.max_accounts:
                raise ValueError("account history capacity reached")
            state = self._accounts[account] = _Account(moment)
        return state.observe(moment, success, client)


def repeated_failure_warning(prior, success):
    return prior.prior_failures + (not success) >= REPEATED_FAILURE_THRESHOLD


def review_repeated_login(*, baseline, prior, success, hard_alert=False):
    """Compare only the repeated-failure warning; preserve independent hard alerts."""
    if hard_alert or prior is None or success is not True:
        return hard_alert or baseline
    return baseline and not (prior.same_recent_client and not prior.failures_since_success)
