"""Read the disposable Keycloak realm's own login results as advisory evidence."""

from ipaddress import ip_address
from urllib.parse import urlsplit

from scripts.f1_lab.account_login_history import (
    AccountLoginHistory,
    repeated_failure_warning,
    review_repeated_login,
)

EVENT_LIMIT = 125


def compare_login_history(events, *, realm_id, client_id, binding):
    if not isinstance(events, list) or len(events) > EVENT_LIMIT:
        raise ValueError("incomplete Keycloak login history")
    matching, seen = [], set()
    unattributed_times = []
    for event in events:
        if (
            not isinstance(event, dict)
            or event.get("realmId") != realm_id
            or event.get("clientId") != client_id
        ):
            raise ValueError("Keycloak login history scope mismatch")
        kind, moment, event_id = (event.get(key) for key in ("type", "time", "id"))
        if (
            kind not in {"LOGIN", "LOGIN_ERROR"}
            or type(moment) is not int
            or moment <= 0
            or not isinstance(event_id, str)
            or not event_id
            or event_id in seen
        ):
            raise ValueError("invalid or duplicate Keycloak login event")
        seen.add(event_id)
        if not event.get("userId"):
            unattributed_times.append(moment)
        if event.get("userId") != binding.subject:
            continue
        if bool(event.get("error")) != (kind == "LOGIN_ERROR"):
            raise ValueError("inconsistent Keycloak login result")
        try:
            source = ip_address(event.get("ipAddress")).packed
        except ValueError:
            source = None
        matching.append((moment, kind == "LOGIN", event.get("sessionId"), source))

    current = [event for event in matching if event[1] and event[2] == binding.session]
    if len(current) != 1:
        raise ValueError("no exact Keycloak login for the verified session")
    current_time, _, _, current_client = current[0]
    unattributed = sum(moment <= current_time for moment in unattributed_times)
    same_time = sum(event[0] == current_time for event in matching) > 1
    eligible = sorted(
        (event for event in matching if event[0] < current_time), key=lambda event: event[0]
    )
    history = AccountLoginHistory(max_accounts=1)
    account = binding.subject.encode()
    for moment, success, _, source in eligible:
        history.observe(account=account, moment=moment, success=success, client=source)
    prior = history.observe(
        account=account, moment=current_time, success=True, client=current_client
    )
    before = repeated_failure_warning(prior, True)
    evidence = prior if not (unattributed or same_time) else None
    return {
        "provider_current_result": "success",
        "verified_session_match": True,
        "earlier_same_account_successes": sum(event[1] for event in eligible),
        "earlier_same_account_failures": sum(not event[1] for event in eligible),
        "unattributed_login_events": unattributed,
        "ambiguous_current_time": same_time,
        "recent_prior_failures_capped": prior.prior_failures,
        "same_recent_source_address": prior.same_recent_client,
        "failures_since_success": prior.failures_since_success,
        "baseline_repeated_failure_warning": before,
        "candidate_repeated_failure_warning": review_repeated_login(
            baseline=before,
            prior=evidence,
            success=True,
        ),
        "candidate_with_independent_hard_alert": review_repeated_login(
            baseline=before,
            prior=evidence,
            success=True,
            hard_alert=True,
        ),
    }


def fetch_login_history(client, issuer, authorization, *, client_id, binding):
    url = urlsplit(issuer)
    prefix = "/realms/"
    realm = url.path.removeprefix(prefix)
    if (
        url.scheme != "http"
        or url.hostname != "127.0.0.1"
        or url.username
        or url.password
        or url.query
        or url.fragment
        or not url.path.startswith(prefix)
        or not realm
        or not all(char.isascii() and (char.isalnum() or char == "-") for char in realm)
    ):
        raise ValueError("login history requires the disposable loopback Keycloak issuer")
    admin = f"{url.scheme}://{url.netloc}/admin/realms/{realm}"
    realm_result = client.get(admin, headers=authorization, follow_redirects=False)
    realm_result.raise_for_status()
    realm_id = realm_result.json().get("id")
    if not isinstance(realm_id, str) or not realm_id:
        raise ValueError("Keycloak realm identity unavailable")
    response = client.get(
        admin + "/events",
        headers=authorization,
        params={"client": client_id, "type": ["LOGIN", "LOGIN_ERROR"], "max": EVENT_LIMIT + 1},
        follow_redirects=False,
    )
    response.raise_for_status()
    return compare_login_history(
        response.json(), realm_id=realm_id, client_id=client_id, binding=binding
    )
