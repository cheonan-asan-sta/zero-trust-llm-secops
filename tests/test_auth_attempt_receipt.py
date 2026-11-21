from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.services.auth_alert_triage import resolve_terminal_auth_alert
from app.services.trusted_signals import SignalRejected
from scripts.local_auth_attempt_lab import LocalAuthAttemptLab
from scripts.local_session_analysis_lab import LocalSessionAnalysisLab


@pytest.fixture
def terminal_lab(tmp_path):
    sessions = LocalSessionAnalysisLab(tmp_path / "sessions")
    return sessions, LocalAuthAttemptLab(sessions)


def test_terminal_receipt_accepts_local_cancel_once_and_binds_exact_event(terminal_lab):
    sessions, attempts = terminal_lab
    event = attempts.open("local-cancel-1")
    receipt = attempts.cancel(event.event_id)
    assert (
        resolve_terminal_auth_alert(sessions.service, event, receipt, sessions.principal)
        == "cleared"
    )
    another_event = attempts.open("local-cancel-2")
    assert (
        resolve_terminal_auth_alert(sessions.service, another_event, receipt, sessions.principal)
        == "needs_evidence"
    )
    with pytest.raises(KeyError):
        attempts.cancel(event.event_id)
    with pytest.raises(ValueError, match="duplicate"):
        attempts.open(event.event_id)


@pytest.mark.parametrize("status", [200, 400, 401, 403, 429, 500, 502, 503, 504])
def test_terminal_health_probe_resolves_only_known_availability_failures(terminal_lab, status):
    sessions, attempts = terminal_lab
    event = attempts.open(f"local-probe-{status}")
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(status))) as client:
        receipt = attempts.check_upstream(event.event_id, lambda: client.get("http://test-idp/"))
    if status in {502, 503, 504}:
        assert receipt is not None
        assert (
            resolve_terminal_auth_alert(sessions.service, event, receipt, sessions.principal)
            == "cleared"
        )
    else:
        assert receipt is None


def test_terminal_receipt_rejects_invalid_signature_expiry_and_revoked_source(terminal_lab):
    sessions, attempts = terminal_lab
    event = attempts.open("local-cancel-3")
    receipt = attempts.cancel(event.event_id)

    def resolve(item, *, now=None):
        return resolve_terminal_auth_alert(
            sessions.service, event, item, sessions.principal, now=now
        )

    assert resolve(receipt.model_copy(update={"signature": "A" * 86})) == "needs_evidence"
    assert resolve(receipt, now=receipt.expires_at + timedelta(seconds=1)) == "needs_evidence"
    sessions.registry["sources"][-1]["enabled"] = False
    sessions.save_registry()
    assert resolve(receipt) == "needs_evidence"


def test_terminal_receipt_cannot_clear_credential_failures_or_event_with_session(terminal_lab):
    sessions, attempts = terminal_lab
    failed = attempts.open("local-failure", failed_attempts=2)
    assert (
        resolve_terminal_auth_alert(
            sessions.service, failed, attempts.cancel(failed.event_id), sessions.principal
        )
        == "needs_evidence"
    )
    observed_mfa = attempts.open("local-observed-mfa")
    auth_context = observed_mfa.auth_context.model_copy(update={"mfa": "success"})
    observed_mfa = observed_mfa.model_copy(update={"auth_context": auth_context})
    attempts.pending[observed_mfa.event_id] = observed_mfa
    assert (
        resolve_terminal_auth_alert(
            sessions.service,
            observed_mfa,
            attempts.cancel(observed_mfa.event_id),
            sessions.principal,
        )
        == "needs_evidence"
    )
    event = attempts.open("local-has-session")
    receipt = attempts.cancel(event.event_id)
    signal = sessions.sign(event, "existing-policy-session")
    sessions.service.evaluate_signed(signal, sessions.principal)
    assert (
        resolve_terminal_auth_alert(sessions.service, event, receipt, sessions.principal)
        == "needs_evidence"
    )


def test_terminal_source_cannot_verify_a_session_signal(terminal_lab):
    sessions, attempts = terminal_lab
    event = attempts.open("local-session-scope")
    signal = sessions.sign(event, "receipt-source-session").model_copy(
        update={"source_id": attempts.source_id, "key_id": "ephemeral-attempt-key"}
    )
    with pytest.raises(SignalRejected, match="observation-only"):
        sessions.service.signal_verifier.verify(signal, sessions.principal, datetime.now(UTC))
