from app.services.auth_alert_triage import resolve_auth_alert
from scripts.local_session_analysis_lab import LocalSessionAnalysisLab


def test_triage_uses_current_verified_session_for_exact_event(tmp_path):
    lab = LocalSessionAnalysisLab(tmp_path / "lab")
    signal, _ = lab.create(
        ("test", False, "remote-read", "employee", "success", True, "READ"),
        evidence_event_id="independent-trace",
    )

    def resolve(event, item):
        return resolve_auth_alert(lab.service, event, item, lab.principal)

    assert resolve(signal.event, signal) == "cleared"
    other = signal.event.model_copy(update={"event_id": "different-trace"})
    assert resolve(other, signal) == "needs_evidence"
    altered = signal.model_copy(update={"signature": "A" * 86})
    assert resolve(signal.event, altered) == "needs_evidence"
    lab.registry["sources"][0]["keys"][0]["enabled"] = False
    lab.save_registry()
    assert resolve(signal.event, signal) == "needs_evidence"


def test_triage_separates_confirmed_policy_block_from_incomplete_observation(tmp_path):
    lab = LocalSessionAnalysisLab(tmp_path / "lab")
    for name, mfa, managed in (
        ("action", "unknown", True),
        ("device", "success", False),
        ("revoked_request", "success", True),
    ):
        signed, _ = lab.create((name, True, "remote-read", "employee", mfa, managed, "READ"))
        assert resolve_auth_alert(lab.service, signed.event, signed, lab.principal) == "confirmed"


def test_triage_keeps_generic_step_up_for_review(tmp_path):
    lab = LocalSessionAnalysisLab(tmp_path / "lab")
    signed, _ = lab.create(
        ("signed", False, "remote-team", "employee", "success", True, "REMOTE_ACCESS")
    )
    assert resolve_auth_alert(lab.service, signed.event, signed, lab.principal) == "needs_evidence"
