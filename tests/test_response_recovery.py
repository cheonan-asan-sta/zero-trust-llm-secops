"""Approval quorum is preserved by full restoration and cannot revive old authority."""

import pytest

from app.services.behavior_context_store import BehaviorContextStore
from app.services.response_actions import ResponseConflict, ResponseService
from tests import test_response_actions as response_cases
from tests.test_behavior_context_recovery import (
    CONTEXT_NAME,
    access,
    backup,
    fresh_capture,
    restore,
)
from tests.test_response_actions import approved, command, create, review


@pytest.fixture
def response_lab(tmp_path, monkeypatch):
    return response_cases.response_lab.__wrapped__(tmp_path, monkeypatch)


def test_full_restore_preserves_response_history_and_fences_pending_execution(
    response_lab, tmp_path, monkeypatch
):
    e = response_lab
    pending = approved(e, "pending-response")
    executed = approved(e, "executed-response")
    executed_command = command(executed)
    receipt = e.service.execute(executed["request_id"], executed_command, e.requester)
    _, cancelled = create(e, "cancelled-response")
    from app.response_models import ResponseCancel

    cancelled = e.service.cancel(
        cancelled["request_id"], ResponseCancel(**review(cancelled).model_dump()), e.requester
    )
    original = e.lab.store.read("tenant-a")
    saved = backup(e.lab, tmp_path, monkeypatch, full_state=True)
    restored = restore(saved, e.lab)
    service = ResponseService(restored.service.store, restored.operations)
    assert restored.service.store.read("tenant-a") == original
    assert access(restored, e.target.session).status_code == 403
    assert e.lab.at(6) < e.target.request.expires_at
    assert service.get(pending["request_id"], e.requester)["status"] == "STALE"
    with pytest.raises(ResponseConflict):
        service.execute(pending["request_id"], command(pending), e.requester)
    retry = service.execute(executed["request_id"], executed_command, e.requester)
    assert retry["duplicate"] and retry["result"] == receipt["result"]
    assert service.get(cancelled["request_id"], e.requester)["status"] == "CANCELLED"
    with pytest.raises(ResponseConflict):
        service.execute(cancelled["request_id"], command(cancelled), e.requester)
    e.target = fresh_capture(restored, e.lab, "fresh-response", 7)
    e.service = service
    fresh = approved(e, "fresh-response")
    assert (
        service.execute(fresh["request_id"], command(fresh), e.requester)["result"][
            "effect_applied"
        ]
        is False
    )
    assert access(restored, e.target.session).status_code == 200
    assert access(restored, e.target.session).status_code == 403
    reopened = ResponseService(
        BehaviorContextStore(restored.stage / CONTEXT_NAME), restored.operations
    )
    assert reopened.get("fresh-response", e.requester)["status"] == "EXECUTED"
    assert restored.service.store.read("tenant-a")[: len(original)] == original


def test_response_events_do_not_change_work_context_evaluation(response_lab):
    e = response_lab
    e.lab.baseline()
    target = e.lab.capture("approved-work", 5)
    before = e.lab.service.evaluate(target.id, e.lab.analyst, now=e.lab.at(5))
    assert before["verdict"] == "normal"
    view = approved(e)
    e.service.execute(view["request_id"], command(view), e.requester)
    after = e.lab.service.evaluate(target.id, e.lab.analyst, now=e.lab.at(5))
    assert after["duplicate"]
    assert {key: value for key, value in after.items() if key != "duplicate"} == {
        key: value for key, value in before.items() if key != "duplicate"
    }
