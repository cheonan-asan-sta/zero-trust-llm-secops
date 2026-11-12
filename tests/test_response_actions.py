"""Local simulated response quorum, target binding and durable exact retries."""

import sqlite3
from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.response_api import response_router
from app.response_models import ResponseCancel, ResponseCommand, ResponseCreate, ResponseReview
from app.security import Principal, Role, get_principal
from app.services import response_actions as responses
from app.services.behavior_context_store import (
    BehaviorContextStore,
    ContextStoreUnavailable,
)
from app.services.response_actions import (
    ResponseConflict,
    ResponseDenied,
    ResponseInvalid,
    ResponseNotFound,
    ResponseService,
)
from app.zero_trust_models import SessionRevocationRequest
from tests import test_behavior_context_integration as context_cases


@pytest.fixture
def response_lab(tmp_path, monkeypatch):
    lab = context_cases.context_lab.__wrapped__(tmp_path, monkeypatch)
    target = lab.capture("response-target", 4)
    lab.clock.now = lab.at(4)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return lab.clock.now.astimezone(tz) if tz else lab.clock.now.replace(tzinfo=None)

    monkeypatch.setattr(responses, "datetime", Clock)
    actor = lambda name, role=Role.RESPONDER, tenant="tenant-a": Principal(
        name,
        tenant,
        frozenset({role}),
        "api_key",
    )
    return SimpleNamespace(
        lab=lab,
        service=ResponseService(lab.store, lab.operations),
        target=target,
        requester=actor(lab.operator.subject),
        reviewers=[actor("reviewer-a"), actor("reviewer-b")],
        actor=actor,
    )


def create(env, identifier="response-a", action="disable_account"):
    request = ResponseCreate(
        request_id=identifier,
        session_id=env.target.session.session.session_id,
        expected_session_version=1,
        action=action,
        expires_at=env.lab.at(64),
        reason="Reviewed local containment proposal",
    )
    return request, env.service.create(request, env.requester)


def review(view):
    return ResponseReview(
        expected_version=view["version"],
        request_digest=view["request_digest"],
        reason="Independent target review",
    )


def command(view):
    return ResponseCommand(expected_version=view["version"], request_digest=view["request_digest"])


def approved(env, identifier="response-a"):
    _, view = create(env, identifier)
    for principal in env.reviewers:
        view = env.service.approve(identifier, review(view), principal)
    return view


@pytest.mark.parametrize(
    "action,target_kind",
    [("disable_account", "account"), ("isolate_device", "device"), ("reduce_privilege", "account")],
)
def test_two_independent_reviews_produce_only_one_simulated_result(
    response_lab, action, target_kind
):
    e = response_lab
    request, view = create(e, action=action)
    before = e.lab.operations.history(e.target.session.session.session_id, e.lab.operator)
    assert view["target"]["kind"] == target_kind and view["required_approvals"] == 2
    assert view["session_binding"]["operator_id"] == e.requester.subject
    with pytest.raises(ResponseDenied):
        e.service.approve(request.request_id, review(view), e.requester)
    with pytest.raises(ResponseConflict):
        e.service.execute(request.request_id, command(view), e.requester)
    first = review(view)
    view = e.service.approve(request.request_id, first, e.reviewers[0])
    assert view["status"] == "PENDING"
    with pytest.raises(ResponseConflict):
        e.service.execute(request.request_id, command(view), e.requester)
    view = e.service.approve(request.request_id, review(view), e.reviewers[1])
    assert view["status"] == "APPROVED"
    duplicate = e.service.approve(request.request_id, first, e.reviewers[0])
    assert duplicate["duplicate"] and duplicate["receipt_version"] == 2
    with pytest.raises(ResponseConflict):
        e.service.approve(request.request_id, review(view), e.actor("third-reviewer"))
    with pytest.raises(ResponseDenied):
        e.service.execute(request.request_id, command(view), e.reviewers[0])
    execute = command(view)
    result = e.service.execute(request.request_id, execute, e.requester)
    assert result["status"] == "EXECUTED" and result["result"]["status"] == "SIMULATED"
    assert result["simulation_only"] and result["result"]["effect_applied"] is False
    assert result["approved_by"] == ["reviewer-a", "reviewer-b"]
    assert e.lab.operations.history(e.target.session.session.session_id, e.lab.operator) == before
    reopened = ResponseService(BehaviorContextStore(e.lab.store_path), e.lab.operations)
    assert reopened.execute(request.request_id, execute, e.requester)["result"] == result["result"]
    assert reopened.execute(request.request_id, execute, e.requester)["duplicate"]
    assert sum(row["kind"] == "response_result" for row in e.lab.store.read("tenant-a")) == 1


def test_work_approvals_are_not_response_quorum(response_lab):
    e = response_lab
    e.lab.baseline()
    _, view = create(e)
    assert view["approved_by"] == [] and view["status"] == "PENDING"


def test_same_identifier_cannot_change_action_owner_or_target(response_lab):
    e = response_lab
    request, view = create(e)
    assert e.service.create(request, e.requester)["duplicate"]
    with pytest.raises(ResponseConflict):
        e.service.create(request.model_copy(update={"action": "isolate_device"}), e.requester)
    with pytest.raises(ResponseConflict):
        e.service.create(request, e.reviewers[0])
    changed = review(view).model_copy(update={"request_digest": "0" * 64})
    with pytest.raises(ResponseConflict):
        e.service.approve(request.request_id, changed, e.reviewers[0])
    with pytest.raises(ResponseDenied):
        e.service.create(request.model_copy(update={"request_id": "other-owner"}), e.reviewers[0])
    with pytest.raises(ResponseNotFound):
        e.service.get(request.request_id, e.actor("foreign", tenant="tenant-b"))
    assert e.service.recent(e.actor("reader", Role.VIEWER)) == []


@pytest.mark.parametrize("role", [Role.VIEWER, Role.ANALYST])
def test_insufficient_role_cannot_create_review_cancel_or_execute(response_lab, role):
    e = response_lab
    request, view = create(e)
    principal = e.actor("restricted", role)
    for method, args in (
        (e.service.create, (request,)),
        (e.service.approve, (request.request_id, review(view))),
        (e.service.cancel, (request.request_id, ResponseCancel(**review(view).model_dump()))),
        (e.service.execute, (request.request_id, command(view))),
    ):
        with pytest.raises(ResponseDenied):
            method(*args, principal)


def test_expiry_changed_session_and_cancellation_never_execute(response_lab):
    e = response_lab
    view = approved(e)
    with pytest.raises(ResponseConflict):
        e.service.execute(view["request_id"], command(view), e.requester, now=e.lab.at(65))
    assert e.service.get(view["request_id"], e.requester, now=e.lab.at(65))["status"] == "EXPIRED"
    e.lab.operations.revoke(
        e.target.session.session.session_id,
        SessionRevocationRequest(expected_version=1, note="New incident confirmed"),
        e.lab.operator,
        now=e.lab.at(6),
    )
    assert e.service.get(view["request_id"], e.requester)["status"] == "STALE"
    with pytest.raises(ResponseConflict):
        e.service.execute(view["request_id"], command(view), e.requester)
    cancel = ResponseCancel(**review(view).model_dump())
    cancelled = e.service.cancel(view["request_id"], cancel, e.reviewers[0])
    assert cancelled["status"] == "CANCELLED"
    assert e.service.cancel(view["request_id"], cancel, e.reviewers[0])["duplicate"]
    with pytest.raises(ResponseConflict):
        e.service.execute(view["request_id"], command(cancelled), e.requester)


@pytest.mark.parametrize("seconds", [-1, 301])
def test_create_has_bounded_nonretroactive_expiry(response_lab, seconds):
    e = response_lab
    request, _ = create(e)
    request = request.model_copy(
        update={"request_id": "invalid-window", "expires_at": e.lab.at(4 + seconds)}
    )
    with pytest.raises(ResponseInvalid):
        e.service.create(request, e.requester)


@pytest.mark.parametrize(
    "field,value",
    [
        ("action", "shell"),
        ("target_id", "arbitrary-account"),
        ("approved_by", ["fake"]),
        ("expected_session_version", True),
    ],
)
def test_caller_cannot_inject_authority_or_arbitrary_action(response_lab, field, value):
    e = response_lab
    request, _ = create(e)
    body = request.model_dump(mode="json") | {field: value}
    with pytest.raises(ValidationError):
        ResponseCreate.model_validate(body)


def test_commit_failure_does_not_publish_a_result(response_lab, monkeypatch):
    e = response_lab
    view = approved(e)

    class Failing(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected response commit failure")

    monkeypatch.setattr(
        e.lab.store,
        "_connect",
        lambda: sqlite3.connect(e.lab.store_path, isolation_level=None, factory=Failing),
    )
    with pytest.raises(ContextStoreUnavailable):
        e.service.execute(view["request_id"], command(view), e.requester)
    reopened = ResponseService(BehaviorContextStore(e.lab.store_path), e.lab.operations)
    assert reopened.get(view["request_id"], e.requester)["status"] == "APPROVED"
    assert reopened.execute(view["request_id"], command(view), e.requester)["status"] == "EXECUTED"


def test_authenticated_http_workflow_uses_current_principal(response_lab):
    e = response_lab
    actor = [e.requester]
    app = FastAPI()
    app.include_router(response_router(e.service))
    app.dependency_overrides[get_principal] = lambda: actor[0]
    client = TestClient(app)
    request = ResponseCreate(
        request_id="http-response",
        session_id=e.target.session.session.session_id,
        expected_session_version=1,
        action="disable_account",
        expires_at=e.lab.at(64),
        reason="HTTP containment proposal",
    )
    response = client.post("/response/requests", json=request.model_dump(mode="json"))
    assert response.status_code == 201
    view = response.json()
    url = "/response/requests/http-response"
    assert (
        client.post(url + "/approvals", json=review(view).model_dump(mode="json")).status_code
        == 403
    )
    for principal in e.reviewers:
        actor[0] = principal
        response = client.post(url + "/approvals", json=review(view).model_dump(mode="json"))
        assert response.status_code == 200
        view = response.json()
    actor[0] = e.requester
    assert (
        client.post(url + "/execute", json=command(view).model_dump(mode="json")).json()["result"][
            "effect_applied"
        ]
        is False
    )
    actor[0] = e.actor("foreign", tenant="tenant-b")
    assert client.get(url).status_code == 404 and client.get("/response/requests").json() == []
