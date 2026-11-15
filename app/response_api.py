"""Authenticated local-only high-risk response simulation workflow."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from app.response_models import ResponseCancel, ResponseCommand, ResponseCreate, ResponseReview
from app.security import Principal, Role, require_roles
from app.services.behavior_context_store import ContextRecordConflict, ContextStoreUnavailable
from app.services.response_actions import (
    ResponseConflict,
    ResponseDenied,
    ResponseInvalid,
    ResponseNotFound,
)
from app.services.zero_trust import JournalUnavailable

Responder = Annotated[Principal, Depends(require_roles(Role.RESPONDER))]
Viewer = Annotated[Principal, Depends(require_roles(Role.VIEWER))]


def response_router(service):
    router = APIRouter(prefix="/response/requests", tags=["response-approval"])

    def call(method, *args, **kwargs):
        if service is None:
            raise HTTPException(status_code=503, detail="Local response simulation is unavailable")
        try:
            return getattr(service, method)(*args, **kwargs)
        except ResponseDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ResponseNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (ResponseConflict, ContextRecordConflict) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ResponseInvalid as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except (ContextStoreUnavailable, JournalUnavailable, KeyError, TypeError) as exc:
            raise HTTPException(
                status_code=503, detail="Verified response state is unavailable"
            ) from exc

    @router.post("", status_code=201)
    def create(request: ResponseCreate, principal: Responder):
        return call("create", request, principal)

    @router.get("")
    def recent(principal: Viewer, limit: int = Query(default=50, ge=1, le=100)):
        return call("recent", principal, limit=limit)

    @router.get("/{identifier}")
    def get(identifier: str, principal: Viewer):
        return call("get", identifier, principal)

    @router.post("/{identifier}/approvals")
    def approve(identifier: str, request: ResponseReview, principal: Responder):
        return call("approve", identifier, request, principal)

    @router.post("/{identifier}/cancel")
    def cancel(identifier: str, request: ResponseCancel, principal: Responder):
        return call("cancel", identifier, request, principal)

    @router.post("/{identifier}/execute")
    def execute(identifier: str, request: ResponseCommand, principal: Responder):
        return call("execute", identifier, request, principal)

    return router
