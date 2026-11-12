"""Local authenticated context management and advisory candidate decisions."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from app.behavior_context_models import (
    ApprovalCreate,
    BaselineCreate,
    ContextEvaluationRequest,
    ContextRevocation,
    SignedBehaviorCapture,
)
from app.behavior_execution_models import SignedExecutionEvidence
from app.security import Principal, Role, require_roles
from app.services.behavior_context import ContextInvalid, ContextNotFound
from app.services.behavior_context_store import ContextRecordConflict, ContextStoreUnavailable
from app.services.trusted_signals import SignalRegistryUnavailable, SignalRejected
from app.services.zero_trust import JournalUnavailable

Analyst = Annotated[Principal, Depends(require_roles(Role.ANALYST))]
Admin = Annotated[Principal, Depends(require_roles(Role.ADMIN))]
Responder = Annotated[Principal, Depends(require_roles(Role.RESPONDER))]
Viewer = Annotated[Principal, Depends(require_roles(Role.VIEWER))]


def behavior_context_router(service):
    router = APIRouter(prefix="/detections/context", tags=["behavior-context"])

    def call(method, *args):
        if service is None:
            raise HTTPException(status_code=503, detail="Local behavior context is unavailable")
        try:
            return getattr(service, method)(*args)
        except SignalRejected as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ContextNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ContextRecordConflict as exc:
            raise HTTPException(status_code=409, detail="Context identifier conflicts with existing content") from exc
        except ContextInvalid as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except (ContextStoreUnavailable, JournalUnavailable, SignalRegistryUnavailable) as exc:
            raise HTTPException(status_code=503, detail="Verified context state is unavailable") from exc

    @router.post("/captures", status_code=201)
    def capture(request: SignedBehaviorCapture, principal: Analyst):
        return call("accept_capture", request, principal)

    @router.post("/baselines", status_code=201)
    def baseline(request: BaselineCreate, principal: Admin):
        return call("create_baseline", request, principal)

    @router.post("/execution-evidence", status_code=201)
    def execution(request: SignedExecutionEvidence, principal: Analyst):
        return call("accept_execution_evidence", request, principal)

    @router.post("/approvals", status_code=201)
    def approval(request: ApprovalCreate, principal: Responder):
        return call("create_approval", request, principal)

    @router.post("/baselines/{identifier}/revoke")
    def revoke_baseline(identifier: str, request: ContextRevocation, principal: Admin):
        return call("revoke", "baseline", identifier, request, principal)

    @router.post("/approvals/{identifier}/revoke")
    def revoke_approval(identifier: str, request: ContextRevocation, principal: Responder):
        return call("revoke", "approval", identifier, request, principal)

    @router.post("/evaluate")
    def evaluate(request: ContextEvaluationRequest, principal: Analyst):
        return call("evaluate", request.capture_id, principal)

    @router.get("/history")
    def history(principal: Viewer):
        return call("history", principal)

    return router
