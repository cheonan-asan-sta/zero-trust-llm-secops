from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response

from app.continuous_signal_models import SignedContinuousSignal
from app.security import Principal, Role, require_roles
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import (
    InboxConflict,
    InboxFull,
    InboxMissing,
    InboxUnavailable,
)
from app.services.trusted_signals import SignalRegistryUnavailable, SignalRejected
from app.services.zero_trust import (
    JournalUnavailable,
    SessionConflict,
    SessionMissing,
    ZeroTrustOperations,
)
from app.zero_trust_models import (
    ProtectedAccessRequest,
    ProtectedAccessResult,
    SessionDecision,
    SessionEvaluationRequest,
    SessionEvaluationResult,
    SessionRevocationRequest,
    SignedSessionSignal,
    ZeroTrustPolicyBundle,
)

Viewer = Annotated[Principal, Depends(require_roles(Role.VIEWER))]
Analyst = Annotated[Principal, Depends(require_roles(Role.ANALYST))]
Responder = Annotated[Principal, Depends(require_roles(Role.RESPONDER))]


def zero_trust_router(service: ZeroTrustOperations | None,
                      inbox_service: ContinuousSignalService | None = None) -> APIRouter:
    def available() -> ZeroTrustOperations:
        if service is None:
            raise HTTPException(404, "Local Zero Trust simulation is disabled in production")
        return service

    Service = Annotated[ZeroTrustOperations, Depends(available)]
    def intake_available() -> ContinuousSignalService:
        available()
        if inbox_service is None:
            raise HTTPException(404, "Continuous signal intake is not configured")
        return inbox_service

    Intake = Annotated[ContinuousSignalService, Depends(intake_available)]
    router = APIRouter(prefix="/zero-trust", tags=["Zero Trust operations simulation"])

    @router.post("/signals/inbox", status_code=202)
    def receive_signal(request: SignedContinuousSignal, principal: Analyst, intake: Intake):
        return intake.accept(request, principal)

    @router.get("/signals/inbox")
    def inbox_summary(principal: Viewer, intake: Intake):
        return intake.summary(principal)

    @router.get("/signals/inbox/{event_id}")
    def signal_receipt(event_id: str, principal: Viewer, intake: Intake):
        return intake.receipt(event_id, principal)

    @router.get("/policies", response_model=ZeroTrustPolicyBundle)
    def policies(_: Viewer, operations: Service):
        return operations.policy

    @router.post("/sessions/evaluate", response_model=SessionEvaluationResult)
    def evaluate(request: SessionEvaluationRequest, principal: Analyst, operations: Service):
        return operations.evaluate(request, principal)

    @router.post("/signals/evaluate", response_model=SessionEvaluationResult)
    def evaluate_signed(request: SignedSessionSignal, principal: Analyst, operations: Service):
        return operations.evaluate_signed(request, principal)

    @router.get("/signals/status")
    def signals_status(principal: Viewer, operations: Service):
        return operations.signal_verifier.readiness(principal.tenant_id)

    @router.get("/sessions", response_model=list[SessionDecision])
    def sessions(principal: Viewer, operations: Service):
        return operations.sessions(principal)

    @router.get("/sessions/{session_id}", response_model=list[SessionDecision])
    def history(session_id: str, principal: Viewer, operations: Service):
        return operations.history(session_id, principal)

    @router.post("/sessions/{session_id}/revoke", response_model=SessionDecision)
    def revoke(session_id: str, request: SessionRevocationRequest,
               principal: Responder, operations: Service):
        return operations.revoke(session_id, request, principal)

    @router.post("/protected-access", response_model=ProtectedAccessResult)
    def protected_access(request: ProtectedAccessRequest, principal: Analyst,
                         operations: Service, response: Response):
        result = operations.access(request, principal)
        if not result.allowed:
            response.status_code = 403
        return result

    return router


def install_zero_trust_error_handlers(app):
    from fastapi.responses import JSONResponse

    @app.exception_handler(InboxConflict)
    async def conflicting_delivery(_request, _exc):
        return JSONResponse({"detail": "Signal event identifier already has different input"},
                            status_code=409)

    @app.exception_handler(InboxFull)
    async def full_inbox(_request, _exc):
        return JSONResponse({"detail": "Signal inbox capacity reached; delivery not accepted"},
                            status_code=429, headers={"Retry-After": "1"})

    @app.exception_handler(InboxMissing)
    async def missing_delivery(_request, _exc):
        return JSONResponse({"detail": "Signal receipt not found"}, status_code=404)

    @app.exception_handler(InboxUnavailable)
    async def unavailable_inbox(_request, _exc):
        return JSONResponse({"detail": "Signal inbox unavailable; delivery not acknowledged"},
                            status_code=503)

    @app.exception_handler(SignalRejected)
    async def rejected_signal(_request, _exc):
        return JSONResponse({"detail": "Signal source, signature, scope or freshness rejected"},
                            status_code=401)

    @app.exception_handler(SignalRegistryUnavailable)
    async def unavailable_sources(_request, _exc):
        return JSONResponse({"detail": "Trusted signal registry unavailable; access denied"},
                            status_code=503)

    @app.exception_handler(SessionConflict)
    async def conflict(_request, _exc):
        return JSONResponse({"detail": "Session version, identity, order or event conflict"},
                            status_code=409)

    @app.exception_handler(SessionMissing)
    async def missing(_request, _exc):
        return JSONResponse({"detail": "Session not found"}, status_code=404)

    @app.exception_handler(JournalUnavailable)
    async def unavailable(_request, _exc):
        return JSONResponse({"detail": "Zero Trust journal unavailable; access denied"},
                            status_code=503)
