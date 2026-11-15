"""Explicitly enabled, authenticated host control for existing local tools."""

from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field

from app.config import get_settings
from app.models import StrictModel
from app.security import Principal, Role, require_roles
from app.services.dashboard_jobs import ACTIONS, JobConflict, JobStore, JobUnavailable

router = APIRouter(prefix="/dashboard/jobs", tags=["dashboard-operations"])
Admin = Annotated[Principal, Depends(require_roles(Role.ADMIN))]


class JobRequest(StrictModel):
    request_id: UUID
    action: Literal["runtime-status", "runtime-up", "runtime-down", "runtime-recover",
                    "runtime-verify", "m6-mock", "m6-plan", "m6-live"]
    reason: str = Field(min_length=3, max_length=300)
    confirmed: Literal[True]
    max_usd: float = Field(default=0, ge=0, le=50, allow_inf_nan=False)


def configuration(principal):
    settings = get_settings()
    if (settings.app_environment not in {"local", "test"} or settings.auth_mode == "disabled"
            or principal.auth_method not in {"api_key", "oidc"}
            or principal.tenant_id != settings.dashboard_operations_tenant):
        raise HTTPException(403, "Authenticated local operations administrator required")
    return settings


def store(settings):
    if settings.dashboard_operations_directory is None:
        raise HTTPException(503, "Dashboard operations directory is not configured")
    try:
        return JobStore(settings.dashboard_operations_directory)
    except (OSError, ValueError) as exc:
        raise HTTPException(503, "Private operations store is unavailable") from exc


@router.get("/capabilities")
def capabilities(principal: Admin):
    settings = configuration(principal)
    paired = settings.dashboard_m7_paired_directory
    return {"enabled": settings.dashboard_operations_directory is not None,
            "max_live_usd": settings.dashboard_live_max_usd,
            "actions": [{"id": action, "title": title, "available": bool(
                settings.dashboard_operations_directory is not None
                and (action not in {"m6-plan", "m6-live"} or (paired and paired.is_dir()))
                and (action != "m6-live" or settings.dashboard_live_max_usd > 0)
            )} for action, title in ACTIONS.items()]}


@router.get("")
def recent(principal: Admin):
    return store(configuration(principal)).recent(principal.tenant_id)


@router.get("/{identifier}")
def detail(identifier: UUID, principal: Admin):
    job = store(configuration(principal)).get(str(identifier), principal.tenant_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    return job


@router.post("", status_code=202)
def start(body: JobRequest, request: Request, principal: Admin):
    settings = configuration(principal)
    origin = request.headers.get("origin")
    if (request.headers.get("x-dashboard-action") != "1"
            or (origin and (urlsplit(origin).scheme, urlsplit(origin).netloc) !=
                (request.url.scheme, request.url.netloc))):
        raise HTTPException(403, "Same-origin dashboard action required")
    options = capabilities(principal)
    if not any(a["id"] == body.action and a["available"] for a in options["actions"]):
        raise HTTPException(409, "Operation is not configured")
    if body.action == "m6-live" and not 0 < body.max_usd <= settings.dashboard_live_max_usd:
        raise HTTPException(422, "Live run requires a budget within the configured ceiling")
    config = {"paired": str(settings.dashboard_m7_paired_directory)
              if settings.dashboard_m7_paired_directory else None,
              "max_usd": settings.dashboard_live_max_usd}
    try:
        return store(settings).start(body, principal, config)
    except JobConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except (JobUnavailable, OSError) as exc:
        raise HTTPException(503, "Operations job could not be accepted") from exc
