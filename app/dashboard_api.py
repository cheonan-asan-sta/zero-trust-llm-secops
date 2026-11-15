"""Read-only identity context for the dashboard, using existing server authentication."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.security import Principal, Role, require_roles

router = APIRouter(prefix="/auth", tags=["dashboard"])


@router.get("/me")
def current_identity(principal: Annotated[Principal, Depends(require_roles(Role.VIEWER))]):
    return {
        "subject": principal.subject,
        "tenant_id": principal.tenant_id,
        "roles": sorted(role.value for role in principal.effective_roles),
        "auth_method": principal.auth_method,
    }


@router.get("/dashboard-catalog")
def dashboard_catalog(request: Request,
                      _: Annotated[Principal, Depends(require_roles(Role.VIEWER))]):
    from app.dashboard_catalog import catalog

    return catalog(request.app)
