"""Local OIDC and OTP acceptance route for signed web redirect evidence."""

import json
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from starlette.responses import RedirectResponse

from app import security
from app.services.settled_io import settled_io
from scripts.evaluate_public_apache_transfer import frozen_model
from scripts.f1_lab.web_capture_lab import (
    REDIRECT_LOCATION,
    REDIRECT_PATH,
    REDIRECT_RESOURCE,
    LocalWebCaptureLab,
)
from scripts.f1_lab.web_request_capture import (
    STATE_KEY,
    RequestCaptureMiddleware,
    ServerObservation,
)
from scripts.f1_lab.web_residual import WebResidualRefinement
from scripts.f1_lab.web_verified_context import Authentication, Authorization, digest, digest_raw

ROUTE = "/fixture/web"


def mount(gateway, root, service, grant, otp):
    """Mount a protected fixture whose target and grant are fixed server-side."""
    baseline = WebResidualRefinement(frozen_model()[0])
    redirect_scope = {
        "path": ROUTE + REDIRECT_PATH,
        "method": "POST",
        "required_role": "analyst",
        "access_scope": [grant.resource_id, grant.action.value],
        "access_policy_sha256": service.policy_digest,
    }
    lab = LocalWebCaptureLab(
        root, baseline, tenant_id=otp.tenant, subject=otp.subject, redirect_scope=redirect_scope
    )
    fixture = FastAPI(docs_url=None, openapi_url=None, redoc_url=None)
    fixture.state.oidc_live_authority = gateway.state.oidc_live_authority
    fixture.add_middleware(RequestCaptureMiddleware, sink=lab.pipeline)

    @fixture.post(REDIRECT_PATH)
    async def redirect(
        request: Request,
        principal: Annotated[
            security.Principal, Depends(security.require_roles(security.Role.ANALYST))
        ],
    ):
        bearer = request.headers.get("authorization", "").partition(" ")[2]
        if not otp.matches(principal, bearer):
            raise HTTPException(status_code=403, detail="Verified OTP for this token is required")
        await settled_io(request.state.authentication_revalidator)
        if service.policy_digest != redirect_scope["access_policy_sha256"]:
            raise HTTPException(status_code=409, detail="Redirect fixture policy changed")
        binding = access_binding(request.state.secops_capture_id, grant.session_id)
        result = await settled_io(
            lambda: service.access(grant, principal, execution_request_sha256=binding)
        )
        if not result.allowed:
            raise HTTPException(status_code=403, detail="Redirect fixture grant not available")
        request.scope["state"][STATE_KEY] = ServerObservation(
            principal=principal,
            session_id=grant.session_id,
            session_version=result.session_version,
            resource_id=REDIRECT_RESOURCE,
            authentication=Authentication(kind="authentication", result="success", mfa="success"),
            authorization=Authorization(
                kind="authorization",
                decision="allow",
                action="redirect",
                policy_sha256=lab.redirect_policy_sha,
                policy_version=1,
            ),
            runtime=None,
        )
        return RedirectResponse(REDIRECT_LOCATION, status_code=303)

    gateway.mount(ROUTE, fixture)
    return lab


def access_binding(capture_id, session_id):
    return digest(["oidc_fixture_redirect", capture_id, session_id, digest_raw(REDIRECT_LOCATION)])


def receipt(lab, response):
    capture_id = response.headers["x-capture-id"]
    assert len(capture_id) == 32 and all(value in "0123456789abcdef" for value in capture_id)
    result = json.loads((lab.directory / "captures" / f"{capture_id}.json").read_bytes())
    assert result["request_id"] == capture_id
    assert result["status"] == response.status_code
    return result


def verify_success(lab, response, service, grant, otp, expected_version):
    assert response.status_code == 303 and response.headers["location"] == REDIRECT_LOCATION
    result = receipt(lab, response)
    expected_identity = digest([otp.tenant, otp.subject, grant.session_id, expected_version])
    assert result.get("identity_sha256") == expected_identity, (
        result["capture_state"], result["context_state"]
    )
    assert result["redirect"]["context_state"] == "consistent"
    assert len(result["redirect"]["evidence_sha256"]) == 64
    assert result["redirect"]["location_sha256"] == digest_raw(REDIRECT_LOCATION)
    assert result["decision"] is None
    with service._transaction() as (_, entries, _):
        bindings = [
            item
            for item in entries
            if item["kind"] == "access"
            and item.get("allowed")
            and item.get("execution_request_sha256")
            == access_binding(result["request_id"], grant.session_id)
        ]
    assert len(bindings) == 1 and bindings[0]["session_version"] == expected_version
    assert bindings[0]["operator_id"] == otp.subject and bindings[0]["tenant_id"] == otp.tenant
    serialized = json.dumps(result)
    assert otp.session not in serialized and otp.subject not in serialized
    assert REDIRECT_LOCATION not in serialized and grant.grant_token not in serialized
