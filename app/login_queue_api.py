"""Tenant-scoped review of held login deliveries and the matching queue alerts."""

import hashlib
import hmac
import json
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import Field, field_validator, model_validator

from app.config import get_settings
from app.models import StrictModel
from app.security import Principal, Role, require_roles
from app.services.audit_review_preconditions import (
    parse_review_identity,
    parse_review_if_match,
    require_review_identity,
    review_identity,
)
from app.services.collector_spool import SpoolBindingMismatch, SpoolUnavailable
from scripts.login_delivery_spool import LoginDeliverySpool, LoginRetryReviewConflict

router = APIRouter(prefix="/dashboard/login-queue", tags=["dashboard-login-queue"])
Viewer = Annotated[Principal, Depends(require_roles(Role.VIEWER))]
Responder = Annotated[Principal, Depends(require_roles(Role.RESPONDER))]
ALERT_NAMES = (
    "C01LoginQueueStatusUnavailable", "C01LoginQueueBacklog",
    "C01LoginQueueHeld", "C01LoginQueueCapacityPressure",
)


class LoginQueueProfile(StrictModel):
    queue_file: Path
    analysis_origin: str = Field(min_length=1, max_length=512)
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    collector_subject: str = Field(min_length=1, max_length=128)
    prometheus_origin: str | None = Field(default=None, max_length=512)
    scrape_job: str = Field(default="zt-signals", min_length=1, max_length=128)
    scrape_instance: str | None = Field(default=None, min_length=1, max_length=256)

    @model_validator(mode="after")
    def validate_scope(self):
        if not self.queue_file.is_absolute():
            raise ValueError("queue_file must be absolute")
        if (self.prometheus_origin is None) != (self.scrape_instance is None):
            raise ValueError("Prometheus origin and scrape instance must be configured together")
        if self.prometheus_origin is not None:
            parsed = urlsplit(self.prometheus_origin)
            if (
                parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"}
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            ):
                raise ValueError("Prometheus origin must be a dedicated loopback HTTP origin")
        return self


class ApprovalRequest(StrictModel):
    event_id: str = Field(min_length=1, max_length=128)
    hold_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    note: str = Field(min_length=3, max_length=300, pattern=r"\S")

    @field_validator("note", mode="before")
    @classmethod
    def strip_note(cls, note):
        return note.strip() if isinstance(note, str) else note


def load_profile(path):
    with path.open("rb") as stream:
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise ValueError("login queue profile too large")
    return LoginQueueProfile.model_validate_json(raw)


def _profile(principal):
    path = get_settings().dashboard_login_queue_profile
    if path is None:
        raise HTTPException(404, "Login queue dashboard is disabled")
    if principal.auth_method not in {"api_key", "oidc"}:
        raise HTTPException(401, "Authenticated operator required")
    try:
        profile = load_profile(path)
    except (OSError, ValueError) as error:
        raise HTTPException(503, "Login queue profile unavailable") from error
    if principal.tenant_id != profile.tenant_id:
        raise HTTPException(403, "Login queue belongs to another tenant")
    return profile


def _queue(profile):
    return LoginDeliverySpool(
        profile.queue_file, origin=profile.analysis_origin,
        tenant_id=profile.tenant_id, collector_subject=profile.collector_subject, create=False,
    )


def _tag(queue, event_id, hold_id):
    scope = json.dumps([queue.status_scope_sha256, event_id, hold_id], ensure_ascii=False).encode()
    return '"r1-' + hashlib.sha256(scope).hexdigest() + '"'


def confirmed_delivery_reference(principal, analysis_id):
    profile = _profile(principal)
    try:
        event_id = _queue(profile).completed_event(analysis_id)
    except (OSError, SpoolUnavailable, SpoolBindingMismatch) as error:
        raise HTTPException(503, "Login queue unavailable") from error
    if event_id is None:
        raise HTTPException(404, "Confirmed delivery not found")
    return profile, event_id


def _prometheus_get(client, origin, path):
    with client.stream("GET", origin.rstrip("/") + path) as response:
        response.raise_for_status()
        raw = bytearray()
        for part in response.iter_bytes(chunk_size=4096):
            raw.extend(part)
            if len(raw) > 65536:
                raise ValueError("monitoring response too large")
    result = json.loads(raw)
    if result["status"] != "success":
        raise ValueError("monitoring query failed")
    return result["data"]


def _alerts(profile):
    if profile.prometheus_origin is None:
        return {"state": "disabled", "entries": []}
    try:
        with httpx.Client(timeout=0.6, trust_env=False, follow_redirects=False) as client:
            targets = _prometheus_get(client, profile.prometheus_origin, "/api/v1/targets?state=active")["activeTargets"]
            alerts = _prometheus_get(client, profile.prometheus_origin, "/api/v1/alerts")["alerts"]
        if type(targets) is not list or type(alerts) is not list:
            raise ValueError("invalid alert inventory")
        expected = profile.scrape_job, profile.scrape_instance
        scoped_targets = [target for target in targets if (
            target["labels"].get("job"), target["labels"].get("instance")
        ) == expected]
        if len(scoped_targets) != 1 or scoped_targets[0]["health"] != "up":
            raise ValueError("login queue scrape target unavailable")
        matching = {}
        for entry in alerts:
            labels = entry["labels"]
            name = labels["alertname"]
            if name not in ALERT_NAMES or (labels.get("job"), labels.get("instance")) != expected:
                continue
            state = entry["state"]
            if state not in {"pending", "firing"} or name in matching:
                raise ValueError("invalid scoped alert state")
            matching[name] = state
    except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
        return {"state": "unavailable", "entries": []}
    return {"state": "ready", "entries": [{"name": name, "state": matching[name]} for name in ALERT_NAMES if name in matching]}


@router.get("")
def login_queue_view(
    principal: Viewer, request: Request, after: int = Query(default=0, ge=0, le=2**63 - 1),
    event_id: str | None = Query(default=None, min_length=1, max_length=128),
):
    profile = _profile(principal)
    revalidate = request.state.authentication_revalidator
    revalidate()
    review = None
    try:
        queue = _queue(profile)
        snapshot = queue.status_snapshot()
        if Role.RESPONDER in principal.effective_roles:
            review = queue.review_page(after=after, event_id=event_id)
            review["identity"] = review_identity(principal)
            for row in review["held"]:
                row["etag"] = _tag(queue, row["event_id"], row["hold_id"])
    except (OSError, SpoolUnavailable, SpoolBindingMismatch):
        snapshot = review = None
    result = {"queue": snapshot, "alerts": _alerts(profile), "review": review}
    revalidate()
    return result


@router.post("/approvals")
def approve_login_retry(body: ApprovalRequest, request: Request, principal: Responder):
    profile = _profile(principal)
    tag = parse_review_if_match(request.headers.getlist("if-match"))
    caller = parse_review_identity(request.headers.getlist("x-review-identity"))
    require_review_identity(principal, caller, tag, required=True)

    def authorize():
        request.state.authentication_revalidator()
        if _profile(principal) != profile:
            raise HTTPException(409, "Login queue configuration changed")

    try:
        queue = _queue(profile)
        if not hmac.compare_digest(tag, _tag(queue, body.event_id, body.hold_id)):
            raise HTTPException(412, "Login queue review version changed")
        return queue.approve_retry(
            body.event_id, body.hold_id, actor=principal.subject, note=body.note, authorize=authorize,
        )
    except LoginRetryReviewConflict as error:
        raise HTTPException(412, "Login hold changed; reload the queue") from error
    except (OSError, SpoolUnavailable, SpoolBindingMismatch) as error:
        raise HTTPException(503, "Login queue unavailable") from error
