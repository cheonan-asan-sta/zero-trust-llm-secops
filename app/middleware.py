import json
import logging
import re
from time import perf_counter
from uuid import uuid4

from prometheus_client import Counter, Histogram
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("secops.access")
REQUESTS = Counter(
    "secops_http_requests_total",
    "HTTP requests processed by the SecOps API",
    ("method", "route", "status"),
)
LATENCY = Histogram(
    "secops_http_request_duration_seconds",
    "HTTP request duration for the SecOps API",
    ("method", "route"),
)
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")


class RequestBodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        content_length = headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > self.max_bytes:
            await JSONResponse(
                {"detail": "Request body exceeds the configured limit"},
                status_code=413,
            )(scope, receive, send)
            return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise RequestBodyTooLarge
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except RequestBodyTooLarge:
            if not response_started:
                await JSONResponse(
                    {"detail": "Request body exceeds the configured limit"},
                    status_code=413,
                )(scope, receive, send)


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        supplied_id = request.headers.get("x-request-id", "")
        request_id = supplied_id if REQUEST_ID_PATTERN.fullmatch(supplied_id) else uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        started = perf_counter()
        status_code = 500

        async def send_with_headers(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"x-request-id", request_id.encode("ascii")),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                        (
                            b"content-security-policy",
                            b"default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
                        ),
                        (b"cache-control", b"no-store"),
                    ]
                )
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        finally:
            elapsed = perf_counter() - started
            route = getattr(scope.get("route"), "path", "unmatched")
            REQUESTS.labels(scope["method"], route, str(status_code)).inc()
            LATENCY.labels(scope["method"], route).observe(elapsed)
            principal = scope.get("state", {}).get("principal")
            logger.info(
                json.dumps(
                    {
                        "event": "http_request",
                        "request_id": request_id,
                        "method": scope["method"],
                        "route": route,
                        "status": status_code,
                        "duration_ms": round(elapsed * 1000, 2),
                        "actor_id": getattr(principal, "subject", None),
                        "tenant_id": getattr(principal, "tenant_id", None),
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )
