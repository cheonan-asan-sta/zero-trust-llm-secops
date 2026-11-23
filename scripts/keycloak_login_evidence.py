"""Collector-side bridge from a verified Keycloak login and mTLS peer to analysis."""

import asyncio
import base64
import hashlib
import ssl
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Event, Lock, Thread
from types import SimpleNamespace
from typing import Literal
from urllib.parse import urlsplit

import httpx
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import ValidationError

from app import security
from app.services.login_delivery import LoginDeliveryIdentity
from app.services.session_analysis_evidence import event_digest
from app.services.trusted_signals import canonical_login_evidence
from app.zero_trust_models import (
    LOGIN_EVIDENCE_EXPIRED,
    LoginDeliveryReceipt,
    LoginDeliveryRequest,
    SignedLoginEvidence,
)
from scripts.login_delivery_spool import LoginDeliverySpool
from scripts.mtls_native import valid_client


def client_fingerprint(channel):
    if (
        not isinstance(channel, ssl.SSLSocket) or not channel.server_side
        or channel.context.verify_mode != ssl.CERT_REQUIRED
    ):
        raise ValueError("client-authenticated TLS required")
    certificate = channel.getpeercert(binary_form=True)
    if not certificate:
        raise ValueError("verified client certificate unavailable")
    valid_client(certificate)
    return hashlib.sha256(certificate).hexdigest()


def capture_login_evidence(
    channel, event, bearer, *, settings, otp_binding, authority, registry, gateway_id,
    source_id, key_id, signing_key,
):
    """Capture at the trusted gateway, using a provider receipt and the observed event."""
    fingerprint = client_fingerprint(channel)
    principal = asyncio.run(security._oidc_principal(
        HTTPAuthorizationCredentials(scheme="Bearer", credentials=bearer), settings,
    ))
    if (
        not otp_binding.matches(principal, bearer)
        or principal.subject != event.user.user_id or event.action != "LOGIN"
        or event.auth_context.authentication_result != "success" or event.auth_context.mfa != "success"
        or event.ground_truth is not None
    ):
        raise HTTPException(403, "Login evidence subject or exact OTP token did not match")
    authority(settings.oidc_issuer, principal)
    now = datetime.now(UTC)
    claims = security._decode_oidc_token(bearer, settings)
    token_issued = datetime.fromtimestamp(claims["iat"], UTC)
    if not token_issued <= event.timestamp <= now < token_issued + timedelta(seconds=30):
        raise HTTPException(403, "Login evidence must belong to the fresh OTP observation")
    assessment = registry.assess(SimpleNamespace(
        tenant_id=principal.tenant_id, gateway_id=gateway_id, user_id=principal.subject,
        device_id=event.device.device_id, client_certificate_sha256=fingerprint,
    ), now=now)
    if assessment.state == "unavailable":
        return None
    unsigned = SignedLoginEvidence(
        tenant_id=principal.tenant_id, source_id=source_id, key_id=key_id,
        event_digest_sha256=event_digest(event),
        device_state="known" if assessment.state == "active" else "revoked_verified_device",
        issued_at=now, expires_at=min(now + timedelta(seconds=30), otp_binding.expires_at),
        signature="A" * 86,
    )
    signature = base64.urlsafe_b64encode(signing_key.sign(canonical_login_evidence(unsigned)))
    return unsigned.model_copy(update={"signature": signature.decode().rstrip("=")})


@dataclass(frozen=True, slots=True)
class LoginAnalysisDelivery:
    response: httpx.Response
    evidence_state: Literal["verified", "missing", "expired", "queued"]
    committed: LoginDeliveryReceipt | None = None

    @property
    def result(self):
        if self.committed is not None:
            return self.committed.result.model_dump(mode="json")
        return None if self.evidence_state == "queued" else self.response.json()


class KeycloakLoginAnalysisCollector:
    """Submit the observed login from the same gateway that verified its evidence."""

    def __init__(
        self, analysis_client: httpx.Client, *, settings, authority, registry, gateway_id,
        source_id, key_id, signing_key, spool_path=None, tenant_id=None, collector_subject=None,
    ):
        target = urlsplit(str(analysis_client.base_url))
        if (
            not target.hostname or target.username is not None or target.password is not None
            or target.path not in {"", "/"} or target.query or target.fragment
            or (target.scheme != "https" and (
                target.scheme != "http" or target.hostname not in {"127.0.0.1", "::1", "localhost"}
            ))
        ):
            raise ValueError("login analysis requires a dedicated HTTPS or loopback HTTP origin")
        self.analysis_client = analysis_client
        self.settings = settings
        self.authority = authority
        self.registry = registry
        self.gateway_id = gateway_id
        self.source_id = source_id
        self.key_id = key_id
        self.signing_key = signing_key
        self.spool = None
        if spool_path is not None:
            if not tenant_id or not collector_subject:
                raise ValueError("durable login delivery requires the authenticated tenant and collector subject")
            self.spool = LoginDeliverySpool(
                spool_path, origin=str(analysis_client.base_url), tenant_id=tenant_id,
                collector_subject=collector_subject,
            )
        self._delivery_lock = Lock()

    def capture(self, channel, event, bearer, otp_binding):
        if otp_binding is None:
            return None
        return capture_login_evidence(
            channel, event, bearer, settings=self.settings, otp_binding=otp_binding,
            authority=self.authority, registry=self.registry, gateway_id=self.gateway_id,
            source_id=self.source_id, key_id=self.key_id, signing_key=self.signing_key,
        )

    def collect(self, channel, event, bearer, otp_binding):
        return self.submit(event, self.capture(channel, event, bearer, otp_binding))

    def submit(self, event, proof: SignedLoginEvidence | None):
        if event.action != "LOGIN" or event.ground_truth is not None:
            raise ValueError("collector requires an observed login event")
        if self.spool is not None:
            body = LoginDeliveryRequest(
                tenant_id=self.spool.tenant_id, collector_subject=self.spool.collector_subject,
                event=event, evidence=proof,
            )
            with self._delivery_lock:
                self.spool.enqueue(body)
                return self._send_pending(body)
        payload = event.analysis_payload()
        state = "missing"
        if proof is not None:
            response = self.analysis_client.post(
                "/analysis/verified-login", params={"report_expiry": "true"},
                json={"event": payload, "evidence": proof.model_dump(mode="json")},
                follow_redirects=False,
            )
            if response.status_code != 410 or response.json() != {"detail": LOGIN_EVIDENCE_EXPIRED}:
                response.raise_for_status()
                return LoginAnalysisDelivery(response, "verified")
            state = "expired"

        response = self.analysis_client.post("/analysis", json=payload, follow_redirects=False)
        response.raise_for_status()
        return LoginAnalysisDelivery(response, state)

    def _send_pending(self, body):
        queued = LoginAnalysisDelivery(httpx.Response(202), "queued")
        try:
            response = self.analysis_client.post(
                "/analysis/login-delivery", json=body.model_dump(mode="json"), follow_redirects=False,
            )
        except httpx.TransportError:
            return queued
        if response.status_code in {408, 429} or response.status_code >= 500:
            return queued
        if response.status_code != 200 and response.is_success:
            return queued  # An unexpected acknowledgement cannot remove an event.
        if response.status_code != 200:
            self.spool.hold(body, response.status_code)
            response.raise_for_status()
            return queued
        try:
            receipt = LoginDeliveryReceipt.model_validate_json(response.content)
        except ValidationError:
            return queued
        identity = LoginDeliveryIdentity.from_request(body)
        if (
            receipt.result.analysis_id != identity.analysis_id
            or receipt.result.login_delivery_sha256 != identity.payload_sha256
            or receipt.result.event_id != body.event.event_id
            or receipt.result.actor_id != body.collector_subject
            or receipt.result.tenant_id != body.tenant_id
        ):
            return queued
        self.spool.acknowledge(body)
        return LoginAnalysisDelivery(response, receipt.evidence_state, receipt)

    def flush_pending(self, *, limit=50):
        if self.spool is None:
            raise ValueError("configure a persistent login queue before replay")
        sent = 0
        for _ in range(limit):
            with self._delivery_lock:
                body = self.spool.peek()
                if body is None:
                    break
                try:
                    outcome = self._send_pending(body)
                except httpx.HTTPStatusError:
                    continue  # Rejected rows are retained separately from retryable work.
                if outcome.evidence_state == "queued":
                    break
                sent += 1
        return sent

    @contextmanager
    def replaying(self, *, interval=1):
        """Start with the existing queue and drain it again after short outages."""
        if self.spool is None or interval <= 0:
            raise ValueError("durable replay requires a persistent login queue and positive interval")
        stop = Event()

        def replay():
            while not stop.is_set():
                self.flush_pending()
                stop.wait(interval)

        worker = Thread(target=replay, name="keycloak-login-replay", daemon=True)
        worker.start()
        try:
            yield self
        finally:
            stop.set()
            worker.join()
