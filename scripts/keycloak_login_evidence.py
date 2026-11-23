"""Collector-side bridge from a verified Keycloak login and mTLS peer to analysis."""

import asyncio
import base64
import hashlib
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Literal
from urllib.parse import urlsplit

import httpx
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app import security
from app.services.session_analysis_evidence import event_digest
from app.services.trusted_signals import canonical_login_evidence
from app.zero_trust_models import LOGIN_EVIDENCE_EXPIRED, SignedLoginEvidence
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
    evidence_state: Literal["verified", "missing", "expired"]


class KeycloakLoginAnalysisCollector:
    """Submit the observed login from the same gateway that verified its evidence."""

    def __init__(
        self, analysis_client: httpx.Client, *, settings, authority, registry, gateway_id,
        source_id, key_id, signing_key,
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
