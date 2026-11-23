"""Collector-side bridge from a verified Keycloak login and mTLS peer to analysis."""

import asyncio
import base64
import hashlib
import ssl
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app import security
from app.services.session_analysis_evidence import event_digest
from app.services.trusted_signals import canonical_login_evidence
from app.zero_trust_models import SignedLoginEvidence
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
