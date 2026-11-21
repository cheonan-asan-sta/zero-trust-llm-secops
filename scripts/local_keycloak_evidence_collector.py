"""Loopback Keycloak evidence collector for the local authorization acceptance suite."""

from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from jwt import InvalidTokenError, PyJWKClientError

from app import security
from app.models import AuthContext, EventAction
from app.zero_trust_models import SignedSessionSignal
from scripts.local_auth_attempt_lab import LocalAuthAttemptLab


@dataclass(frozen=True)
class ObservedSignIn:
    response: httpx.Response
    signal: SignedSessionSignal | None


class LocalKeycloakEvidenceCollector:
    """Issue an exact-attempt signal only from the configured local OTP realm."""

    def __init__(self, lab, settings, client):
        issuer = urlsplit(settings.oidc_issuer)
        if (
            issuer.scheme != "http"
            or issuer.hostname != "127.0.0.1"
            or issuer.username is not None
            or issuer.password is not None
            or issuer.query
            or issuer.fragment
        ):
            raise ValueError("the acceptance collector requires a loopback Keycloak issuer")
        self.lab = lab
        self.settings = settings
        self.client = client
        self.attempts = LocalAuthAttemptLab(lab)
        self.token_url = settings.oidc_issuer + "/protocol/openid-connect/token"
        self.metadata_url = settings.oidc_issuer + "/.well-known/openid-configuration"

    def sign_in(self, *, username, password, otp=None, action=EventAction.READ):
        key = "keycloak-" + uuid4().hex
        self.attempts.open(key, action=action)
        event = self.attempts.begin_authentication(key)
        form = {
            "grant_type": "password",
            "client_id": self.settings.oidc_audience,
            "username": username,
            "password": password,
            "scope": "openid",
        }
        if otp is not None:
            form["otp"] = otp
        response = self.client.post(self.token_url, data=form, follow_redirects=False)
        if response.status_code not in {200, 400}:
            return ObservedSignIn(response, None)
        try:
            body = response.json()
        except ValueError:
            return ObservedSignIn(response, None)
        if not isinstance(body, dict):
            return ObservedSignIn(response, None)
        if response.status_code == 200:
            token = body.get("id_token")
            if not isinstance(token, str) or not isinstance(body.get("access_token"), str):
                return ObservedSignIn(response, None)
            try:
                claims = security._decode_oidc_token(token, self.settings)
            except (InvalidTokenError, PyJWKClientError):
                return ObservedSignIn(response, None)
            if (
                not otp
                or claims.get("preferred_username") != username
                or claims.get(self.settings.oidc_tenant_claim) != self.lab.principal.tenant_id
            ):
                return ObservedSignIn(response, None)
            auth = AuthContext(authentication_result="success", mfa="success")
        elif body.get("error") == "invalid_grant":
            # Keycloak reports invalid_grant for multiple causes. Do not infer a factor failure.
            auth = AuthContext(authentication_result="failure", mfa="unknown", failed_attempts=1)
        else:
            return ObservedSignIn(response, None)
        event = event.model_copy(update={"auth_context": auth})
        return ObservedSignIn(response, self.lab.sign(event, key))

    def probe_readiness(self, event_id):
        return self.attempts.check_upstream(
            event_id, lambda: self.client.get(self.metadata_url, follow_redirects=False)
        )
