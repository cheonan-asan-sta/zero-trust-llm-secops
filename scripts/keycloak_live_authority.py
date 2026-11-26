"""Read-only current Keycloak authority for the disposable loopback gateway."""

from urllib.parse import quote, urlsplit

import httpx
from fastapi import HTTPException

from app.security import Principal


class KeycloakLiveAuthority:
    """Verify the signed session ID and token roles against the current provider state."""

    def __init__(self, issuer, client_id, client_secret, *, transport=None):
        url = urlsplit(issuer)
        prefix, separator, realm = url.path.rpartition("/realms/")
        if (
            url.scheme != "http"
            or url.hostname != "127.0.0.1"
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
            or not separator
            or not realm
            or "/" in realm
        ):
            raise ValueError("live authority requires a loopback Keycloak realm")
        self.issuer = issuer
        self.token_url = issuer + "/protocol/openid-connect/token"
        self.users_url = f"{url.scheme}://{url.netloc}{prefix}/admin/realms/{realm}/users"
        self.credentials = (client_id, client_secret)
        self.transport = transport

    def __call__(self, issuer: str, principal: Principal):
        if issuer != self.issuer or not principal.oidc_session_id:
            raise HTTPException(401, "Current provider session is required")
        subject_url = f"{self.users_url}/{quote(principal.subject, safe='')}"
        try:
            with httpx.Client(
                trust_env=False, follow_redirects=False, timeout=2, transport=self.transport
            ) as client:
                response = client.post(
                    self.token_url, auth=self.credentials, data={"grant_type": "client_credentials"}
                )
                response.raise_for_status()
                token = response.json()["access_token"]
                if not isinstance(token, str) or not token:
                    raise ValueError("Missing verifier token")
                headers = {"Authorization": f"Bearer {token}"}
                user = client.get(subject_url, headers=headers)
                if user.status_code == 404:
                    raise HTTPException(401, "Caller authority is revoked")
                user.raise_for_status()
                account = user.json()
                if not isinstance(account, dict) or account.get("id") != principal.subject:
                    raise ValueError("Invalid provider user response")
                if account.get("enabled") is False:
                    raise HTTPException(401, "Caller authority is revoked")
                if account.get("enabled") is not True:
                    raise ValueError("Invalid provider account status")

                role_response = client.get(
                    subject_url + "/role-mappings/realm/composite", headers=headers
                )
                role_response.raise_for_status()
                role_rows = role_response.json()
                if not isinstance(role_rows, list) or not all(
                    isinstance(row, dict) and isinstance(row.get("name"), str) for row in role_rows
                ):
                    raise ValueError("Invalid provider role response")
                roles = {row["name"] for row in role_rows}

                session_response = client.get(subject_url + "/sessions", headers=headers)
                session_response.raise_for_status()
                sessions = session_response.json()
                if not isinstance(sessions, list) or not all(
                    isinstance(row, dict) and isinstance(row.get("id"), str) for row in sessions
                ):
                    raise ValueError("Invalid provider session response")
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            raise HTTPException(503, "Current provider authority is unavailable") from exc
        if not any(row["id"] == principal.oidc_session_id for row in sessions):
            raise HTTPException(401, "Caller session is no longer active")
        if not {role.value for role in principal.roles} <= roles:
            raise HTTPException(401, "Caller roles changed since token issuance")
