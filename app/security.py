import asyncio
import hashlib
import hmac
import re
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Annotated, Any

import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError, PyJWKClient, PyJWKClientConnectionError, PyJWKClientError

from app.config import Settings, get_settings


class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    RESPONDER = "responder"
    ADMIN = "admin"


_ROLE_IMPLICATIONS = {
    Role.VIEWER: {Role.VIEWER},
    Role.ANALYST: {Role.VIEWER, Role.ANALYST},
    Role.RESPONDER: {Role.VIEWER, Role.ANALYST, Role.RESPONDER},
    Role.ADMIN: set(Role),
}


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: str
    roles: frozenset[Role]
    auth_method: str

    @property
    def effective_roles(self) -> frozenset[Role]:
        expanded: set[Role] = set()
        for role in self.roles:
            expanded.update(_ROLE_IMPLICATIONS[role])
        return frozenset(expanded)


_bearer = HTTPBearer(auto_error=False)
_TENANT_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")


@lru_cache(maxsize=8)
def _jwks_client(url: str) -> PyJWKClient:
    return PyJWKClient(url, cache_jwk_set=True, lifespan=300)


def _unauthorized(detail: str = "Authentication required") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _parse_roles(value: object) -> frozenset[Role]:
    if isinstance(value, str):
        candidates = value.replace(",", " ").split()
    elif isinstance(value, list):
        candidates = [item for item in value if isinstance(item, str)]
    else:
        candidates = []
    roles = {Role(candidate.lower()) for candidate in candidates if candidate.lower() in Role._value2member_map_}
    if not roles:
        raise _unauthorized("Token does not contain an allowed role")
    return frozenset(roles)


def _api_key_principal(api_key: str | None, settings: Settings) -> Principal:
    if not api_key or settings.api_key_sha256 is None:
        raise _unauthorized()
    actual_digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    expected_digest = settings.api_key_sha256.get_secret_value().lower()
    if not hmac.compare_digest(actual_digest, expected_digest):
        raise _unauthorized("Invalid API credential")
    return Principal(
        subject=settings.api_key_subject,
        tenant_id=settings.api_key_tenant_id,
        roles=_parse_roles(settings.api_key_role_list),
        auth_method="api_key",
    )


def _decode_oidc_token(token: str, settings: Settings) -> dict[str, Any]:
    if not settings.oidc_jwks_url or not settings.oidc_issuer or not settings.oidc_audience:
        raise _unauthorized("OIDC is not configured")
    client = _jwks_client(settings.oidc_jwks_url)
    signing_key = client.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=settings.oidc_audience,
        issuer=settings.oidc_issuer,
        options={"require": ["exp", "iat", "sub"]},
    )


async def _oidc_principal(
    credentials: HTTPAuthorizationCredentials | None,
    settings: Settings,
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()
    try:
        claims = await asyncio.to_thread(_decode_oidc_token, credentials.credentials, settings)
        subject = str(claims["sub"])
        tenant_id = str(claims[settings.oidc_tenant_claim])
        roles = _parse_roles(claims.get(settings.oidc_roles_claim))
    except HTTPException:
        raise
    except PyJWKClientConnectionError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Identity provider is temporarily unavailable",
        ) from exc
    except (InvalidTokenError, PyJWKClientError, KeyError, TypeError, ValueError) as exc:
        raise _unauthorized("Invalid identity token") from exc
    if not subject or not _TENANT_PATTERN.fullmatch(tenant_id):
        raise _unauthorized("Token identity claims are invalid")
    return Principal(
        subject=subject[:128],
        tenant_id=tenant_id,
        roles=roles,
        auth_method="oidc",
    )


async def get_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> Principal:
    settings = get_settings()
    if settings.auth_mode == "disabled":
        principal = Principal(
            subject="local-operator",
            tenant_id="local",
            roles=frozenset({Role.ADMIN}),
            auth_method="disabled",
        )
    elif settings.auth_mode == "api_key":
        principal = _api_key_principal(api_key, settings)
    else:
        principal = await _oidc_principal(credentials, settings)
    request.state.principal = principal
    return principal


def require_roles(*required: Role):
    async def authorize(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
        if not principal.effective_roles.intersection(required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role for this operation",
            )
        return principal

    return authorize
