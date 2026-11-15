"""Request-bound OIDC identity for a trusted, one-shot systemd request broker.

ID tokens are accepted only by this authentication callback, never as API
access tokens. The broker's callbacks are trusted server configuration, not
request-supplied code. Identity is not authorization or proof of human presence.
"""

import base64
import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import Field, field_validator

from app.models import StrictModel
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_evidence import (
    PolicyObservation,
    ServiceEvent,
    ServiceEvidenceJoiner,
    Unit,
    digest,
)
from scripts.f1_lab.web_verified_context import SHA, Identifier, Window, public_bytes


class CallerSubject(StrictModel):
    subject: str = Field(min_length=1, max_length=255)
    tenant_id: Identifier
    kind: Literal["person", "workload"]
    enabled: bool = Field(strict=True)


class CallerRegistry(Window):
    schema_version: Literal["zt-service-caller-registry-1"] = "zt-service-caller-registry-1"
    version: int = Field(strict=True, ge=1)
    environment: Literal["local_oidc", "oidc"]
    issuer: str = Field(min_length=10, max_length=2048)
    audience: Identifier
    jwks: dict
    subjects: list[CallerSubject] = Field(min_length=1, max_length=1000)
    broker_public_key: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")


class PinnedCallerRegistry:
    """Administrator-pinned public trust bundle. No token-directed URL fetches."""

    def __init__(self, path, expected_sha256, *, expected_environment="oidc", minimum_version=1):
        require(
            isinstance(expected_sha256, str)
            and len(expected_sha256) == 64
            and set(expected_sha256) <= set("0123456789abcdef")
            and expected_environment in {"oidc", "local_oidc"}
            and type(minimum_version) is int
            and minimum_version > 0,
            "caller_registry_pin",
        )
        self.path = Path(path)
        self.sha256 = expected_sha256
        self.environment = expected_environment
        self.minimum_version = minimum_version

    def current(self, now):
        Window.aware(now)
        require(self.path.is_file() and not self.path.is_symlink(), "caller_registry_file")
        with self.path.open("rb") as stream:
            raw = stream.read(256001)
        require(
            len(raw) <= 256000 and hashlib.sha256(raw).hexdigest() == self.sha256,
            "caller_registry_hash",
        )
        r = CallerRegistry.model_validate(decode(raw))
        issuer = urlsplit(r.issuer)
        require(
            r.environment == self.environment
            and r.version >= self.minimum_version
            and r.issued_at <= now < r.expires_at
            and timedelta(0) < r.expires_at - r.issued_at <= timedelta(hours=24)
            and r.issuer.startswith("https://")
            and not any(c in r.issuer for c in "?#@")
            and not r.issuer.endswith("/")
            and issuer.hostname
            and issuer.scheme == "https"
            and (r.environment != "oidc" or not issuer.hostname.endswith(".invalid")),
            "caller_registry_scope",
        )
        require(any(public_bytes(r.broker_public_key)), "caller_broker_key")
        require(set(r.jwks) == {"keys"} and isinstance(r.jwks["keys"], list), "caller_jwks")
        keys, materials = set(), set()
        require(1 <= len(r.jwks["keys"]) <= 10, "caller_key_count")
        for key in r.jwks["keys"]:
            require(
                isinstance(key, dict)
                and set(key) == {"kty", "kid", "use", "alg", "n", "e"}
                and key["kty"] == "RSA"
                and key["alg"] == "RS256"
                and key["use"] == "sig"
                and isinstance(key["kid"], str)
                and 0 < len(key["kid"]) <= 128
                and key["kid"] not in keys,
                "caller_public_signing_key",
            )
            parsed = jwt.PyJWK.from_dict(key, algorithm="RS256").key
            require(parsed.key_size >= 2048, "caller_rsa_strength")
            material = parsed.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            require(material not in materials, "caller_duplicate_key")
            keys.add(key["kid"])
            materials.add(material)
        identities = [(s.tenant_id, s.subject) for s in r.subjects]
        require(len(identities) == len(set(identities)), "caller_subject_directory")
        return r


class ServiceRequest(Window):
    schema_version: Literal["zt-service-request-1"] = "zt-service-request-1"
    request_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    nonce: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$", repr=False)
    tenant_id: Identifier
    server_id: Identifier
    unit: Unit
    executable_sha256: SHA
    command_sha256: SHA

    @property
    def authentication_nonce(self):
        # OIDC nonce commits to every field, including random nonce and expiry.
        return digest(self.model_dump(mode="json"))


class CallerReceipt(StrictModel):
    schema_version: Literal["zt-service-caller-receipt-1"] = "zt-service-caller-receipt-1"
    environment: Literal["local_oidc", "oidc"]
    request_sha256: SHA
    event_sha256: SHA
    service_evidence_sha256: SHA
    caller_ref_sha256: SHA
    registry_sha256: SHA
    authenticated_at: datetime
    bound_at: datetime
    relationship: Literal["broker_mediated_start"] = "broker_mediated_start"
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$", repr=False)

    @field_validator("authenticated_at", "bound_at")
    @classmethod
    def aware(cls, value):
        return Window.aware(value)


def receipt_bytes(receipt):
    return canonical(receipt.model_dump(mode="json", exclude={"signature"}))


def verify_receipt(receipt, pinned, request, event, *, now=None):
    """Verify a fresh broker association; never treat its presence as permission."""
    now = datetime.now(UTC) if now is None else now
    registry = pinned.current(now)
    receipt = CallerReceipt.model_validate(receipt.model_dump())
    request = ServiceRequest.model_validate(request.model_dump())
    event = ServiceEvent.model_validate(event.model_dump())
    require(
        receipt.environment == registry.environment
        and receipt.registry_sha256 == pinned.sha256
        and receipt.request_sha256 == request.authentication_nonce
        and receipt.event_sha256 == event.sha256
        and (event.tenant_id, event.server_id, event.unit, event.mode)
        == (request.tenant_id, request.server_id, request.unit, "systemd")
        and int(request.issued_at.timestamp())
        <= receipt.authenticated_at.timestamp()
        <= event.observed_at.timestamp()
        <= receipt.bound_at.timestamp()
        <= now.timestamp()
        and now < request.expires_at
        and any(
            s.enabled
            and s.kind == "person"
            and s.tenant_id == request.tenant_id
            and digest([registry.issuer, s.tenant_id, s.subject]) == receipt.caller_ref_sha256
            for s in registry.subjects
        ),
        "caller_receipt_binding",
    )
    signature = base64.urlsafe_b64decode(receipt.signature + "==")
    require(
        base64.urlsafe_b64encode(signature).decode().rstrip("=") == receipt.signature,
        "caller_receipt_signature_encoding",
    )
    Ed25519PublicKey.from_public_bytes(public_bytes(registry.broker_public_key)).verify(
        signature, receipt_bytes(receipt)
    )
    require(pinned.current(now) == registry, "caller_registry_changed")
    return receipt


def verify_identity(token, request, registry, now):
    """Fresh request-bound ID token plus independently configured person directory."""
    require(isinstance(token, str) and 0 < len(token) <= 16384, "caller_token_bound")
    header = jwt.get_unverified_header(token)
    require(
        set(header) <= {"alg", "kid", "typ"}
        and header.get("alg") == "RS256"
        and header.get("typ", "JWT") == "JWT",
        "caller_token_header",
    )
    keys = [k for k in registry.jwks["keys"] if k["kid"] == header.get("kid")]
    require(len(keys) == 1, "caller_token_key")
    # Time is checked against the supplied trusted clock below, allowing tests
    # to be reproducible without globally patching PyJWT's clock.
    claims = jwt.decode(
        token,
        jwt.PyJWK.from_dict(keys[0], algorithm="RS256").key,
        algorithms=["RS256"],
        issuer=registry.issuer,
        audience=registry.audience,
        options={
            "require": ["iss", "sub", "aud", "iat", "exp", "auth_time", "nonce"],
            "verify_exp": False,
            "verify_iat": False,
            "verify_nbf": False,
            "strict_aud": True,
        },
    )
    seconds = now.timestamp()
    require(
        all(type(claims[k]) is int for k in ["iat", "exp", "auth_time"])
        and ("nbf" not in claims or type(claims["nbf"]) is int)
        and int(request.issued_at.timestamp()) <= claims["auth_time"] <= claims["iat"] <= seconds
        and seconds < claims["exp"] <= claims["iat"] + 60
        and claims.get("nbf", claims["iat"]) <= seconds
        and claims.get("azp", registry.audience) == registry.audience
        and secrets.compare_digest(str(claims["nonce"]), request.authentication_nonce),
        "caller_token_fresh_request",
    )
    matches = [
        s
        for s in registry.subjects
        if s.subject == claims["sub"] and s.tenant_id == request.tenant_id
    ]
    require(
        len(matches) == 1 and matches[0].enabled and matches[0].kind == "person",
        "caller_not_registered_person",
    )
    return digest([registry.issuer, request.tenant_id, claims["sub"]]), claims["auth_time"]


class ServiceCallerBroker:
    """One-shot dispatch. After a crash/uncertain launch, never automatically retry.

    This SQLite ledger assumes a trusted local host; it is not a distributed
    lock, remote attestation, or rollback-proof audit store. The configured PDP,
    launcher and collector must not be exposed as caller-controlled callbacks.
    """

    def __init__(self, registry, service_joiner, ledger, signing_key, *, capacity=10000):
        require(
            isinstance(registry, PinnedCallerRegistry)
            and isinstance(service_joiner, ServiceEvidenceJoiner)
            and service_joiner.mode == "systemd"
            and type(capacity) is int
            and 1 <= capacity <= 10000,
            "caller_broker_configuration",
        )
        self.registry, self.joiner = registry, service_joiner
        self.path, self.key, self.capacity = Path(ledger), signing_key, capacity
        require(self.path.parent.is_dir(), "caller_ledger_parent")
        with self.connect() as con:
            con.execute(
                "CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, body TEXT NOT NULL, scope TEXT NOT NULL, state TEXT NOT NULL, receipt TEXT)"
            )
            con.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS launching_scope ON requests(scope) WHERE state='launching'"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS clock (singleton INTEGER PRIMARY KEY CHECK(singleton=1), observed TEXT NOT NULL)"
            )

    @contextmanager
    def connect(self):
        require(not self.path.is_symlink(), "caller_ledger_link")
        con = sqlite3.connect(self.path, timeout=5)
        try:
            with con:
                yield con
        finally:
            con.close()

    def trust(self, now):
        r = self.registry.current(now)
        public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        require(public == public_bytes(r.broker_public_key), "caller_signer_pin")
        service = self.joiner.registry.current(now)
        require(
            public not in {public_bytes(a.public_key) for a in service.authorities},
            "caller_signer_role_separation",
        )
        return r

    @staticmethod
    def tick(con, now):
        Window.aware(now)
        old = con.execute("SELECT observed FROM clock WHERE singleton=1").fetchone()
        require(old is None or now >= datetime.fromisoformat(old[0]), "caller_clock_regression")
        con.execute("INSERT OR REPLACE INTO clock VALUES (1,?)", (now.astimezone(UTC).isoformat(),))

    def issue(self, *, tenant_id, server_id, unit, executable_sha256, command_sha256, now=None):
        now = datetime.now(UTC) if now is None else now
        self.trust(now)
        r = ServiceRequest(
            request_id=secrets.token_hex(16),
            nonce=secrets.token_urlsafe(32),
            tenant_id=tenant_id,
            server_id=server_id,
            unit=unit,
            executable_sha256=executable_sha256,
            command_sha256=command_sha256,
            issued_at=now,
            expires_at=now + timedelta(seconds=60),
        )
        service = self.joiner.registry.current(now)
        for role in ("runtime", "authorization"):
            require(
                any(
                    a.enabled
                    and a.kind == role
                    and a.mode == "systemd"
                    and (a.tenant_id, a.server_id) == (tenant_id, server_id)
                    and unit in a.units
                    and a.issued_at <= now < a.expires_at
                    for a in service.authorities
                ),
                "caller_service_scope",
            )
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            self.tick(con, now)
            require(
                con.execute("SELECT count(*) FROM requests").fetchone()[0] < self.capacity,
                "caller_capacity",
            )
            con.execute(
                "INSERT INTO requests VALUES (?,?,?,'pending',NULL)",
                (
                    r.request_id,
                    canonical(r.model_dump(mode="json")).decode(),
                    digest([tenant_id, server_id, unit]),
                ),
            )
        return r

    def dispatch(self, request_id, token, *, authorize, launch, collect, policy_proof, now=None):
        """Verify person, then PDP, then launch once; bind fresh native evidence.

        authorize(request) -> (PolicyObservation, actual_observed_at)
        launch(request) -> None (must reject already-running units)
        collect(request) -> (ServiceEvent, runtime ServiceProof)
        policy_proof(event, observation, observed_at) -> authorization ServiceProof
        """
        now = datetime.now(UTC) if now is None else now
        registry = self.trust(now)
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            self.tick(con, now)
            row = con.execute(
                "SELECT body,state FROM requests WHERE id=?", (request_id,)
            ).fetchone()
            require(row is not None and row[1] == "pending", "caller_request_not_pending")
            request = ServiceRequest.model_validate(json.loads(row[0]))
            require(request.issued_at <= now < request.expires_at, "caller_request_expired")
            actor, auth_time = verify_identity(token, request, registry, now)
            # Reserve before contacting the trusted PDP or manager. An error
            # consumes this request; it never becomes a retryable start.
            con.execute("UPDATE requests SET state='launching' WHERE id=?", (request_id,))
        try:
            observation, policy_time = authorize(request)
            observation = PolicyObservation.model_validate(observation.model_dump())
            Window.aware(policy_time)
            service = self.joiner.registry.current(datetime.now(UTC))
            require(
                observation.decision == "allow"
                and observation.policy_sha256 == service.policy_sha256
                and observation.policy_version >= service.minimum_policy_version
                and observation.executable_sha256 == request.executable_sha256
                and observation.command_sha256 == request.command_sha256
                and now <= policy_time <= datetime.now(UTC)
                and self.trust(datetime.now(UTC)) == registry
                and datetime.now(UTC) < request.expires_at,
                "caller_prior_authorization",
            )
            launch(request)
            event, runtime = collect(request)
            event = ServiceEvent.model_validate(event.model_dump())
            require(
                (event.tenant_id, event.server_id, event.unit, event.mode)
                == (request.tenant_id, request.server_id, request.unit, "systemd")
                and policy_time <= event.observed_at < request.expires_at
                and runtime.observation.command_sha256 == request.command_sha256
                and runtime.observation.executable_sha256 == request.executable_sha256,
                "caller_launched_execution_binding",
            )
            permission = policy_proof(event, observation, policy_time)
            bound_at = datetime.now(UTC)
            facts = self.joiner.check(event, [runtime, permission], now=bound_at)
            require(
                facts.state == "consistent"
                and not facts.duplicate
                and self.trust(bound_at) == registry
                and bound_at < request.expires_at,
                "caller_complete_native_evidence",
            )
            receipt = CallerReceipt(
                environment=registry.environment,
                request_sha256=request.authentication_nonce,
                event_sha256=event.sha256,
                service_evidence_sha256=facts.evidence_sha256,
                caller_ref_sha256=actor,
                registry_sha256=self.registry.sha256,
                authenticated_at=datetime.fromtimestamp(auth_time, UTC),
                bound_at=bound_at,
                signature="A" * 86,
            )
            receipt = receipt.model_copy(
                update={
                    "signature": base64.urlsafe_b64encode(self.key.sign(receipt_bytes(receipt)))
                    .decode()
                    .rstrip("=")
                }
            )
            with self.connect() as con:
                con.execute("BEGIN IMMEDIATE")
                self.tick(con, bound_at)
                con.execute(
                    "UPDATE requests SET state='bound',receipt=? WHERE id=? AND state='launching'",
                    (
                        canonical(receipt.model_dump(mode="json")).decode(),
                        request_id,
                    ),
                )
            return receipt, event, [runtime, permission]
        except Exception:
            with self.connect() as con:
                con.execute(
                    "UPDATE requests SET state='uncertain' WHERE id=? AND state='launching'",
                    (request_id,),
                )
            raise
