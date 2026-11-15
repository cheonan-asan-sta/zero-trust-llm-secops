"""Signed service execution observations and independent policy facts; no grants."""

import base64
import hashlib
import math
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, field_validator, model_validator

from app.models import StrictModel
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.web_verified_context import SHA, Identifier, Window, public_bytes

Unit = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}\.service$")]
Token = Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
Mode = Literal["systemd", "local_process_lab"]
UInt = Annotated[int, Field(strict=True, ge=0, le=4294967294)]


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


class ServiceEvent(StrictModel):
    schema_version: Literal["zt-service-event-1"] = "zt-service-event-1"
    tenant_id: Identifier
    server_id: Identifier
    unit: Unit
    boot_id: Token
    invocation_id: Token
    event_id: SHA
    raw_sha256: SHA
    process_id: int = Field(strict=True, ge=1, le=4294967294)
    observed_at: datetime
    mode: Mode
    collection_basis: Literal["native_journal", "manager_snapshot", "local_process_lab"]

    @model_validator(mode="after")
    def origin_binding(self):
        require(
            (self.collection_basis == "local_process_lab") == (self.mode == "local_process_lab"),
            "service_collection_mode",
        )
        return self

    @field_validator("observed_at")
    @classmethod
    def aware(cls, value):
        return Window.aware(value)

    @field_validator("boot_id", "invocation_id")
    @classmethod
    def nonzero(cls, value):
        require(value != "0" * 32, "service_empty_binding")
        return value

    @property
    def sha256(self):
        return digest(self.model_dump(mode="json"))


class ProcessObservation(StrictModel):
    kind: Literal["runtime"] = "runtime"
    pid: int = Field(strict=True, ge=1, le=4294967294)
    start_ticks: int = Field(strict=True, ge=1)
    parent_pid: UInt
    real_uid: UInt
    effective_uid: UInt
    login_uid: UInt | None
    audit_session_id: UInt | None
    executable_sha256: SHA
    command_sha256: SHA
    argument_count: int = Field(strict=True, ge=1, le=256)
    parent_ref_sha256: SHA | None


class PolicyObservation(StrictModel):
    kind: Literal["authorization"] = "authorization"
    action: Literal["run_service_process"] = "run_service_process"
    decision: Literal["allow", "deny", "unknown"]
    policy_sha256: SHA
    policy_version: int = Field(strict=True, ge=1)
    executable_sha256: SHA
    command_sha256: SHA


class ServiceProof(Window):
    schema_version: Literal["zt-service-proof-1"] = "zt-service-proof-1"
    tenant_id: Identifier
    source_id: Identifier
    key_id: Identifier
    event_sha256: SHA
    observed_at: datetime
    observation: Annotated[ProcessObservation | PolicyObservation, Field(discriminator="kind")]
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$", repr=False)

    @field_validator("observed_at")
    @classmethod
    def aware_observation(cls, value):
        return Window.aware(value)


class ServiceAuthority(Window):
    tenant_id: Identifier
    source_id: Identifier
    key_id: Identifier
    kind: Literal["runtime", "authorization"]
    mode: Mode
    server_id: Identifier
    units: list[Unit] = Field(min_length=1, max_length=100)
    public_key: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    enabled: bool = Field(strict=True)


class ServiceRegistry(Window):
    schema_version: Literal["zt-service-registry-1"] = "zt-service-registry-1"
    version: int = Field(strict=True, ge=1)
    policy_sha256: SHA
    minimum_policy_version: int = Field(strict=True, ge=1)
    authorities: list[ServiceAuthority] = Field(min_length=2, max_length=100)


def proof_bytes(proof):
    return canonical(proof.model_dump(mode="json", exclude={"signature"}))


class PinnedServiceRegistry:
    def __init__(self, path, expected_sha256, *, minimum_version=1):
        require(
            isinstance(expected_sha256, str)
            and len(expected_sha256) == 64
            and set(expected_sha256) <= set("0123456789abcdef")
            and type(minimum_version) is int
            and minimum_version > 0,
            "service_registry_pin",
        )
        self.path, self.expected_sha256, self.minimum_version = (
            Path(path),
            expected_sha256,
            minimum_version,
        )

    def current(self, now):
        require(self.path.is_file() and not self.path.is_symlink(), "service_registry_file")
        with self.path.open("rb") as stream:
            raw = stream.read(256001)
        require(
            len(raw) <= 256000 and hashlib.sha256(raw).hexdigest() == self.expected_sha256,
            "service_registry_hash",
        )
        registry = ServiceRegistry.model_validate(decode(raw))
        require(
            registry.version >= self.minimum_version
            and registry.issued_at <= now < registry.expires_at
            and timedelta(0) < registry.expires_at - registry.issued_at <= timedelta(hours=24),
            "service_registry_window",
        )
        keys, identities, sources = set(), set(), {}
        for a in registry.authorities:
            key = public_bytes(a.public_key)
            identity = a.tenant_id, a.source_id, a.key_id
            source = a.tenant_id, a.source_id
            require(
                any(key)
                and key not in keys
                and identity not in identities
                and len(a.units) == len(set(a.units))
                and a.issued_at < a.expires_at
                and (source not in sources or sources[source] == a.kind),
                "service_authority_separation",
            )
            keys.add(key)
            identities.add(identity)
            sources[source] = a.kind
        return registry


@dataclass(frozen=True)
class ServiceFacts:
    state: str
    evidence_sha256: str | None = None
    duplicate: bool = False


class ServiceEvidenceJoiner:
    """Recheck pins/roles/freshness on every access; persist only bounded digests.

    The local SQLite store gives idempotency, not remote tamper/rollback proof.
    A copied or restored store is not a production anti-rollback authority.
    """

    def __init__(self, registry, ledger, *, capacity=10000, expected_mode="systemd"):
        require(
            isinstance(registry, PinnedServiceRegistry)
            and type(capacity) is int
            and 1 <= capacity <= 10000,
            "service_joiner_capacity",
        )
        require(expected_mode in {"systemd", "local_process_lab"}, "service_expected_mode")
        self.registry, self.path, self.capacity, self.mode = (
            registry,
            Path(ledger),
            capacity,
            expected_mode,
        )
        require(self.path.parent.is_dir() and not self.path.is_symlink(), "service_ledger_path")
        with self.connect() as con:
            con.execute(
                "CREATE TABLE IF NOT EXISTS observations (identity TEXT PRIMARY KEY, event TEXT NOT NULL, evidence TEXT NOT NULL, state TEXT NOT NULL)"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS clock (singleton INTEGER PRIMARY KEY CHECK(singleton=1), observed TEXT NOT NULL)"
            )

    @contextmanager
    def connect(self):
        require(not self.path.is_symlink(), "service_ledger_link")
        connection = sqlite3.connect(self.path, timeout=5)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def check(self, event, proofs, *, now=None):
        now = datetime.now(UTC) if now is None else now
        try:
            Window.aware(now)
            event = ServiceEvent.model_validate(event.model_dump())
            require(
                event.mode == self.mode
                and isinstance(proofs, (list, tuple))
                and len(proofs) == 2
                and timedelta(0) <= now - event.observed_at <= timedelta(seconds=30),
                "service_event_freshness",
            )
            registry = self.registry.current(now)
            observations, signed = {}, []
            for supplied in proofs:
                proof = ServiceProof.model_validate(supplied.model_dump())
                kind = proof.observation.kind
                require(
                    kind not in observations
                    and proof.tenant_id == event.tenant_id
                    and proof.event_sha256 == event.sha256,
                    "service_event_proof_binding",
                )
                matches = [
                    a
                    for a in registry.authorities
                    if (a.tenant_id, a.source_id, a.key_id, a.kind)
                    == (proof.tenant_id, proof.source_id, proof.key_id, kind)
                ]
                require(len(matches) == 1, "service_authority_role")
                authority = matches[0]
                require(
                    authority.enabled
                    and authority.server_id == event.server_id
                    and authority.mode == event.mode
                    and event.unit in authority.units,
                    "service_authority_scope",
                )
                require(
                    authority.issued_at
                    <= proof.observed_at
                    <= proof.issued_at
                    <= now
                    < authority.expires_at
                    and proof.issued_at < proof.expires_at <= authority.expires_at
                    and now < proof.expires_at
                    and proof.observed_at <= proof.issued_at
                    and timedelta(0) < proof.expires_at - proof.issued_at <= timedelta(seconds=30),
                    "service_proof_window",
                )
                if kind == "runtime":
                    require(
                        event.observed_at
                        <= proof.observed_at
                        <= event.observed_at + timedelta(seconds=5),
                        "service_runtime_time",
                    )
                else:
                    require(
                        event.observed_at - timedelta(seconds=30)
                        <= proof.observed_at
                        <= event.observed_at,
                        "service_policy_asof",
                    )
                signature = base64.urlsafe_b64decode(proof.signature + "==")
                require(
                    base64.urlsafe_b64encode(signature).decode().rstrip("=") == proof.signature,
                    "service_signature_encoding",
                )
                Ed25519PublicKey.from_public_bytes(public_bytes(authority.public_key)).verify(
                    signature, proof_bytes(proof)
                )
                observations[kind] = proof.observation
                signed.append(proof.model_dump(mode="json"))
            require(set(observations) == {"runtime", "authorization"}, "service_complete_proofs")
            runtime, policy = observations["runtime"], observations["authorization"]
            require(
                runtime.pid == event.process_id
                and runtime.executable_sha256 == policy.executable_sha256
                and runtime.command_sha256 == policy.command_sha256
                and policy.policy_sha256 == registry.policy_sha256
                and policy.policy_version >= registry.minimum_policy_version,
                "service_command_policy_binding",
            )
            require(self.registry.current(now) == registry, "service_registry_changed")
            state = (
                "adverse"
                if policy.decision == "deny"
                else "consistent"
                if policy.decision == "allow"
                else "review"
            )
            evidence = digest(sorted(signed, key=lambda v: v["observation"]["kind"]))
            identity = digest([event.tenant_id, event.server_id, event.mode, event.event_id])
            with self.connect() as con:
                con.execute("BEGIN IMMEDIATE")
                clock = con.execute("SELECT observed FROM clock WHERE singleton=1").fetchone()
                require(
                    clock is None or now >= datetime.fromisoformat(clock[0]),
                    "service_clock_regression",
                )
                con.execute(
                    "INSERT OR REPLACE INTO clock VALUES (1,?)", (now.astimezone(UTC).isoformat(),)
                )
                old = con.execute(
                    "SELECT event,evidence,state FROM observations WHERE identity=?", (identity,)
                ).fetchone()
                if old:
                    require(old == (event.sha256, evidence, state), "service_event_collision")
                    return ServiceFacts(state, evidence, True)
                require(
                    con.execute("SELECT count(*) FROM observations").fetchone()[0] < self.capacity,
                    "service_ledger_capacity",
                )
                con.execute(
                    "INSERT INTO observations VALUES (?,?,?,?)",
                    (identity, event.sha256, evidence, state),
                )
            return ServiceFacts(state, evidence)
        except (
            ValueError,
            TypeError,
            AttributeError,
            KeyError,
            OSError,
            sqlite3.Error,
            InvalidSignature,
            RecursionError,
        ):
            return ServiceFacts("unavailable")


def refine_service(previous, facts):
    require(
        isinstance(previous, OperationDecision) and previous.automatic_enforcement_allowed is False,
        "service_previous",
    )
    require(
        type(previous.alert) is bool
        and type(previous.review) is bool
        and all(
            type(v) in {int, float} and math.isfinite(v) and 0 <= v <= 1
            for v in (previous.baseline_score, previous.score)
        ),
        "service_previous_score",
    )
    require(
        isinstance(facts, ServiceFacts)
        and facts.state in {"adverse", "consistent", "review", "unavailable"},
        "service_facts",
    )
    if previous.alert or facts.state != "adverse":
        return previous
    return OperationDecision(
        previous.baseline_score,
        max(previous.score, 1.0),
        True,
        True,
        "verified_service_policy_denial_with_running_process",
    )


class VerifiedServiceRisk:
    def __init__(self, joiner):
        require(isinstance(joiner, ServiceEvidenceJoiner), "service_joiner")
        self.joiner = joiner

    def decide(self, previous, *, event=None, proofs=None, now=None):
        refine_service(previous, ServiceFacts("unavailable"))
        if event is None or proofs is None:
            return previous
        return refine_service(previous, self.joiner.check(event, proofs, now=now))
