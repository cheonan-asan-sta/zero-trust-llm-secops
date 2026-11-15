import base64
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.service_caller_identity import (
    PinnedCallerRegistry,
    ServiceCallerBroker,
    receipt_bytes,
    verify_identity,
    verify_receipt,
)
from scripts.f1_lab.shared_execution_collector import runtime_proof
from scripts.f1_lab.shared_execution_evidence import (
    PolicyObservation,
    ProcessObservation,
    ServiceEvent,
)
from scripts.run_shared_execution_controls import sign_policy
from scripts.run_systemd_caller_controls import setup_broker, token_for


def fixture(tmp_path):
    keys, service, identity, broker = setup_broker(tmp_path / "evidence", "fixture.service")

    def issue():
        return broker.issue(
            tenant_id="local-lab",
            server_id="shared-lab",
            unit="fixture.service",
            executable_sha256="a" * 64,
            command_sha256="b" * 64,
        )

    return keys, service, identity, broker, issue


def callbacks(keys, service):
    launches = []

    def authorize(request):
        return PolicyObservation(
            decision="allow",
            policy_sha256=service.policy_sha256,
            policy_version=1,
            executable_sha256=request.executable_sha256,
            command_sha256=request.command_sha256,
        ), datetime.now(UTC)

    def launch(request):
        launches.append(request.request_id)

    def collect(request):
        event = ServiceEvent(
            tenant_id=request.tenant_id,
            server_id=request.server_id,
            unit=request.unit,
            boot_id="1" * 32,
            invocation_id="2" * 32,
            process_id=42,
            event_id=request.authentication_nonce,
            raw_sha256="d" * 64,
            observed_at=datetime.now(UTC),
            mode="systemd",
            collection_basis="manager_snapshot",
        )
        observation = ProcessObservation(
            pid=42,
            start_ticks=1,
            parent_pid=1,
            real_uid=65534,
            effective_uid=65534,
            login_uid=None,
            audit_session_id=None,
            executable_sha256=request.executable_sha256,
            command_sha256=request.command_sha256,
            argument_count=3,
            parent_ref_sha256=None,
        )
        return event, runtime_proof(
            event, observation, keys["runtime"], source_id="local-proc", key_id="proc-1"
        )

    def permission(event, observation, observed):
        return sign_policy(
            event,
            observation,
            keys["authorization"],
            observed_at=observed,
            issued_at=datetime.now(UTC),
        )

    return {
        "authorize": authorize,
        "launch": launch,
        "collect": collect,
        "policy_proof": permission,
    }, launches


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://attacker.invalid"},
        {"aud": "wrong"},
        {"aud": ["local-systemd-broker"]},
        {"azp": "wrong"},
        {"sub": "fixture-machine"},
        {"sub": "unknown"},
        {"nonce": "bad"},
        {"auth_time": 1},
        {"iat": True},
        {"exp": True},
        {"auth_time": True},
        {"exp": 1},
        {"iat": 9999999999},
        {"nbf": 9999999999},
        {"nbf": True},
        {"exp": 9999999999},
        {"sub": ["fixture-person"]},
    ],
)
def test_wrong_identity_never_calls_launcher(tmp_path, claims):
    keys, service, identity, broker, issue = fixture(tmp_path)
    request = issue()
    handlers, launches = callbacks(keys, service)
    with pytest.raises((ValueError, jwt.PyJWTError)):
        broker.dispatch(request.request_id, token_for(request, identity, **claims), **handlers)
    assert not launches


@pytest.mark.parametrize("mode", ["key", "kid", "alg", "jku", "missing_nonce", "missing_auth_time"])
def test_untrusted_signatures_and_headers_are_rejected(tmp_path, mode):
    _, _, identity, broker, issue = fixture(tmp_path)
    request = issue()
    token = token_for(request, identity)
    if mode == "key":
        token = token_for(request, generate_private_key(public_exponent=65537, key_size=2048))
    else:
        claims = jwt.decode(token, options={"verify_signature": False})
        headers = {"kid": "fixture-rsa-1"}
        if mode == "kid":
            headers["kid"] = "unknown"
        elif mode == "jku":
            headers["jku"] = "https://attacker.invalid/keys"
        elif mode.startswith("missing_"):
            del claims[mode.removeprefix("missing_")]
        if mode == "alg":
            token = jwt.encode(
                claims, "test-only-long-symmetric-secret" * 2, algorithm="HS256", headers=headers
            )
        else:
            token = jwt.encode(claims, identity, algorithm="RS256", headers=headers)
    with pytest.raises((ValueError, jwt.PyJWTError)):
        verify_identity(
            token, request, broker.registry.current(datetime.now(UTC)), datetime.now(UTC)
        )


def test_nonce_commits_to_complete_request(tmp_path):
    _, _, identity, broker, issue = fixture(tmp_path)
    request, other = issue(), issue()
    r = broker.registry.current(datetime.now(UTC))
    token = token_for(request, identity)
    for changed in [
        other,
        request.model_copy(update={"unit": "other.service"}),
        request.model_copy(update={"command_sha256": "c" * 64}),
    ]:
        with pytest.raises(ValueError):
            verify_identity(token, changed, r, datetime.now(UTC))


def test_signed_receipt_binds_identity_and_native_evidence(tmp_path):
    keys, service, identity, broker, issue = fixture(tmp_path)
    request = issue()
    handlers, launches = callbacks(keys, service)
    receipt, event, proofs = broker.dispatch(
        request.request_id, token_for(request, identity), **handlers
    )
    assert launches == [request.request_id] and receipt.environment == "local_oidc"
    assert receipt.event_sha256 == event.sha256 and len(proofs) == 2
    assert receipt.request_sha256 == request.authentication_nonce
    signature = base64.urlsafe_b64decode(receipt.signature + "==")
    broker.key.public_key().verify(signature, receipt_bytes(receipt))
    assert verify_receipt(receipt, broker.registry, request, event) == receipt
    with pytest.raises(ValueError):
        verify_receipt(
            receipt, broker.registry, request, event.model_copy(update={"invocation_id": "3" * 32})
        )
    with pytest.raises(InvalidSignature):
        broker.key.public_key().verify(
            signature, receipt_bytes(receipt.model_copy(update={"event_sha256": "f" * 64}))
        )
    with broker.connect() as con:
        stored = " ".join(str(row) for row in con.execute("SELECT * FROM requests"))
    assert "fixture-person" not in stored and "eyJ" not in stored


def test_restart_and_concurrent_dispatch_never_start_twice(tmp_path):
    keys, service, identity, broker, issue = fixture(tmp_path)
    request = issue()
    token = token_for(request, identity)
    handlers, launches = callbacks(keys, service)

    def attempt(_):
        try:
            broker.dispatch(request.request_id, token, **handlers)
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(attempt, range(4))) == 1
    restarted = ServiceCallerBroker(broker.registry, broker.joiner, broker.path, broker.key)
    with pytest.raises(ValueError):
        restarted.dispatch(request.request_id, token, **handlers)
    assert launches == [request.request_id]


@pytest.mark.parametrize("failure", ["deny", "command", "crash", "collect", "forged_runtime"])
def test_failed_or_uncertain_dispatch_is_consumed_and_cannot_retry(tmp_path, failure):
    keys, service, identity, broker, issue = fixture(tmp_path)
    request = issue()
    handlers, launches = callbacks(keys, service)
    original_authorize, original_collect = handlers["authorize"], handlers["collect"]
    if failure in {"deny", "command"}:

        def changed(r):
            p, t = original_authorize(r)
            return p.model_copy(
                update={"decision": "deny"} if failure == "deny" else {"command_sha256": "c" * 64}
            ), t

        handlers["authorize"] = changed
    elif failure == "crash":

        def crash(r):
            launches.append(r.request_id)
            raise RuntimeError("test uncertain start")

        handlers["launch"] = crash
    else:

        def changed_collect(r):
            event, runtime = original_collect(r)
            if failure == "collect":
                return event.model_copy(update={"invocation_id": "3" * 32}), runtime
            return event, runtime.model_copy(update={"signature": "A" * 86})

        handlers["collect"] = changed_collect
    token = token_for(request, identity)
    with pytest.raises((ValueError, RuntimeError)):
        broker.dispatch(request.request_id, token, **handlers)
    restarted = ServiceCallerBroker(broker.registry, broker.joiner, broker.path, broker.key)
    with pytest.raises(ValueError):
        restarted.dispatch(request.request_id, token, **handlers)
    assert len(launches) == (0 if failure in {"deny", "command"} else 1)
    with broker.connect() as con:
        assert con.execute("SELECT state FROM requests").fetchone()[0] == "uncertain"


def test_local_issuer_is_rejected_by_default_operational_mode(tmp_path):
    _, _, _, broker, _ = fixture(tmp_path)
    production = PinnedCallerRegistry(broker.registry.path, broker.registry.sha256)
    with pytest.raises(ValueError):
        production.current(datetime.now(UTC))


@pytest.mark.parametrize(
    "mutation", ["disabled", "workload", "key", "private", "duplicate", "expired"]
)
def test_current_pin_and_directory_changes_are_not_ignored(tmp_path, mutation):
    _, _, identity, broker, issue = fixture(tmp_path)
    request = issue()
    data = json.loads(broker.registry.path.read_bytes())
    if mutation == "disabled":
        data["subjects"][0]["enabled"] = False
    elif mutation == "workload":
        data["subjects"][0]["kind"] = "workload"
    elif mutation == "key":
        data["jwks"]["keys"][0]["kid"] = "rotated"
    elif mutation == "private":
        data["jwks"]["keys"][0]["d"] = "forbidden"
    elif mutation == "duplicate":
        data["subjects"].append(data["subjects"][0])
    else:
        data["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    broker.registry.path.write_bytes(canonical(data))
    with pytest.raises(ValueError):
        broker.registry.current(datetime.now(UTC))
    import hashlib

    refreshed = PinnedCallerRegistry(
        broker.registry.path,
        hashlib.sha256(broker.registry.path.read_bytes()).hexdigest(),
        expected_environment="local_oidc",
    )
    with pytest.raises((ValueError, jwt.PyJWTError)):
        verify_identity(
            token_for(request, identity),
            request,
            refreshed.current(datetime.now(UTC)),
            datetime.now(UTC),
        )


def test_expiry_and_orphaned_launch_fail_closed(tmp_path):
    keys, service, identity, broker, issue = fixture(tmp_path)
    request = issue()
    handlers, launches = callbacks(keys, service)
    token = token_for(request, identity)
    with pytest.raises(ValueError):
        broker.dispatch(
            request.request_id, token, now=datetime.now(UTC) + timedelta(seconds=61), **handlers
        )
    with broker.connect() as con:
        con.execute("UPDATE requests SET state='launching'")
    restarted = ServiceCallerBroker(
        broker.registry, broker.joiner, broker.path, broker.key, capacity=1
    )
    with pytest.raises(ValueError):
        restarted.dispatch(request.request_id, token, **handlers)
    assert not launches


def test_persisted_clock_and_capacity_are_enforced_after_restart(tmp_path):
    keys, service, identity, broker, issue = fixture(tmp_path)
    request = issue()
    handlers, launches = callbacks(keys, service)
    future = datetime.now(UTC) + timedelta(seconds=2)
    broker.issue(
        tenant_id="local-lab",
        server_id="shared-lab",
        unit="fixture.service",
        executable_sha256="a" * 64,
        command_sha256="b" * 64,
        now=future,
    )
    restarted = ServiceCallerBroker(
        broker.registry, broker.joiner, broker.path, broker.key, capacity=2
    )
    with pytest.raises(ValueError, match="clock_regression"):
        restarted.dispatch(request.request_id, token_for(request, identity), **handlers)
    with pytest.raises(ValueError, match="capacity"):
        restarted.issue(
            tenant_id="local-lab",
            server_id="shared-lab",
            unit="fixture.service",
            executable_sha256="a" * 64,
            command_sha256="b" * 64,
            now=future,
        )
    assert not launches


def test_corrupt_database_does_not_dispatch(tmp_path):
    keys, service, identity, broker, issue = fixture(tmp_path)
    request = issue()
    handlers, launches = callbacks(keys, service)
    broker.path.write_bytes(b"corrupt")
    with pytest.raises(sqlite3.DatabaseError):
        broker.dispatch(request.request_id, token_for(request, identity), **handlers)
    assert not launches
