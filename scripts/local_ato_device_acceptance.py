"""Use the same verified Keycloak login and an actual mTLS peer for ATO review."""

import asyncio
import hashlib
import json
import secrets
import ssl
from datetime import UTC, datetime, timedelta
from http.client import HTTPSConnection
from http.server import ThreadingHTTPServer
from threading import Lock, Thread
from time import monotonic
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app import security
from app.services.account_takeover import Device, Factor, Takeover, assess_login
from scripts import mtls_fixtures
from scripts.evaluate_local_remote_holdout import write
from scripts.evaluate_rba_ato_separation import network_change
from scripts.f1_lab.login_environment import Change
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.vpn_enrollment import PinnedVPNEnrollments
from scripts.keycloak_login_evidence import client_fingerprint
from scripts.mtls_transport import Quiet

GATEWAY = "ato-loopback"


def device_from_peer(channel, registry, principal, now, device_ids=None):
    fingerprint = client_fingerprint(channel)
    enrollment = registry.assess(
        SimpleNamespace(
            tenant_id=principal.tenant_id,
            gateway_id=GATEWAY,
            user_id=principal.subject,
            device_id=(device_ids or {}).get(fingerprint, fingerprint),
            client_certificate_sha256=fingerprint,
        ),
        now=now,
    )
    return {"active": Device.KNOWN, "revoked": Device.REVOKED, "unavailable": Device.UNKNOWN}[
        enrollment.state
    ]


def _material(root, name, bundle):
    cert, key = root / f"{name}.crt", root / f"{name}.key"
    cert.write_text(bundle["cert"], encoding="ascii")
    key.write_text(bundle["key"], encoding="ascii")
    return str(cert), str(key)


def exercise(
    root, *, settings, binding, token, other_token, authority, pattern_report, warning,
    revoke_session=None,
):
    """Run paired controls with real key possession and provider MFA, using scoped test conditions."""
    root.mkdir()
    patterns = [
        row["environment_flags"]
        for row in pattern_report["controlled_patterns"]
        for _ in range(row["rows"])
    ]
    if len(patterns) != 7 or any(
        not network_change(flags) or flags & Change.CHANGED_OS for flags in patterns
    ):
        raise ValueError("expected seven prior priority residual patterns")
    ca = mtls_fixtures.authority("Ephemeral ATO review CA")
    ca_path = root / "ca.crt"
    ca_path.write_bytes(ca[1].public_bytes(serialization.Encoding.PEM))
    server_cert = _material(root, "server", mtls_fixtures.leaf(ca, "localhost", server=True))
    clients = {
        name: mtls_fixtures.leaf(ca, name)
        for name in ("approved", "revoked", "foreign-account", "unregistered")
    }
    device_ids = {}
    if revoke_session is not None:
        for name, device_id in (
            ("first", "fixture-device-a"),
            ("replacement", "fixture-device-b"),
            ("reenrolled", "fixture-device-b"),
        ):
            clients[name] = mtls_fixtures.leaf(ca, name)
            device_ids[clients[name]["fingerprint"]] = device_id
    contexts = {}
    for name, bundle in clients.items():
        client = ssl.create_default_context(cafile=str(ca_path))
        client.load_cert_chain(*_material(root, name, bundle))
        contexts[name] = client
    contexts["no-certificate"] = ssl.create_default_context(cafile=str(ca_path))
    gate = Lock()
    enabled = {"approved": True, "revoked": False, "foreign-account": True}
    version = 0
    registry = None

    def publish_registry(**updates):
        nonlocal registry, version
        now = datetime.now(UTC)
        version += 1
        enabled.update(updates)
        bindings = []
        for name, is_enabled in enabled.items():
            certificate = clients[name]["fingerprint"]
            bindings.append({
                "tenant_id": binding.tenant,
                "gateway_id": GATEWAY,
                "user_id": binding.subject if name != "foreign-account" else "separate-fixture-subject",
                "device_id": device_ids.get(certificate, certificate),
                "client_certificate_sha256": certificate,
                "enabled": is_enabled,
            })
        config_path = root / f"enrollments-v{version}.json"
        write(
            config_path,
            {
                "schema_version": "zt-vpn-enrollments-1",
                "version": version,
                "issued_at": (now - timedelta(seconds=1)).isoformat(),
                "expires_at": (now + timedelta(minutes=5)).isoformat(),
                "bindings": bindings,
            },
        )
        candidate = PinnedVPNEnrollments(
            config_path, hashlib.sha256(config_path.read_bytes()).hexdigest(), minimum_version=version
        )
        with gate:
            registry = candidate

    publish_registry()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.verify_mode = ssl.CERT_REQUIRED
    tls.verify_flags |= ssl.VERIFY_X509_STRICT
    tls.load_verify_locations(cafile=str(ca_path))
    tls.load_cert_chain(*server_cert)
    pending = {}

    class Handler(Quiet):
        def do_POST(self):
            self.connection.settimeout(4)
            scheme, _, presented = self.headers.get("Authorization", "").partition(" ")
            auth = (
                HTTPAuthorizationCredentials(scheme=scheme, credentials=presented)
                if presented
                else None
            )
            try:
                principal = asyncio.run(security._oidc_principal(auth, settings))
                if not binding.matches(principal, presented):
                    raise HTTPException(403)
                authority(settings.oidc_issuer, principal)
                with gate:
                    challenge = pending.pop(self.path, None)
                    current_registry = registry
                if challenge is None or monotonic() >= challenge[1]:
                    raise HTTPException(409)
                device = device_from_peer(
                    self.connection, current_registry, principal, datetime.now(UTC), device_ids
                )
                if not binding.matches(principal, presented):
                    raise HTTPException(403)
            except HTTPException as error:
                self.reply(error.status_code)
                return
            except ValueError:
                self.reply(403)
                return
            flags = challenge[0]
            review = assess_login(
                warning=warning,
                success=True,
                environment_change=network_change(flags),
                factor=Factor.VERIFIED,
                device=device,
            )
            old_priority = network_change(flags) and bool(flags & Change.CHANGED_OS)
            self.reply(
                200,
                json.dumps(
                    {
                        "device": device.value,
                        "previous_priority": old_priority,
                        "new_priority": old_priority or review.takeover is Takeover.PRIORITY_REVIEW,
                        "still_reviewed": review.takeover is not Takeover.NO_SIGNAL,
                        "warning": review.repeated_failure_warning,
                    }
                ).encode(),
            )

    def issue(flags, lifetime=60):
        path = "/ato/" + secrets.token_urlsafe(24)
        with gate:
            pending[path] = flags, monotonic() + lifetime
        return path

    def request(port, path, device, bearer=token):
        connection = HTTPSConnection("localhost", port, context=contexts[device], timeout=5)
        try:
            connection.request(
                "POST", path, headers={"Authorization": "Bearer " + bearer} if bearer else {}
            )
            response = connection.getresponse()
            return response.status, json.loads(response.read(4096))
        finally:
            connection.close()

    def check_lifecycle(port, flags):
        previous, current = counts(), counts()
        cases = {}

        def observe(name, path, client, expected):
            status, result = request(port, path, client)
            assert status == 200 and result["device"] == expected, (name, status, result)
            assert result["still_reviewed"] and result["warning"] == warning, name
            cases[name] = {"http_status": status, **result}
            return result

        def score(name, path, client, expected):
            result = observe(name, path, client, expected)
            needs_priority = expected is Device.REVOKED
            assert result["new_priority"] == needs_priority, name
            record(previous, needs_priority, result["previous_priority"])
            record(current, needs_priority, result["new_priority"])

        unregistered = observe("before_registration", issue(flags), "first", Device.UNKNOWN)
        assert not unregistered["new_priority"]
        publish_registry(first=True)
        score("new_device_registered", issue(flags), "first", Device.KNOWN)

        issued_before_replacement = issue(flags)
        publish_registry(first=False, replacement=True)
        score("retired_device_after_replacement", issued_before_replacement, "first", Device.REVOKED)
        score("new_replacement_device", issue(flags), "replacement", Device.KNOWN)

        issued_before_revocation = issue(flags)
        publish_registry(replacement=False)
        score("first_request_after_device_revocation", issued_before_revocation, "replacement", Device.REVOKED)
        publish_registry(reenrolled=True)
        score("old_certificate_after_reenrollment", issue(flags), "replacement", Device.REVOKED)
        score("reenrolled_device_new_certificate", issue(flags), "reenrolled", Device.KNOWN)

        issued_before_session_revocation = issue(flags)
        revoke_status = revoke_session()
        status, result = request(port, issued_before_session_revocation, "reenrolled")
        assert status == 401 and not result, (status, result)
        signed_principal = asyncio.run(security._oidc_principal(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=token), settings
        ))
        assert binding.matches(signed_principal, token)
        return {
            "registry_versions": version,
            "cases": cases,
            "before": metrics(previous),
            "after": metrics(current),
            "keycloak_session_revocation": {
                "admin_http_status": revoke_status,
                "first_request_http_status": status,
                "revoked_token_still_passed_signed_claims_and_otp_binding": True,
                "decision_returned": bool(result),
            },
        }

    before, after = counts(), counts()
    lifecycle = None
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        port = server.server_address[1]
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for flags in patterns:
                for device, label in (("approved", False), ("revoked", True)):
                    status, observed = request(port, issue(flags), device)
                    assert (
                        status == 200
                        and observed["still_reviewed"]
                        and observed["warning"] == warning
                    )
                    assert observed["device"] == (Device.REVOKED if label else Device.KNOWN)
                    record(before, label, observed["previous_priority"])
                    record(after, label, observed["new_priority"])
            flags = patterns[0]
            for device in ("unregistered", "foreign-account"):
                status, observed = request(port, issue(flags), device)
                assert (
                    status == 200
                    and observed["device"] == Device.UNKNOWN
                    and not observed["new_priority"]
                )
            old_detection = issue(flags | Change.CHANGED_OS)
            status, observed = request(port, old_detection, "approved")
            assert status == 200 and observed["previous_priority"] and observed["new_priority"]
            assert request(port, old_detection, "approved")[0] == 409
            assert request(port, issue(flags, -1), "revoked")[0] == 409
            assert request(port, issue(flags), "revoked", other_token)[0] == 403
            assert request(port, issue(flags), "revoked", "")[0] == 401
            try:
                request(port, issue(flags), "no-certificate")
            except (OSError, ssl.SSLError):
                pass
            else:
                raise AssertionError("device test accepted the connection without a certificate")
            if revoke_session is not None:
                lifecycle = check_lifecycle(port, flags)
        finally:
            server.shutdown()
            thread.join(timeout=5)
    assert before["fn"] == after["tp"] == 7 and after["fp"] == 0
    return {
        "scope": "paired local laboratory scenarios with one real OTP session; controlled risk labels",
        "before": metrics(before),
        "after": metrics(after),
        "actual_provider_otp_verified": True,
        "actual_mtls_client_proof": True,
        "pinned_device_enrollment": True,
        "existing_priority_retained": 1,
        "unregistered_and_foreign_scope_remained_review": 2,
        "rejected_replay_expiry_other_session_missing_token_missing_certificate": 5,
        **({"device_lifecycle": lifecycle} if lifecycle is not None else {}),
    }
