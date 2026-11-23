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
from scripts import mtls_fixtures
from scripts.evaluate_local_remote_holdout import write
from scripts.evaluate_rba_ato_separation import network_change
from scripts.f1_lab.ato_triage import Device, Factor, Takeover, assess_login
from scripts.f1_lab.login_environment import Change
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.vpn_enrollment import PinnedVPNEnrollments
from scripts.mtls_native import valid_client
from scripts.mtls_transport import Quiet

GATEWAY = "ato-loopback"


def device_from_peer(channel, registry, principal, now):
    if (
        not isinstance(channel, ssl.SSLSocket)
        or not channel.server_side
        or channel.context.verify_mode != ssl.CERT_REQUIRED
    ):
        raise ValueError("client-authenticated TLS required")
    certificate = channel.getpeercert(binary_form=True)
    if not certificate:
        raise ValueError("verified client certificate unavailable")
    valid_client(certificate)
    fingerprint = hashlib.sha256(certificate).hexdigest()
    enrollment = registry.assess(
        SimpleNamespace(
            tenant_id=principal.tenant_id,
            gateway_id=GATEWAY,
            user_id=principal.subject,
            device_id=fingerprint,
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


def exercise(root, *, settings, binding, token, other_token, authority, pattern_report, warning):
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
    contexts = {}
    for name, bundle in clients.items():
        client = ssl.create_default_context(cafile=str(ca_path))
        client.load_cert_chain(*_material(root, name, bundle))
        contexts[name] = client
    contexts["no-certificate"] = ssl.create_default_context(cafile=str(ca_path))
    now = datetime.now(UTC)
    config_path = root / "enrollments.json"
    write(
        config_path,
        {
            "schema_version": "zt-vpn-enrollments-1",
            "version": 1,
            "issued_at": (now - timedelta(seconds=1)).isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "bindings": [
                {
                    "tenant_id": binding.tenant,
                    "gateway_id": GATEWAY,
                    "user_id": binding.subject
                    if name != "foreign-account"
                    else "separate-fixture-subject",
                    "device_id": clients[name]["fingerprint"],
                    "client_certificate_sha256": clients[name]["fingerprint"],
                    "enabled": name != "revoked",
                }
                for name in ("approved", "revoked", "foreign-account")
            ],
        },
    )
    registry = PinnedVPNEnrollments(
        config_path, hashlib.sha256(config_path.read_bytes()).hexdigest()
    )
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.verify_mode = ssl.CERT_REQUIRED
    tls.verify_flags |= ssl.VERIFY_X509_STRICT
    tls.load_verify_locations(cafile=str(ca_path))
    tls.load_cert_chain(*server_cert)
    pending = {}
    gate = Lock()

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
                if challenge is None or monotonic() >= challenge[1]:
                    raise HTTPException(409)
                device = device_from_peer(self.connection, registry, principal, datetime.now(UTC))
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

    before, after = counts(), counts()
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
    }
