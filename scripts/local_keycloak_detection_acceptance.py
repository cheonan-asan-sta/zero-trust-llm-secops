"""Independent loopback cases exercising the application's verified-login route."""

import hashlib
import json
import secrets
import ssl
from datetime import UTC, datetime, timedelta
from http.client import HTTPSConnection
from http.server import ThreadingHTTPServer
from threading import Lock, Thread
from typing import NamedTuple
from unittest.mock import patch
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import config, security
from app.config import Settings
from app.models import SecurityEvent
from app.services.audit import AuditStore
from scripts import mtls_fixtures
from scripts.evaluate_local_remote_holdout import write
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.vpn_enrollment import PinnedVPNEnrollments
from scripts.keycloak_login_evidence import capture_login_evidence
from scripts.local_ato_device_acceptance import _material
from scripts.mtls_transport import Quiet

SOURCE = "keycloak-login-observer"
KEY_ID = "holdout-ephemeral"
RESOURCE = "holdout-sso"
GATEWAY = "holdout-mtls"


class Case(NamedTuple):
    name: str
    enrollment: str
    anomaly: bool
    priority: bool


# Fixed before collection. Labels are kept in the evaluator, outside both HTTP requests.
HOLDOUT = (
    Case("new_registration_office", "active", False, False),
    Case("approved_replacement_travel", "active", True, False),
    Case("reenrolled_certificate_remote", "active", True, False),
    Case("first_vpn_egress_change", "active", True, False),
    Case("onboarding_certificate_not_registered", "missing", True, False),
    Case("certificate_registered_to_another_account", "foreign", True, False),
    Case("retired_workstation_remote", "revoked", True, True),
    Case("offboarded_device_vpn", "revoked", True, True),
    Case("old_key_after_reenrollment", "revoked", True, True),
    Case("revoked_loaner_new_egress", "revoked", True, True),
)


def username(case):
    return "holdout-" + case.name.replace("_", "-")


def exercise(root, *, acquire, settings, authority, tenant):
    root.mkdir()
    now = datetime.now(UTC)
    ca = mtls_fixtures.authority("Independent login holdout CA")
    ca_path = root / "ca.crt"
    ca_path.write_bytes(ca[1].public_bytes(serialization.Encoding.PEM))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.verify_mode = ssl.CERT_REQUIRED
    tls.verify_flags |= ssl.VERIFY_X509_STRICT
    tls.load_verify_locations(cafile=str(ca_path))
    tls.load_cert_chain(*_material(root, "server", mtls_fixtures.leaf(ca, "localhost", server=True)))

    credentials = {}
    for case in HOLDOUT:
        bundle = mtls_fixtures.leaf(ca, case.name)
        context = ssl.create_default_context(cafile=str(ca_path))
        context.load_cert_chain(*_material(root, case.name, bundle))
        credentials[case.name] = (bundle["fingerprint"], context)

    # Discover account identifiers from the IdP outside the scoring and capture requests.
    subjects = {case.name: acquire(case, lookup=True) for case in HOLDOUT}
    devices = {case.name: "device-" + str(index) for index, case in enumerate(HOLDOUT, 1)}
    registry_path = root / "device-enrollments.json"
    write(registry_path, {
        "schema_version": "zt-vpn-enrollments-1",
        "version": 1,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "bindings": [
            {
                "tenant_id": tenant,
                "gateway_id": GATEWAY,
                "user_id": subjects[case.name] if case.enrollment != "foreign" else subjects[HOLDOUT[0].name],
                "device_id": devices[case.name],
                "client_certificate_sha256": credentials[case.name][0],
                "enabled": case.enrollment != "revoked",
            }
            for case in HOLDOUT if case.enrollment != "missing"
        ],
    })
    registry = PinnedVPNEnrollments(registry_path, hashlib.sha256(registry_path.read_bytes()).hexdigest())
    signing_key = Ed25519PrivateKey.generate()
    source_path = root / "trusted-login-source.json"
    source = {
        "source_id": SOURCE,
        "tenant_id": tenant,
        "user_ids": list(subjects.values()),
        "device_ids": list(devices.values()),
        "roles": ["employee"],
        "login_evidence_resource_ids": [RESOURCE],
        "keys": [{
            "key_id": KEY_ID,
            "public_key_pem": signing_key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
            "not_before": (now - timedelta(seconds=1)).isoformat(),
            "not_after": (now + timedelta(minutes=5)).isoformat(),
        }],
    }
    def publish_source(enabled):
        staged = source_path.with_suffix(".next")
        write(staged, {"sources": [{**source, "enabled": enabled}]})
        staged.replace(source_path)

    publish_source(True)
    operator_key = secrets.token_urlsafe(32)
    analysis_settings = Settings(
        _env_file=None, app_environment="test", analyzer_mode="rule", auth_mode="api_key",
        api_key_sha256=hashlib.sha256(operator_key.encode()).hexdigest(), api_key_tenant_id=tenant,
        trusted_signal_sources_path=source_path, audit_backend="jsonl", audit_log_path=root / "analysis-audit.jsonl",
        case_log_path=root / "cases.jsonl", outbox_log_path=root / "outbox.jsonl",
        zero_trust_db_path=root / "sessions.sqlite3",
    )
    with patch.object(config, "get_settings", return_value=analysis_settings):
        from app import main

    analysis_settings.audit_log_path.touch()
    audit = AuditStore(analysis_settings.audit_log_path, strict_reads=True)
    pending = {}
    gate = Lock()

    class Handler(Quiet):
        def do_POST(self):
            with gate:
                candidate = pending.pop(self.path, None)
            if candidate is None:
                self.reply(404)
                return
            event, binding = candidate
            bearer = self.headers.get("Authorization", "").removeprefix("Bearer ")
            try:
                proof = capture_login_evidence(
                    self.connection, event, bearer,
                    settings=settings, otp_binding=binding, authority=authority, registry=registry,
                    gateway_id=GATEWAY, source_id=SOURCE, key_id=KEY_ID, signing_key=signing_key,
                )
            except HTTPException as error:
                self.reply(error.status_code)
                return
            if proof is None:
                self.reply(204, b"")
                return
            self.reply(200, proof.model_dump_json().encode())

    def capture(server, event, binding, bearer, cert_case):
        path = "/" + uuid4().hex
        with gate:
            pending[path] = event, binding
        connection = HTTPSConnection(
            "localhost", server.server_address[1], context=credentials[cert_case.name][1], timeout=8,
        )
        try:
            connection.request("POST", path, headers={"Authorization": "Bearer " + bearer})
            response = connection.getresponse()
            data = response.read(4096)
            return response.status, json.loads(data) if data else None
        finally:
            connection.close()

    before, after = counts(), counts()
    observed = []
    guards = {}
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with (
                patch.object(main, "get_settings", return_value=analysis_settings),
                patch.object(security, "get_settings", return_value=analysis_settings),
                patch.object(main, "audit_store", audit),
                TestClient(main.app, headers={"X-API-Key": operator_key}) as api,
            ):
                for index, case in enumerate(HOLDOUT, 1):
                    authentication = acquire(case)
                    binding = authentication.otp_binding
                    assert binding is not None and binding.subject == subjects[case.name]
                    bearer = authentication.response.json()["id_token"]
                    event = SecurityEvent.model_validate({
                        "event_id": "login-" + uuid4().hex,
                        "timestamp": datetime.now(UTC),
                        "user": {"user_id": binding.subject, "role": "employee"},
                        "device": {"device_id": devices[case.name], "managed": True, "security_posture": "healthy"},
                        "resource": {"resource_id": RESOURCE, "resource_type": "sso", "sensitivity": "internal"},
                        "network": {
                            "ip": f"192.0.2.{index}", "location": "holdout", "location_anomaly": case.anomaly,
                            "access_method": "office" if not case.anomaly else "vpn",
                        },
                        "action": "LOGIN",
                        "auth_context": {"authentication_result": "success", "mfa": "success"},
                        "behavior": {},
                    })
                    status, proof = capture(server, event, binding, bearer, case)
                    assert status == (204 if case.enrollment in {"missing", "foreign"} else 200), (case.name, status)
                    payload = event.analysis_payload()
                    baseline = api.post("/analysis", json=payload)
                    assert baseline.status_code == 200, (case.name, baseline.status_code)
                    previous = baseline.json()
                    assert "verified_login_detection" not in previous
                    result = previous
                    if proof is not None:
                        candidate = api.post("/analysis/verified-login", json={"event": payload, "evidence": proof})
                        assert candidate.status_code == 200, (case.name, candidate.status_code)
                        result = candidate.json()
                        record_on_disk = audit.get(event.event_id, tenant)
                        assert record_on_disk is not None and record_on_disk.verified_login_detection is not None
                        assert record_on_disk.verified_login_detection.model_dump(mode="json") == result["verified_login_detection"]
                    actual = result.get("verified_login_detection", {}).get("disposition")
                    escalated = result["policy_decision"]["requires_human_review"]
                    old_escalation = previous["policy_decision"]["requires_human_review"]
                    assert escalated == case.priority, (case.name, escalated)
                    assert (actual == "priority_review") == case.priority, (case.name, actual)
                    assert previous["detection"] == result["detection"], case.name
                    record(before, case.priority, old_escalation)
                    record(after, case.priority, escalated)
                    observed.append({
                        "case": case.name, "expected_priority": case.priority,
                        "proof_issued": proof is not None, "disposition": actual,
                        "previous_human_review": old_escalation, "current_human_review": escalated,
                        "existing_sigma_matches_unchanged": True,
                    })

                    if index == 1:
                        assert proof is not None
                        wrong_device = capture(server, event, binding, bearer, HOLDOUT[1])
                        assert wrong_device[0] == 204
                        guards["other_mtls_credential_produced_no_proof"] = True
                        changed = {**payload, "event_id": "different-login"}
                        forged = {**proof, "device_state": "revoked_verified_device"}
                        missing = api.post("/analysis/verified-login", json={"event": payload})
                        assert missing.status_code == 422
                        guards["missing_receipt"] = missing.status_code
                        for name, body in (
                            ("different_event", {"event": changed, "evidence": proof}),
                            ("modified_evidence", {"event": payload, "evidence": forged}),
                        ):
                            rejected = api.post("/analysis/verified-login", json=body)
                            assert rejected.status_code == 401, (name, rejected.status_code)
                            guards[name] = rejected.status_code
                        publish_source(False)
                        withdrawn = api.post("/analysis/verified-login", json={"event": payload, "evidence": proof})
                        assert withdrawn.status_code == 401
                        guards["disabled_collector"] = withdrawn.status_code
                        publish_source(True)
        finally:
            server.shutdown()
            thread.join(timeout=5)

    assert audit.integrity()["ok"], "verified analysis audit integrity"
    return {
        "scope": "disjoint local scenarios with previously unused Keycloak accounts and fixed expected review labels",
        "cases": observed,
        "before": metrics(before),
        "after": metrics(after),
        "guards": guards,
        "audit_integrity": True,
        "distinct_actual_otp_accounts": len(subjects),
    }
