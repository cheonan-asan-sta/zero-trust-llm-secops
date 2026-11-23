"""Independent loopback cases exercising the application's verified-login route."""

import hashlib
import json
import secrets
import socket
import ssl
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.client import HTTPSConnection
from http.server import ThreadingHTTPServer
from threading import Lock, Thread
from time import monotonic, sleep
from typing import NamedTuple
from unittest.mock import patch
from uuid import uuid4

import httpx
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException

from app import config, security
from app.config import Settings
from app.models import SecurityEvent
from app.services.audit import AuditStore
from app.zero_trust_models import LOGIN_EVIDENCE_EXPIRED, SignedLoginEvidence
from scripts import mtls_fixtures
from scripts.evaluate_local_remote_holdout import write
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.vpn_enrollment import PinnedVPNEnrollments
from scripts.keycloak_login_evidence import KeycloakLoginAnalysisCollector
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
FALLBACK_CASES = (
    (Case("missing_normal", "missing", True, False), "missing"),
    (Case("missing_existing_credential_alert", "active", True, True), "missing"),
    (Case("expired_normal", "active", True, False), "expired"),
    (Case("expired_existing_high_risk", "revoked", True, True), "expired"),
)
CASES = HOLDOUT + tuple(case for case, _ in FALLBACK_CASES)


def username(case):
    return "holdout-" + case.name.replace("_", "-")


@contextmanager
def analysis_client(app, operator_key):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        server = uvicorn.Server(uvicorn.Config(
            app, lifespan="off", access_log=False, log_config=None,
        ))
        thread = Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = monotonic() + 10
            while not server.started:
                if not thread.is_alive() or monotonic() >= deadline:
                    raise RuntimeError("loopback analysis service failed to start")
                sleep(0.02)
            with httpx.Client(
                base_url=f"http://127.0.0.1:{listener.getsockname()[1]}",
                headers={"X-API-Key": operator_key}, trust_env=False, timeout=12,
            ) as client:
                yield client
        finally:
            server.should_exit = True
            thread.join(timeout=8)
            if thread.is_alive():
                raise RuntimeError("loopback analysis service failed to stop")


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
    for case in CASES:
        bundle = mtls_fixtures.leaf(ca, case.name)
        context = ssl.create_default_context(cafile=str(ca_path))
        context.load_cert_chain(*_material(root, case.name, bundle))
        credentials[case.name] = (bundle["fingerprint"], context)

    # Discover account identifiers from the IdP outside the scoring and capture requests.
    subjects = {case.name: acquire(case, lookup=True) for case in CASES}
    devices = {case.name: "device-" + str(index) for index, case in enumerate(CASES, 1)}
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
            for case in CASES if case.enrollment != "missing"
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
            event, binding, capture_only = candidate
            bearer = self.headers.get("Authorization", "").removeprefix("Bearer ")
            try:
                if capture_only:
                    proof = collector.capture(self.connection, event, bearer, binding)
                    if proof is None:
                        self.reply(204, b"")
                    else:
                        self.reply(200, proof.model_dump_json().encode())
                    return
                delivered = collector.collect(self.connection, event, bearer, binding)
            except HTTPException as error:
                self.reply(error.status_code)
                return
            except httpx.HTTPStatusError as error:
                self.reply(error.response.status_code)
                return
            self.reply(200, json.dumps({
                "evidence_state": delivered.evidence_state, "result": delivered.response.json(),
            }).encode())

    def gateway_request(server, event, binding, bearer, cert_case, *, capture_only=False):
        path = "/" + uuid4().hex
        with gate:
            pending[path] = event, binding, capture_only
        connection = HTTPSConnection(
            "localhost", server.server_address[1], context=credentials[cert_case.name][1], timeout=15,
        )
        try:
            connection.request("POST", path, headers={"Authorization": "Bearer " + bearer})
            response = connection.getresponse()
            data = response.read(65536)
            return response.status, json.loads(data) if data else None
        finally:
            connection.close()

    def make_event(case, index, *, bad_otp=False, severe=False):
        return SecurityEvent.model_validate({
            "event_id": "login-" + uuid4().hex,
            "timestamp": datetime.now(UTC),
            "user": {"user_id": subjects[case.name], "role": "employee"},
            "device": {
                "device_id": devices[case.name], "managed": True,
                "security_posture": "compromised" if severe else "healthy",
            },
            "resource": {
                "resource_id": RESOURCE, "resource_type": "sso",
                "sensitivity": "critical" if severe else "internal",
            },
            "network": {
                "ip": f"192.0.2.{index}", "location": "holdout", "location_anomaly": case.anomaly,
                "access_method": "office" if not case.anomaly else "vpn",
            },
            "action": "LOGIN",
            "auth_context": {
                "authentication_result": "failure" if bad_otp else "success",
                "mfa": "unknown" if bad_otp else "success", "failed_attempts": 3 if bad_otp else 0,
            },
            "behavior": {"request_rate": "high"} if severe else {},
        })

    def fallback_result(event, case, state, result, previous, writes):
        assert audit.integrity()["verified_lines"] == writes + 1, case.name
        saved = audit.get(event.event_id, tenant)
        assert saved is not None and saved.analysis_id == result["analysis_id"]
        assert saved.verified_login_detection is None, case.name
        assert "verified_login_detection" not in result, case.name
        for field in ("detection", "assessment", "policy_decision", "review_status"):
            assert result[field] == previous[field], (case.name, field)
        review = result["policy_decision"]["requires_human_review"]
        sigma_count = len(result["detection"]["matches"])
        if case.name == "missing_existing_credential_alert":
            assert sigma_count > 0, case.name
        assert (review or sigma_count > 0) == case.priority, case.name
        return {
            "case": case.name, "evidence_state": state, "expected_warning_or_review": case.priority,
            "existing_sigma_matches": sigma_count, "existing_human_review": review,
            "baseline_assessment_and_detection_unchanged": True, "audit_writes": 1,
        }

    before, after = counts(), counts()
    observed = []
    fallback_observations = []
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
                analysis_client(main.app, operator_key) as api,
            ):
                collector = KeycloakLoginAnalysisCollector(
                    api, settings=settings, authority=authority, registry=registry,
                    gateway_id=GATEWAY, source_id=SOURCE, key_id=KEY_ID, signing_key=signing_key,
                )
                for index, case in enumerate(HOLDOUT, 1):
                    authentication = acquire(case)
                    binding = authentication.otp_binding
                    assert binding is not None and binding.subject == subjects[case.name]
                    bearer = authentication.response.json()["id_token"]
                    event = make_event(case, index)
                    payload = event.analysis_payload()
                    baseline = api.post("/analysis", json=payload)
                    assert baseline.status_code == 200, (case.name, baseline.status_code)
                    previous = baseline.json()
                    assert "verified_login_detection" not in previous
                    writes = audit.integrity()["verified_lines"]
                    status, delivery = gateway_request(server, event, binding, bearer, case)
                    assert status == 200, (case.name, status)
                    assert audit.integrity()["verified_lines"] == writes + 1, case.name
                    state = "missing" if case.enrollment in {"missing", "foreign"} else "verified"
                    assert delivery["evidence_state"] == state, case.name
                    result = delivery["result"]
                    if state == "verified":
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
                        "proof_issued": state == "verified", "disposition": actual,
                        "automatic_delivery": state,
                        "previous_human_review": old_escalation, "current_human_review": escalated,
                        "existing_sigma_matches_unchanged": True,
                    })

                    if index == 1:
                        status, proof = gateway_request(server, event, binding, bearer, case, capture_only=True)
                        assert status == 200
                        assert proof is not None
                        wrong_device = gateway_request(server, event, binding, bearer, HOLDOUT[1], capture_only=True)
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

                waiting = []
                for index, (case, state) in enumerate(FALLBACK_CASES, len(HOLDOUT) + 1):
                    bad_otp = state == "missing" and case.priority
                    authentication = acquire(case, invalid_otp=bad_otp)
                    binding = authentication.otp_binding
                    if bad_otp:
                        assert authentication.response.status_code == 400 and binding is None
                    else:
                        assert binding is not None and binding.subject == subjects[case.name]
                    bearer = authentication.response.json().get("id_token", "")
                    event = make_event(case, index, bad_otp=bad_otp, severe=state == "expired" and case.priority)
                    previous_response = api.post("/analysis", json=event.analysis_payload())
                    previous_response.raise_for_status()
                    previous = previous_response.json()
                    if state == "expired":
                        status, raw = gateway_request(server, event, binding, bearer, case, capture_only=True)
                        assert status == 200, (case.name, status)
                        waiting.append((case, event, SignedLoginEvidence.model_validate(raw), previous))
                        continue
                    writes = audit.integrity()["verified_lines"]
                    status, delivery = gateway_request(server, event, binding, bearer, case)
                    assert status == 200 and delivery["evidence_state"] == "missing", case.name
                    fallback_observations.append(fallback_result(
                        event, case, state, delivery["result"], previous, writes,
                    ))

                expire_by = max(proof.expires_at for _, _, proof, _ in waiting)
                sleep(max(0, (expire_by - datetime.now(UTC)).total_seconds()) + 0.05)
                for index, (case, event, proof, previous) in enumerate(waiting):
                    assert datetime.now(UTC) >= proof.expires_at
                    writes = audit.integrity()["verified_lines"]
                    if index == 0:
                        payload = {"event": event.analysis_payload(), "evidence": proof.model_dump(mode="json")}
                        strict = api.post("/analysis/verified-login", json=payload)
                        assert strict.status_code == 401, strict.status_code
                        expiry = api.post("/analysis/verified-login?report_expiry=true", json=payload)
                        assert expiry.status_code == 410 and expiry.json() == {"detail": LOGIN_EVIDENCE_EXPIRED}
                        altered = proof.model_copy(update={"device_state": "revoked_verified_device"})
                        try:
                            collector.submit(event, altered)
                        except httpx.HTTPStatusError as error:
                            assert error.response.status_code == 401
                        else:
                            raise AssertionError("forged expired evidence triggered fallback")
                        assert audit.integrity()["verified_lines"] == writes
                        guards.update(expired_strict=strict.status_code, expired_signal=expiry.status_code,
                                      altered_expired_no_fallback=401)
                    delivery = collector.submit(event, proof)
                    assert delivery.evidence_state == "expired", case.name
                    fallback_observations.append(fallback_result(
                        event, case, "expired", delivery.response.json(), previous, writes,
                    ))
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
        "distinct_actual_otp_accounts": len(HOLDOUT),
        "delivery_fallback": fallback_observations,
    }
