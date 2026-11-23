"""Run a disposable loopback Keycloak OTP, app approval and revocation test."""

import argparse
import hashlib
import hmac
import json
import re
import secrets
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated
from unittest.mock import patch
from urllib.parse import quote
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app import security
from app.config import Settings
from app.services.auth_alert_triage import resolve_auth_alert, resolve_terminal_auth_alert
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import ProtectedAccessRequest, SignedSessionSignal
from scripts import local_ato_device_acceptance, local_oidc_redirect_lab
from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.f1_lab.ato_triage import Factor, Takeover, assess_login
from scripts.keycloak_live_authority import KeycloakLiveAuthority
from scripts.local_keycloak_evidence_collector import LocalKeycloakEvidenceCollector
from scripts.local_keycloak_login_history import fetch_login_history
from scripts.local_session_analysis_lab import LocalSessionAnalysisLab

IMAGE = "quay.io/keycloak/keycloak:26.8.0"
REALM = "zt-acceptance"
CLIENT_ID = "local-gateway"
AUTHORITY_CLIENT = "local-authority-reader"
TEST_USER = "local-analyst"
ADMIN = "fixture-admin"
TENANT = "local-lab"


def docker(*args):
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=35, check=False
    )
    if result.returncode:
        raise RuntimeError(f"Docker {args[0]} failed")
    return result.stdout.strip()


def realm(password, otp_seed, authority_secret):
    return {
        "realm": REALM,
        "enabled": True,
        "sslRequired": "none",
        "eventsEnabled": True,
        "roles": {"realm": [{"name": role} for role in ("analyst", "viewer")]},
        "clients": [
            {
                "clientId": CLIENT_ID,
                "protocol": "openid-connect",
                "publicClient": True,
                "directAccessGrantsEnabled": True,
                "standardFlowEnabled": False,
                "protocolMappers": [
                    {
                        "name": "local-tenant",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-hardcoded-claim-mapper",
                        "config": {
                            "claim.name": "tenant_id",
                            "claim.value": TENANT,
                            "jsonType.label": "String",
                            "id.token.claim": "true",
                        },
                    },
                    {
                        "name": "local-roles",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-usermodel-realm-role-mapper",
                        "config": {
                            "claim.name": "roles",
                            "jsonType.label": "String",
                            "multivalued": "true",
                            "id.token.claim": "true",
                        },
                    },
                ],
            },
            {
                "clientId": AUTHORITY_CLIENT,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": authority_secret,
                "serviceAccountsEnabled": True,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "fullScopeAllowed": True,
            },
        ],
        "users": [
            {
                "username": TEST_USER,
                "enabled": True,
                "firstName": "Local",
                "lastName": "Fixture",
                "email": "local-analyst@example.invalid",
                "emailVerified": True,
                "realmRoles": ["analyst"],
                "credentials": [
                    {"type": "password", "value": password, "temporary": False},
                    {
                        "type": "otp",
                        "userLabel": "fixture-totp",
                        "secretData": json.dumps({"value": otp_seed}),
                        "credentialData": json.dumps(
                            {
                                "subType": "totp",
                                "digits": 6,
                                "counter": 0,
                                "period": 30,
                                "algorithm": "HmacSHA1",
                            }
                        ),
                    },
                ],
            }
        ],
    }


def fixture_otp(seed, *, unix_time=None):
    counter = int(time.time() if unix_time is None else unix_time) // 30
    digest = hmac.new(seed.encode(), counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def fixture_admin_authorization(client, base, admin_password):
    admin = client.post(
        f"{base}/realms/master/protocol/openid-connect/token",
        data={
            "client_id": "admin-cli",
            "grant_type": "password",
            "username": ADMIN,
            "password": admin_password,
        },
    )
    admin.raise_for_status()
    return {"Authorization": "Bearer " + admin.json()["access_token"]}


def provision_authority_reader(client, base, admin_password):
    authorization = fixture_admin_authorization(client, base, admin_password)
    admin_base = f"{base}/admin/realms/{REALM}"
    clients = admin_base + "/clients"

    def client_id(name):
        response = client.get(clients, params={"clientId": name}, headers=authorization)
        response.raise_for_status()
        return next(row["id"] for row in response.json() if row["clientId"] == name)

    account_path = f"{clients}/{client_id(AUTHORITY_CLIENT)}/service-account-user"
    account = client.get(account_path, headers=authorization)
    account.raise_for_status()
    realm_management = client_id("realm-management")
    role = client.get(f"{clients}/{realm_management}/roles/view-users", headers=authorization)
    role.raise_for_status()
    mappings = f"{admin_base}/users/{account.json()['id']}/role-mappings/clients/{realm_management}"
    assigned = client.post(mappings, json=[role.json()], headers=authorization)
    assigned.raise_for_status()


def verify(
    base, root, password, otp_seed, admin_password, authority_secret, *, stop_provider,
    ato_residual=None, device_lifecycle=False,
):
    issuer = f"{base}/realms/{REALM}"
    metadata_url = issuer + "/.well-known/openid-configuration"
    device_review = None
    with httpx.Client(trust_env=False, timeout=8) as client:
        for _ in range(210):
            try:
                metadata = client.get(metadata_url)
                if metadata.is_success:
                    break
            except httpx.TransportError:
                pass
            time.sleep(1)
        else:
            raise RuntimeError("Keycloak discovery did not become ready")
        assert metadata.json()["issuer"] == issuer
        token_url = issuer + "/protocol/openid-connect/token"

        def token(**fields):
            return client.post(token_url, data={"client_id": CLIENT_ID, **fields})

        provision_authority_reader(client, base, admin_password)
        settings = Settings(
            _env_file=None,
            app_environment="test",
            auth_mode="oidc",
            oidc_issuer=issuer,
            oidc_audience=CLIENT_ID,
            oidc_jwks_url=issuer + "/protocol/openid-connect/certs",
        )
        lab = LocalSessionAnalysisLab(root / "gateway")
        collector = LocalKeycloakEvidenceCollector(lab, settings, client)

        def sign_in(**fields):
            return collector.sign_in(username=TEST_USER, password=password, **fields)

        previous_otp = None

        def fresh_sign_in(**fields):
            nonlocal previous_otp
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                instant = time.time()
                otp = fixture_otp(otp_seed, unix_time=instant)
                if otp != previous_otp and 1 <= instant % 30 <= 27:
                    observed = sign_in(otp=otp, **fields)
                    assert observed.response.status_code == 200, observed.response.status_code
                    previous_otp = otp
                    return observed
                time.sleep(0.25)
            raise RuntimeError("No fresh OTP window for local acceptance fixture")

        valid_otp = fixture_otp(otp_seed)
        wrong_otp = sign_in(otp=f"{(int(valid_otp) + 1) % 1_000_000:06d}")
        missing_otp = sign_in()
        repeated_missing_otp = sign_in()
        for rejected in (wrong_otp, missing_otp, repeated_missing_otp):
            assert rejected.response.status_code == 400 and rejected.signal is not None
            assert rejected.signal.event.auth_context.authentication_result == "failure"
            assert rejected.signal.event.auth_context.mfa == "unknown"
        approved_otp = fresh_sign_in()
        assert approved_otp.response.status_code == 200 and approved_otp.signal is not None
        tokens = approved_otp.response.json()
        identity = security._decode_oidc_token(tokens["id_token"], settings)["sub"]

        cancelled_event = collector.attempts.open("cancel-before-auth-" + uuid4().hex)
        assert collector.probe_readiness(cancelled_event.event_id) is None
        cancelled_receipt = collector.attempts.cancel(cancelled_event.event_id)
        cancelled_alert = resolve_terminal_auth_alert(
            lab.service, cancelled_event, cancelled_receipt, lab.principal
        )
        assert cancelled_alert == "cleared"

        gateway = FastAPI()
        gateway.state.oidc_live_authority = KeycloakLiveAuthority(
            issuer, AUTHORITY_CLIENT, authority_secret
        )
        gateway.include_router(zero_trust_router(lab.service))
        install_zero_trust_error_handlers(gateway)

        @gateway.post("/fixture/auth-alert")
        def auth_alert(
            signal: SignedSessionSignal,
            principal: Annotated[
                security.Principal, Depends(security.require_roles(security.Role.ANALYST))
            ],
        ):
            return {"disposition": resolve_auth_alert(lab.service, signal.event, signal, principal)}

        security._jwks_client.cache_clear()

        def headers(token_value):
            return {"Authorization": "Bearer " + token_value}

        analyst = headers(tokens["id_token"])
        with (
            patch.object(security, "get_settings", return_value=settings),
            TestClient(gateway, client=('127.0.0.1', 50000)) as app,
        ):

            def evaluate(authentication):
                signed = authentication.signal
                assert signed is not None
                response = app.post(
                    "/zero-trust/signals/evaluate",
                    json=signed.model_dump(mode="json"),
                    headers=analyst,
                )
                assert response.status_code == 200, response.status_code
                triage = app.post(
                    "/fixture/auth-alert", json=signed.model_dump(mode="json"), headers=analyst
                )
                assert triage.status_code == 200, triage.status_code
                return response.json(), triage.json()["disposition"]

            approved, approved_alert = evaluate(approved_otp)
            assert approved_alert == "cleared"
            assert approved["session"]["decision"] == "ALLOW" and approved["grant_token"]
            requested = {
                "session_id": approved["session"]["session_id"],
                "resource_id": "remote-read",
                "action": "READ",
                "grant_token": approved["grant_token"],
            }
            assert app.post("/zero-trust/protected-access", json=requested, headers=analyst).json()[
                "allowed"
            ]
            # Verify these short-lived signals before waiting for additional OTP windows.
            failed, failed_alert = evaluate(wrong_otp)
            missing, missing_alert = evaluate(missing_otp)
            assert failed_alert == missing_alert == "confirmed"
            for rejected in (failed, missing):
                assert rejected["session"]["decision"] == "DENY" and not rejected["grant_token"]
            redirect_signin = fresh_sign_in()
            otp_binding = redirect_signin.otp_binding
            assert otp_binding is not None and otp_binding.subject == identity
            login_history = fetch_login_history(
                client, issuer, fixture_admin_authorization(client, base, admin_password),
                client_id=CLIENT_ID, binding=otp_binding,
            )
            assert login_history["earlier_same_account_failures"] == 3
            assert login_history["earlier_same_account_successes"] == 1
            assert login_history["baseline_repeated_failure_warning"] is True
            assert login_history["candidate_repeated_failure_warning"] is False
            assert login_history["candidate_with_independent_hard_alert"] is True
            assert redirect_signin.signal.event.auth_context.mfa == "success"
            verified_otp_with_change = assess_login(
                warning=login_history["candidate_repeated_failure_warning"],
                success=login_history["verified_session_match"],
                environment_change=True,
                factor=Factor.VERIFIED,
            )
            provider_error = wrong_otp.signal.event.auth_context
            assert provider_error.authentication_result == "failure" and provider_error.mfa == "unknown"
            failed_login = assess_login(warning=True, success=False, environment_change=True)
            assert verified_otp_with_change.takeover is Takeover.REVIEW
            assert failed_login.repeated_failure_warning and failed_login.takeover is Takeover.NO_SIGNAL
            redirect_tokens = redirect_signin.response.json()
            redirect_caller = headers(redirect_tokens["id_token"])
            redirect_session, redirect_alert = evaluate(redirect_signin)
            assert redirect_alert == "cleared" and redirect_session["grant_token"]
            redirect_grant = ProtectedAccessRequest(
                session_id=redirect_session["session"]["session_id"],
                resource_id="remote-read",
                action="READ",
                grant_token=redirect_session["grant_token"],
            )
            redirect_lab = local_oidc_redirect_lab.mount(
                gateway, root / "web", lab.service, redirect_grant, otp_binding
            )
            redirect_path = local_oidc_redirect_lab.ROUTE + "/continue"
            same_role_refresh = token(
                grant_type="refresh_token", refresh_token=redirect_tokens["refresh_token"]
            )
            assert same_role_refresh.status_code == 200
            refreshed_redirect = app.post(
                redirect_path, headers=headers(same_role_refresh.json()["id_token"]), follow_redirects=False
            )
            assert refreshed_redirect.status_code == 403
            assert refreshed_redirect.json()["detail"] == "Verified OTP for this token is required"
            assert "redirect" not in local_oidc_redirect_lab.receipt(redirect_lab, refreshed_redirect)
            web_redirect = app.post(redirect_path, headers=redirect_caller, follow_redirects=False)
            local_oidc_redirect_lab.verify_success(
                redirect_lab, web_redirect, lab.service, redirect_grant, otp_binding, redirect_session["session"]["version"]
            )
            reused_redirect = app.post(redirect_path, headers=redirect_caller, follow_redirects=False)
            assert reused_redirect.status_code == 403
            assert "redirect" not in local_oidc_redirect_lab.receipt(redirect_lab, reused_redirect)
            out_of_scope = fresh_sign_in(action="REMOTE_ACCESS")
            scope_denial, scope_alert = evaluate(out_of_scope)
            assert scope_alert == "confirmed"
            assert scope_denial["session"]["decision"] == "DENY" and not scope_denial["grant_token"]
            if ato_residual is not None:
                review_binding = otp_binding
                review_token = redirect_tokens["id_token"]
                revoke_session = None
                if device_lifecycle:
                    review_binding = out_of_scope.otp_binding
                    assert review_binding is not None and review_binding.session != otp_binding.session
                    review_token = out_of_scope.response.json()["id_token"]

                    def revoke_session():
                        session = quote(review_binding.session, safe="")
                        response = client.delete(
                            f"{base}/admin/realms/{REALM}/sessions/{session}",
                            headers=fixture_admin_authorization(client, base, admin_password),
                        )
                        assert response.status_code == 204, response.status_code
                        return response.status_code

                device_review = local_ato_device_acceptance.exercise(
                    root / "ato-device", settings=settings, binding=review_binding,
                    token=review_token, other_token=tokens["id_token"],
                    authority=gateway.state.oidc_live_authority,
                    pattern_report=read(ato_residual), warning=login_history["candidate_repeated_failure_warning"],
                    revoke_session=revoke_session,
                )
                device_review["residual_report_sha256"] = fingerprint(ato_residual)
            authorization = fixture_admin_authorization(client, base, admin_password)
            if device_lifecycle:
                sessions = client.get(
                    f"{base}/admin/realms/{REALM}/users/{identity}/sessions", headers=authorization
                )
                sessions.raise_for_status()
                active = {row["id"] for row in sessions.json()}
                assert review_binding.session not in active
                assert approved_otp.otp_binding.session in active and otp_binding.session in active
                device_review["device_lifecycle"]["keycloak_session_revocation"]["other_sessions_retained"] = 2
            roles = f"{base}/admin/realms/{REALM}/roles"
            mappings = f"{base}/admin/realms/{REALM}/users/{identity}/role-mappings/realm"
            entries = {}
            for role in ("analyst", "viewer"):
                response = client.get(f"{roles}/{role}", headers=authorization)
                response.raise_for_status()
                entries[role] = response.json()
            role_removal = client.request(
                "DELETE", mappings, headers=authorization, json=[entries["analyst"]]
            )
            assert role_removal.status_code == 204
            app_path = "/zero-trust/protected-access"
            old_role = app.post(app_path, json=requested, headers=analyst)
            assert old_role.status_code == 401
            assert old_role.json()["detail"] == "Caller roles changed since token issuance"
            web_old_role = app.post(redirect_path, headers=redirect_caller, follow_redirects=False)
            assert web_old_role.status_code == 401
            assert web_old_role.json()["detail"] == "Caller roles changed since token issuance"
            assert "redirect" not in local_oidc_redirect_lab.receipt(redirect_lab, web_old_role)
            assert (
                client.post(mappings, headers=authorization, json=[entries["viewer"]]).status_code
                == 204
            )
            refresh = token(grant_type="refresh_token", refresh_token=tokens["refresh_token"])
            assert refresh.status_code == 200, refresh.status_code
            viewer = headers(refresh.json()["id_token"])
            downgraded = app.post(app_path, json=requested, headers=viewer)
            assert downgraded.status_code == 403
            assert downgraded.json()["detail"] == "Insufficient role for this operation"
            web_viewer = app.post(redirect_path, headers=viewer, follow_redirects=False)
            assert web_viewer.status_code == 403
            assert web_viewer.json()["detail"] == "Insufficient role for this operation"
            assert "redirect" not in local_oidc_redirect_lab.receipt(redirect_lab, web_viewer)

            logout = client.post(
                f"{base}/admin/realms/{REALM}/users/{identity}/logout", headers=authorization
            )
            assert logout.status_code == 204
            assert (
                token(
                    grant_type="refresh_token", refresh_token=refresh.json()["refresh_token"]
                ).status_code
                == 400
            )
            blocked = app.post(app_path, json=requested, headers=viewer)
            assert blocked.status_code == 401
            assert blocked.json()["detail"] == "Caller session is no longer active"
            web_after_logout = app.post(redirect_path, headers=redirect_caller, follow_redirects=False)
            assert web_after_logout.status_code == 401
            assert web_after_logout.json()["detail"] == "Caller session is no longer active"
            assert "redirect" not in local_oidc_redirect_lab.receipt(redirect_lab, web_after_logout)
        security._jwks_client.cache_clear()
        stop_provider()
        unavailable_event = collector.attempts.open("outage-before-auth-" + uuid4().hex)
        unavailable_receipt = collector.probe_readiness(unavailable_event.event_id)
        assert unavailable_receipt is not None
        assert unavailable_receipt.outcome == "upstream_unavailable"
        unavailable_alert = resolve_terminal_auth_alert(
            lab.service, unavailable_event, unavailable_receipt, lab.principal
        )
        assert unavailable_alert == "cleared"
        assert (
            resolve_terminal_auth_alert(
                lab.service, unavailable_event, cancelled_receipt, lab.principal
            )
            == "needs_evidence"
        )
    return {
        "image": IMAGE,
        "alert_triage": {
            "approved_mfa_and_scope": approved_alert,
            "denied_scope": scope_alert,
            "rejected_otp_request": failed_alert,
            "missing_otp_request": missing_alert,
            "pre_auth_cancelled": cancelled_alert,
            "pre_auth_outage": unavailable_alert,
            "cross_attempt_receipt": "needs_evidence",
        },
        "mfa_correct": 200,
        "mfa_wrong": 400,
        "mfa_missing": 400,
        "allowed_read": True,
        "remote_out_of_scope": "DENY",
        "failed_mfa_policy": failed["session"]["decision"],
        "failed_mfa_observation": "unknown",
        "pre_auth_outage_probe": "actual stopped loopback provider",
        "failed_mfa_grant": False,
        "downgraded_role": 403,
        "role_removal": role_removal.status_code,
        "logout": 204,
        "refresh_after_logout": 400,
        "old_token_after_role_removal": old_role.status_code,
        "token_after_provider_logout": blocked.status_code,
        "oidc_web_redirect": {
            "verified_otp_redirect": web_redirect.status_code,
            "evidence_state": "consistent",
            "refreshed_token_without_exact_otp_binding": refreshed_redirect.status_code,
            "consumed_redirect_grant": reused_redirect.status_code,
            "old_role": web_old_role.status_code,
            "downgraded_role": web_viewer.status_code,
            "after_logout": web_after_logout.status_code,
            "denied_redirect_receipts": 0,
        },
        "authority_mode": "read-only provider checks on each request",
        "login_history_review": login_history,
        "account_takeover_triage": {
            "environment_change_is_controlled_input": True,
            "verified_otp_with_unknown_device": verified_otp_with_change.takeover.value,
            "ambiguous_provider_error_factor": provider_error.mfa,
            "failed_login_retained_warning": failed_login.repeated_failure_warning,
            "failed_login_takeover": failed_login.takeover.value,
        },
        "ato_device_review": device_review,
        "manual_revocation_file": False,
        "finished_at": datetime.now(UTC).isoformat(),
        "paid_api_calls": 0,
    }


def run(output, *, ato_residual=None, device_lifecycle=False):
    if device_lifecycle and ato_residual is None:
        raise ValueError("device lifecycle requires an ATO residual report")
    name = f"zt-keycloak-{uuid4().hex[:12]}"
    password, admin_password = secrets.token_urlsafe(28), secrets.token_urlsafe(28)
    otp_seed = secrets.token_hex(20)
    authority_secret = secrets.token_urlsafe(32)
    with TemporaryDirectory(prefix="zt-keycloak-") as directory:
        root = Path(directory)
        imports = root / "imports"
        imports.mkdir()
        write(imports / f"{REALM}-realm.json", realm(password, otp_seed, authority_secret))
        docker(
            "run",
            "-d",
            "--rm",
            "--pull=never",
            "--name",
            name,
            "--publish",
            "127.0.0.1::8080",
            "--mount",
            f"type=bind,source={imports},target=/opt/keycloak/data/import,readonly",
            "--env",
            f"KC_BOOTSTRAP_ADMIN_USERNAME={ADMIN}",
            "--env",
            f"KC_BOOTSTRAP_ADMIN_PASSWORD={admin_password}",
            "--env",
            "JAVA_OPTS_APPEND=-XX:ActiveProcessorCount=4",
            IMAGE,
            "start-dev",
            "--import-realm",
        )
        stopped = False

        def stop_provider():
            nonlocal stopped
            if not stopped:
                docker("stop", "--time", "12", name)
                stopped = True

        try:
            mapping = docker("port", name, "8080/tcp")
            if not re.fullmatch(r"127\.0\.0\.1:\d{1,5}", mapping):
                raise RuntimeError("unexpected Keycloak endpoint")
            report = verify(
                f"http://{mapping}",
                root,
                password,
                otp_seed,
                admin_password,
                authority_secret,
                stop_provider=stop_provider,
                ato_residual=ato_residual,
                device_lifecycle=device_lifecycle,
            )
        finally:
            try:
                stop_provider()
            except RuntimeError:
                if name in docker("ps", "-a", "--format", "{{.Names}}").splitlines():
                    raise
        write(output, {**report, "container_removed": True})
        print(json.dumps(report))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--ato-residual", type=Path)
    parser.add_argument("--device-lifecycle", action="store_true", help="include device transitions and targeted Keycloak session revocation")
    args = parser.parse_args()
    run(args.output, ato_residual=args.ato_residual, device_lifecycle=args.device_lifecycle)
