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
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app import security
from app.config import Settings
from app.services.auth_alert_triage import resolve_auth_alert, resolve_terminal_auth_alert
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import SignedSessionSignal
from scripts.evaluate_local_remote_holdout import write
from scripts.keycloak_live_authority import KeycloakLiveAuthority
from scripts.local_keycloak_evidence_collector import LocalKeycloakEvidenceCollector
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


def fixture_otp(seed):
    counter = int(time.time()) // 30
    digest = hmac.new(seed.encode(), counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def provision_authority_reader(client, base, admin_password):
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
    authorization = {"Authorization": "Bearer " + admin.json()["access_token"]}
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
    return authorization


def verify(base, root, password, otp_seed, admin_password, authority_secret, *, stop_provider):
    issuer = f"{base}/realms/{REALM}"
    metadata_url = issuer + "/.well-known/openid-configuration"
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

        authorization = provision_authority_reader(client, base, admin_password)
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

        valid_otp = fixture_otp(otp_seed)
        wrong_otp = sign_in(otp=f"{(int(valid_otp) + 1) % 1_000_000:06d}")
        missing_otp = sign_in()
        for rejected in (wrong_otp, missing_otp):
            assert rejected.response.status_code == 400 and rejected.signal is not None
            assert rejected.signal.event.auth_context.authentication_result == "failure"
            assert rejected.signal.event.auth_context.mfa == "unknown"
        approved_otp = sign_in(otp=fixture_otp(otp_seed))
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
            TestClient(gateway) as app,
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
            out_of_scope = sign_in(otp=fixture_otp(otp_seed), action="REMOTE_ACCESS")
            scope_denial, scope_alert = evaluate(out_of_scope)
            assert scope_alert == "confirmed"
            assert scope_denial["session"]["decision"] == "DENY" and not scope_denial["grant_token"]
            failed, failed_alert = evaluate(wrong_otp)
            missing, missing_alert = evaluate(missing_otp)
            assert failed_alert == missing_alert == "confirmed"
            for rejected in (failed, missing):
                assert rejected["session"]["decision"] == "DENY" and not rejected["grant_token"]

            roles = f"{base}/admin/realms/{REALM}/roles"
            mappings = f"{base}/admin/realms/{REALM}/users/{identity}/role-mappings/realm"
            entries = {}
            for role in ("analyst", "viewer"):
                response = client.get(f"{roles}/{role}", headers=authorization)
                response.raise_for_status()
                entries[role] = response.json()
            assert (
                client.request(
                    "DELETE", mappings, headers=authorization, json=[entries["analyst"]]
                ).status_code
                == 204
            )
            assert (
                client.post(mappings, headers=authorization, json=[entries["viewer"]]).status_code
                == 204
            )
            app_path = "/zero-trust/protected-access"
            old_role = app.post(app_path, json=requested, headers=analyst)
            assert old_role.status_code == 401
            assert old_role.json()["detail"] == "Caller roles changed since token issuance"
            refresh = token(grant_type="refresh_token", refresh_token=tokens["refresh_token"])
            assert refresh.status_code == 200, refresh.status_code
            viewer = headers(refresh.json()["id_token"])
            downgraded = app.post(app_path, json=requested, headers=viewer)
            assert downgraded.status_code == 403
            assert downgraded.json()["detail"] == "Insufficient role for this operation"

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
        "logout": 204,
        "refresh_after_logout": 400,
        "old_token_after_role_removal": old_role.status_code,
        "token_after_provider_logout": blocked.status_code,
        "authority_mode": "read-only provider checks on each request",
        "manual_revocation_file": False,
        "finished_at": datetime.now(UTC).isoformat(),
        "paid_api_calls": 0,
    }


def run(output):
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
    run(parser.parse_args().output)
