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
from unittest.mock import patch
from uuid import uuid4

import httpx
import jwt
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import security
from app.config import Settings
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from scripts.evaluate_local_remote_holdout import write
from scripts.local_session_analysis_lab import LocalSessionAnalysisLab

IMAGE = "quay.io/keycloak/keycloak:26.8.0"
REALM = "zt-acceptance"
CLIENT_ID = "local-gateway"
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


def realm(password, otp_seed):
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
            }
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


def verify(base, root, password, otp_seed, admin_password):
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

        def sign_in(**fields):
            return token(
                grant_type="password",
                username=TEST_USER,
                password=password,
                scope="openid",
                **fields,
            )

        valid_otp = fixture_otp(otp_seed)
        wrong_otp = sign_in(otp=f"{(int(valid_otp) + 1) % 1_000_000:06d}")
        missing_otp = sign_in()
        assert wrong_otp.status_code == missing_otp.status_code == 400
        assert wrong_otp.json().get("error") == missing_otp.json().get("error") == "invalid_grant"
        approved_otp = sign_in(otp=fixture_otp(otp_seed))
        assert approved_otp.status_code == 200, approved_otp.status_code
        tokens = approved_otp.json()
        identity = jwt.decode(tokens["id_token"], options={"verify_signature": False})["sub"]

        policy = root / "revocations.json"

        def publish_revocations(subjects):
            temporary = policy.with_suffix(".tmp")
            write(
                temporary, {"schema": "oidc-revocations-1", "issuer": issuer, "subjects": subjects}
            )
            temporary.replace(policy)

        publish_revocations([])
        settings = Settings(
            _env_file=None,
            app_environment="test",
            auth_mode="oidc",
            oidc_issuer=issuer,
            oidc_audience=CLIENT_ID,
            oidc_jwks_url=issuer + "/protocol/openid-connect/certs",
            oidc_revoked_subjects_path=policy,
        )
        lab = LocalSessionAnalysisLab(root / "gateway")
        gateway = FastAPI()
        gateway.include_router(zero_trust_router(lab.service))
        install_zero_trust_error_handlers(gateway)
        security._jwks_client.cache_clear()

        def headers(token_value):
            return {"Authorization": "Bearer " + token_value}

        analyst = headers(tokens["id_token"])
        with (
            patch.object(security, "get_settings", return_value=settings),
            TestClient(gateway) as app,
        ):

            def evaluate(action, authentication):
                mfa = "success" if authentication.status_code == 200 else "failed"
                scenario = ("fixture", False, "remote-read", "employee", mfa, True, action)
                old, _ = lab.create(scenario)
                event = old.event.model_copy(update={"event_id": "keycloak-" + old.event.event_id})
                signed = lab.sign(event, "keycloak-" + old.session_id)
                response = app.post(
                    "/zero-trust/signals/evaluate",
                    json=signed.model_dump(mode="json"),
                    headers=analyst,
                )
                assert response.status_code == 200, response.status_code
                return response.json()

            approved = evaluate("READ", approved_otp)
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
            scope_denial = evaluate("REMOTE_ACCESS", approved_otp)
            assert scope_denial["session"]["decision"] == "DENY" and not scope_denial["grant_token"]
            failed = evaluate("READ", wrong_otp)
            assert failed["session"]["decision"] == "STEP_UP" and not failed["grant_token"]

            admin = client.post(
                f"{base}/realms/master/protocol/openid-connect/token",
                data={
                    "client_id": "admin-cli",
                    "grant_type": "password",
                    "username": ADMIN,
                    "password": admin_password,
                },
            )
            assert admin.status_code == 200, admin.status_code
            authorization = headers(admin.json()["access_token"])
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
            refresh = token(grant_type="refresh_token", refresh_token=tokens["refresh_token"])
            assert refresh.status_code == 200, refresh.status_code
            viewer = headers(refresh.json()["id_token"])
            app_path = "/zero-trust/protected-access"
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
            publish_revocations([{"tenant_id": TENANT, "subject": identity}])
            blocked = app.post(app_path, json=requested, headers=analyst)
            assert (
                blocked.status_code == 401
                and blocked.json()["detail"] == "Caller authority is revoked"
            )
        security._jwks_client.cache_clear()
    return {
        "image": IMAGE,
        "mfa_correct": 200,
        "mfa_wrong": 400,
        "mfa_missing": 400,
        "allowed_read": True,
        "remote_out_of_scope": "DENY",
        "failed_mfa_policy": "STEP_UP",
        "failed_mfa_grant": False,
        "downgraded_role": 403,
        "logout": 204,
        "refresh_after_logout": 400,
        "old_token_after_published_revocation": 401,
        "revocation_publication": "fixture operator after confirmed Keycloak logout",
        "finished_at": datetime.now(UTC).isoformat(),
        "paid_api_calls": 0,
    }


def run(output):
    name = f"zt-keycloak-{uuid4().hex[:12]}"
    password, admin_password = secrets.token_urlsafe(28), secrets.token_urlsafe(28)
    otp_seed = secrets.token_hex(20)
    with TemporaryDirectory(prefix="zt-keycloak-") as directory:
        root = Path(directory)
        imports = root / "imports"
        imports.mkdir()
        write(imports / f"{REALM}-realm.json", realm(password, otp_seed))
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
        try:
            mapping = docker("port", name, "8080/tcp")
            if not re.fullmatch(r"127\.0\.0\.1:\d{1,5}", mapping):
                raise RuntimeError("unexpected Keycloak endpoint")
            report = verify(f"http://{mapping}", root, password, otp_seed, admin_password)
        finally:
            try:
                docker("stop", "--time", "12", name)
            except RuntimeError:
                if name in docker("ps", "-a", "--format", "{{.Names}}").splitlines():
                    raise
        write(output, {**report, "container_removed": True})
        print(json.dumps(report))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    run(parser.parse_args().output)
