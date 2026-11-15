"""Measure local signed-signal access control with independently specified outcomes."""

import argparse
import hashlib
import json
import math
import secrets
import sqlite3
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from statistics import median
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.scenarios import synthetic_events
from app.services.trusted_signals import SignalVerifier
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import SignedSessionSignal
from scripts.test_signal_compose import sign

DOCUMENTS = "zt-demo-documents"
VAULT = "zt-demo-vault"
RESOURCE_CONTENT = "모의 업무 자원에 대한 접근이 허용되었습니다."
TENANT = "local-access-benchmark"
SOURCE = "local-benchmark-ed25519"
KEY_ID = "evaluation-key"
FAMILIES = (
    ("signed_read", True, "ACCESS_GRANTED"),
    ("bound_mfa_recovery", True, "ACCESS_GRANTED"),
    ("unrelated_after_revocation", True, "ACCESS_GRANTED"),
    ("fresh_reevaluation", True, "ACCESS_GRANTED"),
    ("after_journal_reopen", True, "ACCESS_GRANTED"),
    ("grant_replay", False, "GRANT_ALREADY_USED"),
    ("revoked_session", False, "SESSION_NOT_AUTHORIZED"),
    ("wrong_resource", False, "SCOPE_DENIED"),
    ("wrong_principal", False, "GRANT_INVALID"),
    ("expired_signal_proof", False, "SIGNAL_PROOF_EXPIRED"),
)
REASON_CODES = {reason for _, _, reason in FAMILIES} | {
    "GRANT_EXPIRED", "POLICY_CHANGED", "SIGNAL_SOURCE_REVOKED",
}


class EvaluationClock(datetime):
    """Controlled in-process time for freshness boundaries without sleeping."""

    current = datetime(2026, 10, 29, 12, tzinfo=UTC)

    @classmethod
    def now(cls, tz=None):
        return cls.current.astimezone(tz) if tz else cls.current.replace(tzinfo=None)


class SetupFailed(RuntimeError):
    """An episode's preconditions did not hold."""


def case_plan():
    cases = []
    for family, allowed, reason in FAMILIES:
        for variant in range(1, 21):
            index = len(cases) + 1
            tag = f"local-{index:03}"
            resource = VAULT if variant % 2 == 0 else DOCUMENTS
            action = "DOWNLOAD" if resource == VAULT and variant % 4 == 0 and family != "signed_read" else "READ"
            role = "administrator" if resource == VAULT or variant % 3 == 0 else "employee"
            boundary = None
            if family == "wrong_principal":
                boundary = "cross_tenant" if variant % 2 else "cross_operator"
            target_resource = resource
            if family == "wrong_resource":
                target_resource = VAULT if resource == DOCUMENTS else DOCUMENTS
            cases.append({
                "case_id": tag, "family": family, "variant": variant, "session_id": tag + "-session",
                "account_id": tag + "-account", "device_id": tag + "-device",
                "operator_id": tag + "-operator", "tenant_id": TENANT,
                "role": role, "resource_id": resource, "action": action,
                "client_ip": f"192.0.2.{index}", "principal_boundary": boundary,
                "request_resource_id": target_resource,
                "request_operator_id": tag + ("-operator-other" if boundary == "cross_operator" else "-operator"),
                "request_tenant_id": TENANT + ("-other" if boundary == "cross_tenant" else ""),
                "expected_status": 200 if allowed else 403, "expected_protected_content": allowed,
                "expected_reason_code": reason,
            })
    return cases


def credentials(subject, tenant):
    key = secrets.token_urlsafe(32)
    settings = Settings(
        _env_file=None, app_environment="test", analyzer_mode="rule", auth_mode="api_key",
        api_key_sha256=hashlib.sha256(key.encode()).hexdigest(), api_key_subject=subject,
        api_key_tenant_id=tenant, api_key_roles="responder",
    )
    return settings, {"X-API-Key": key}


class Episode:
    def __init__(self, case, directory, signer, setup):
        self.case = case
        self.signer = signer
        self.setup = setup
        self.credentials = credentials(case["operator_id"], case["tenant_id"])
        self.database = directory / "journal.sqlite3"
        self.registry = directory / "sources.json"
        now = EvaluationClock.current
        self.registry.write_text(json.dumps({"sources": [{
            "source_id": SOURCE, "tenant_id": TENANT,
            "user_ids": [case["account_id"], case["account_id"] + "-peer"],
            "device_ids": [case["device_id"], case["device_id"] + "-peer"],
            "roles": ["employee", "administrator"],
            "keys": [{
                "key_id": KEY_ID,
                "public_key_pem": signer.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode(),
                "not_before": (now - timedelta(days=1)).isoformat(),
                "not_after": (now + timedelta(days=1)).isoformat(),
            }],
        }]}), encoding="utf-8")
        self.operations = self.open_store()

    def open_store(self):
        return ZeroTrustOperations(self.database, signal_verifier=SignalVerifier(self.registry))

    def post(self, path, body, *, caller=None):
        settings, headers = caller or self.credentials
        with patch("app.security.get_settings", return_value=settings):
            return self.client.post(path, json=body, headers=headers)

    def signed_evaluation(self, name, *, version=0, mfa="success", challenge=None,
                          proof_seconds=90, peer=False):
        case = self.case
        now = EvaluationClock.current
        suffix = "-peer" if peer else ""
        event = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
        event.update(event_id=case["case_id"] + "-" + name, timestamp=now.isoformat(), action=case["action"])
        event["user"].update(user_id=case["account_id"] + suffix, role=case["role"], active=True)
        event["device"].update(device_id=case["device_id"] + suffix, managed=True, security_posture="healthy")
        event["network"].update(ip=case["client_ip"])
        event["resource"].update(resource_id=case["resource_id"], required_role=None)
        event["auth_context"].update(authentication_result="success", mfa=mfa)
        signed = sign(SignedSessionSignal(
            session_id=case["session_id"] + suffix, expected_version=version, event=event,
            tenant_id=TENANT, source_id=SOURCE, key_id=KEY_ID, issued_at=now,
            expires_at=now + timedelta(seconds=proof_seconds), challenge_id=challenge, signature="A" * 86,
        ), self.signer)
        response = self.post("/zero-trust/signals/evaluate", signed.model_dump(mode="json"))
        step = {"step": name, "http_status": response.status_code}
        self.setup.append(step)
        if response.status_code != 200:
            raise SetupFailed(name)
        result = response.json()
        session = result["session"]
        expected = "STEP_UP" if mfa != "success" else "ALLOW"
        step.update(decision=session["decision"], signal_trust=session["signal_trust"])
        if (session["decision"] != expected or session["signal_trust"] != "verified_source"
                or session["version"] != version + 1
                or bool(result["grant_token"]) != (expected == "ALLOW")):
            raise SetupFailed(name)
        return result

    def revoke(self, *, peer=False):
        session = self.case["session_id"] + ("-peer" if peer else "")
        response = self.post(f"/zero-trust/sessions/{session}/revoke",
                             {"expected_version": 1, "note": "Controlled access evaluation"})
        self.setup.append({"step": "revoke_peer" if peer else "revoke", "http_status": response.status_code})
        if response.status_code != 200 or response.json()["status"] != "REVOKED":
            raise SetupFailed("revoke")

    def access_request(self, grant):
        return {key: self.case[key] for key in ("session_id", "resource_id", "action")} | {"grant_token": grant}

    def last_record(self):
        with sqlite3.connect(self.database) as connection:
            row = connection.execute("SELECT seq, payload FROM journal ORDER BY seq DESC LIMIT 1").fetchone()
        return (row[0], json.loads(row[1])) if row else (0, {})

    def measure(self, request, *, caller=None):
        settings, _ = caller or self.credentials
        previous_seq, _ = self.last_record()
        started = time.perf_counter()
        response = self.post("/zero-trust/protected-access", request, caller=caller)
        elapsed = round((time.perf_counter() - started) * 1000, 3)
        sequence, evidence = self.last_record()
        body = response.json() if response.status_code in {200, 403} else {}
        allowed = self.case["expected_protected_content"]
        journal_matches = sequence == previous_seq + 1 and all(evidence.get(key) == value for key, value in {
            "kind": "access", "session_id": request["session_id"], "resource_id": request["resource_id"],
            "action": request["action"], "tenant_id": settings.api_key_tenant_id,
            "operator_id": settings.api_key_subject, "allowed": body.get("allowed"),
            "session_version": body.get("session_version"), "reason_code": body.get("reason_code"),
        }.items())
        content_present = body.get("content") is not None
        expected_content = RESOURCE_CONTENT if allowed else None
        reason = body.get("reason_code")
        return {
            "requested_resource_id": request["resource_id"], "requested_action": request["action"],
            "request_operator_id": settings.api_key_subject, "request_tenant_id": settings.api_key_tenant_id,
            "session_version": body.get("session_version"),
            "observed_status": response.status_code, "protected_content_present": content_present,
            "reason_code": reason if isinstance(reason, str) and reason in REASON_CODES else None,
            "journal_matches": journal_matches,
            "request_ms": elapsed,
            "passed": response.status_code == self.case["expected_status"]
            and body.get("allowed") is allowed and "content" in body
            and body["content"] == expected_content
            and reason == self.case["expected_reason_code"] and journal_matches,
        }

    def run(self):
        app = FastAPI()
        app.include_router(zero_trust_router(self.operations))
        install_zero_trust_error_handlers(app)
        family = self.case["family"]
        with TestClient(app) as client:
            self.client = client
            initial = self.signed_evaluation(
                "initial", mfa="unknown" if family == "bound_mfa_recovery" else "success",
                proof_seconds=10 if family == "expired_signal_proof" else 90,
            )
            if family in {"bound_mfa_recovery", "fresh_reevaluation"}:
                challenge = initial["session"]["challenge_id"]
                if family == "bound_mfa_recovery" and not challenge:
                    raise SetupFailed("challenge_not_issued")
                EvaluationClock.current += timedelta(seconds=1)
                initial = self.signed_evaluation("refreshed", version=1, challenge=challenge)
            request = self.access_request(initial["grant_token"])
            if family == "unrelated_after_revocation":
                self.signed_evaluation("peer", peer=True)
                self.revoke(peer=True)
            elif family == "grant_replay":
                first = self.post("/zero-trust/protected-access", request)
                self.setup.append({"step": "consume_grant", "http_status": first.status_code})
                if first.status_code != 200 or first.json().get("content") != RESOURCE_CONTENT:
                    raise SetupFailed("consume_grant")
            elif family == "revoked_session":
                self.revoke()
            elif family == "wrong_resource":
                request["resource_id"] = self.case["request_resource_id"]
            elif family == "wrong_principal":
                caller = credentials(self.case["request_operator_id"], self.case["request_tenant_id"])
                return self.measure(request, caller=caller)
            elif family == "expired_signal_proof":
                EvaluationClock.current += timedelta(seconds=11)
            if family != "after_journal_reopen":
                return self.measure(request)
        reopened_app = FastAPI()
        reopened_app.include_router(zero_trust_router(self.open_store()))
        install_zero_trust_error_handlers(reopened_app)
        with TestClient(reopened_app) as self.client:
            self.setup.append({"step": "reopen_sqlite"})
            return self.measure(request)


def write_json(path, data):
    payload = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def run(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=False)
    cases = case_plan()
    plan_hash = write_json(output_dir / "plan.json", {"schema": "local-access-plan-1", "cases": cases})
    signer = Ed25519PrivateKey.generate()
    results = []
    start = datetime(2026, 10, 29, 12, tzinfo=UTC)
    with tempfile.TemporaryDirectory(prefix="local-access-") as scratch, patch(
        "app.services.zero_trust.datetime", EvaluationClock,
    ):
        for index, case in enumerate(cases):
            directory = Path(scratch) / case["case_id"]
            directory.mkdir()
            EvaluationClock.current = start + timedelta(minutes=index)
            setup = []
            result = {"case_id": case["case_id"], "family": case["family"], "setup": setup}
            try:
                episode = Episode(case, directory, signer, setup)
                result.update(policy_version=episode.operations.policy.version,
                              policy_digest_sha256=episode.operations.policy_digest)
                result.update(episode.run())
            except Exception as error:  # noqa: BLE001 - preserve every planned episode, including errors.
                result.update(passed=False, observed_status=None, protected_content_present=None,
                              error_type=type(error).__name__)
                if isinstance(error, SetupFailed):
                    result["failed_step"] = error.args[0]
            results.append(result)

    by_family = {}
    for family, allowed, _ in FAMILIES:
        rows = [row for row in results if row["family"] == family]
        timings = sorted(row["request_ms"] for row in rows if row.get("request_ms") is not None)
        by_family[family] = {
            "cases": len(rows), "expected_allow": allowed, "passed": sum(row["passed"] for row in rows),
            "measured_requests": len(timings), "local_ms_p50": median(timings) if timings else None,
            "local_ms_p95": timings[math.ceil(0.95 * len(timings)) - 1] if timings else None,
        }
    report = {
        "schema": "local-access-report-1", "plan_sha256": plan_hash,
        "scope": "controlled local ASGI authorization; distinct from identity-provider and model evaluation",
        "python_version": sys.version.split()[0],
        "cases": len(results),
        "expected_permit": sum(case["expected_protected_content"] for case in cases),
        "expected_reject": sum(not case["expected_protected_content"] for case in cases),
        "passed": sum(row["passed"] for row in results),
        "by_family": by_family, "results": results,
    }
    write_json(output_dir / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory for plan and report")
    args = parser.parse_args()
    report = run(args.output_dir)
    print(f"{report['passed']}/{report['cases']} local access cases matched predeclared expectations.")
    return 0 if report["passed"] == report["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
