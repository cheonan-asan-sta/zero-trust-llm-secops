"""Compare local login detection before and after a simulated extended queue outage."""

import argparse
import hashlib
import json
import secrets
from datetime import UTC, datetime
from email.utils import formatdate
from itertools import pairwise
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import httpx

from app import config, security
from app.config import Settings
from app.models import SecurityEvent
from app.services.sqlite_audit import SQLiteAuditStore
from scripts.evaluate_local_remote_holdout import write
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.keycloak_login_evidence import KeycloakLoginAnalysisCollector
from scripts.local_keycloak_detection_acceptance import analysis_client
from scripts.login_delivery_spool import LoginRetryPolicy

TENANT = "login-load-lab"
SUBJECT = "login-load-collector"
FIELDS = ("detection", "assessment", "policy_decision", "review_status")


def events(size):
    for index in range(size):
        threat = bool(index % 2)
        event = SecurityEvent.model_validate({
            "event_id": f"bulk-login-{index:04d}",
            "timestamp": datetime.now(UTC),
            "user": {"user_id": f"fixture-subject-{index}", "role": "employee"},
            "device": {"device_id": f"fixture-device-{index}", "managed": True, "security_posture": "healthy"},
            "network": {
                "ip": f"192.0.2.{index % 240 + 1}", "location": f"site-{index % 5}",
                "location_anomaly": True, "access_method": "vpn",
            },
            "resource": {"resource_id": "registered-sso", "resource_type": "sso", "sensitivity": "internal"},
            "action": "LOGIN",
            "auth_context": {
                "authentication_result": "failure" if threat else "success",
                "mfa": "unknown" if threat else "success", "failed_attempts": 3 + index % 4 if threat else 0,
            },
            "behavior": {},
        })
        yield event, threat


def flagged(result):
    return bool(result["detection"]["matches"]) or result["policy_decision"]["requires_human_review"]


def exercise(root, size):
    operator_key = secrets.token_urlsafe(32)
    settings = Settings(
        _env_file=None, app_environment="test", analyzer_mode="rule", auth_mode="api_key",
        api_key_sha256=hashlib.sha256(operator_key.encode()).hexdigest(), api_key_tenant_id=TENANT,
        api_key_subject=SUBJECT, audit_backend="sqlite", audit_db_path=root / "original.sqlite3",
        case_log_path=root / "cases.jsonl", outbox_log_path=root / "outbox.jsonl",
        zero_trust_db_path=root / "sessions.sqlite3",
    )
    with patch.object(config, "get_settings", return_value=settings):
        from app import main

    recovered = SQLiteAuditStore(root / "recovered.sqlite3")
    cases = list(events(size))
    expected = {}
    before, after = counts(), counts()
    now = datetime.now(UTC).timestamp()
    policy = LoginRetryPolicy(base_delay=5, max_delay=60, max_attempts=4, success_interval=0.25)
    probes = []
    recovery_requests = []
    duplicate_receipts = 0
    drop_response = True
    recover = False
    fix_permissions = False

    def downstream(request):
        nonlocal duplicate_receipts, drop_response
        payload = json.loads(request.content)
        event_id = payload["event"]["event_id"]
        if not recover:
            probes.append((now, event_id))
            match len(probes):
                case 1:
                    return httpx.Response(503, headers={"Retry-After": "120"})
                case 2:
                    raise httpx.ConnectError("local simulated outage", request=request)
                case 3:
                    return httpx.Response(429, headers={"Retry-After": formatdate(now + 420, usegmt=True)})
                case 4:
                    return httpx.Response(503, headers={"Retry-After": "600"})
                case _:
                    raise AssertionError("extra network probe during simulated outage")
        recovery_requests.append(now)
        if event_id == cases[1][0].event_id and not fix_permissions:
            return httpx.Response(403)
        answer = api.post("/analysis/login-delivery", json=payload)
        answer.raise_for_status()
        duplicate_receipts += int(answer.json()["duplicate"])
        if event_id == cases[10][0].event_id and drop_response:
            drop_response = False
            raise httpx.ReadError("local simulated response loss after commit", request=request)
        return answer

    def collector(client):
        return KeycloakLoginAnalysisCollector(
            client, settings=None, authority=None, registry=None, gateway_id="load-fixture",
            source_id="load-fixture", key_id="not-used-for-basic-login", signing_key=None,
            spool_path=root / "login-queue.sqlite3", tenant_id=TENANT, collector_subject=SUBJECT,
            retry_policy=policy, clock=lambda: now,
        )

    with (
        patch.object(main, "get_settings", return_value=settings),
        patch.object(security, "get_settings", return_value=settings),
        analysis_client(main.app, operator_key) as api,
    ):
        for event, truth in cases:
            result = api.post("/analysis", json=event.analysis_payload())
            result.raise_for_status()
            expected[event.event_id] = result.json()
            record(before, truth, flagged(result.json()))
        print(f"Compared {size} baseline logins; starting queue recovery.", flush=True)

        with httpx.Client(base_url=api.base_url, transport=httpx.MockTransport(downstream)) as client:
            sending = collector(client)
            for event, _ in cases:
                assert sending.submit(event, None).evidence_state == "queued"
            assert sending.spool.counts() == {"pending": size, "held": 0}
            assert len(probes) == 1
            start = now
            delays = []
            for expected_delay in (120, 10, 420, 600):
                due = sending.spool.next_attempt()
                assert due is not None and abs((due - now) - expected_delay) <= 1, (due, now, expected_delay)
                delays.append(round(due - now))
                now = due - 0.01
                previous_probes = len(probes)
                assert sending.flush_pending() == 0
                assert len(probes) == previous_probes
                now = due
                if len(probes) < 4:
                    assert sending.flush_pending() == 0
            assert len(probes) == 4 and len({event_id for _, event_id in probes}) == 1
            assert sending.spool.counts() == {"pending": size - 1, "held": 1}

        with (
            patch.object(main, "audit_store", recovered),
            httpx.Client(base_url=api.base_url, transport=httpx.MockTransport(downstream)) as client,
        ):
            sending = collector(client)
            assert sending.spool.next_attempt() == now
            recover_at = now
            recover = True

            def drain():
                nonlocal now
                loops = 0
                while sending.spool.counts()["pending"]:
                    due = sending.spool.next_attempt()
                    assert due is not None
                    now = max(now, due)
                    sending.flush_pending()
                    loops += 1
                    assert loops < size + 30, "login queue did not drain"

            drain()
            assert recovered.integrity()["verified_lines"] == size - 2
            failures = sending.spool.held()
            assert [(row["failure_code"], row["attempts"]) for row in failures] == [("http_503", 4), ("http_403", 1)]
            fix_permissions = True
            for failure in failures:
                assert sending.spool.requeue(failure["event_id"], now=now)
            drain()
            assert sending.spool.counts() == {"pending": 0, "held": 0}

    saved = {row.event_id: row.model_dump(mode="json") for row in recovered._records()}
    assert len(saved) == recovered.integrity()["verified_lines"] == size
    for event, truth in cases:
        current = saved[event.event_id]
        assert all(current[key] == expected[event.event_id][key] for key in FIELDS), event.event_id
        record(after, truth, flagged(current))
    intervals = [b - a for a, b in pairwise(recovery_requests)]
    assert intervals and min(intervals) == policy.success_interval
    assert duplicate_receipts == 1 and len(recovery_requests) == size + 2
    assert before == after == {"tp": size // 2, "fp": 0, "fn": 0, "tn": size // 2, "inference_errors": 0}
    return {
        "scope": "controlled normal and credential-alert inputs, real local HTTP analysis, simulated outage clock",
        "events_at_peak": size,
        "outage_clock_seconds": round(recover_at - start),
        "outage_retry_intervals_seconds": delays,
        "outage_requests": len(probes),
        "recovery_requests": len(recovery_requests),
        "recovery_minimum_spacing_seconds": min(intervals),
        "held_resolved": [{"code": row["failure_code"], "attempts": row["attempts"]} for row in failures],
        "lost_ack_replayed": duplicate_receipts,
        "analysis_audit_records": len(saved),
        "analysis_and_sigma_matched": size,
        "before": metrics(before),
        "after": metrics(after),
        "final_queue": sending.spool.counts(),
        "aws_calls": 0,
        "paid_api_calls": 0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cases", type=int, default=192)
    args = parser.parse_args()
    if args.cases < 12 or args.cases % 2:
        parser.error("--cases must be even and at least 12")
    with TemporaryDirectory(prefix="zt-login-load-") as temporary:
        result = exercise(Path(temporary), args.cases)
    write(args.output, result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
