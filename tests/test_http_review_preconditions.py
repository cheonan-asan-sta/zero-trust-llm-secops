"""Actual owned loopback process: conditional review races and restart recovery."""

import asyncio
import os
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.models import AnalysisResult, PolicyDecision, SecurityAssessment
from app.services.sqlite_audit import SQLiteAuditStore
from scripts.f1_lab.http_worker_controls import owned_worker
from scripts.f1_lab.shared_native_controls import configure
from scripts.run_exec_history_controls import setup_app


@pytest.mark.skipif(os.name != "posix", reason="Owned Linux native worker fixture")
def test_actual_http_review_version_survives_concurrent_writers_and_worker_loss(tmp_path):
    lab = setup_app(tmp_path / "control", "fixture.service")
    config, pin, _ = configure(lab, tmp_path / "shared")
    # Only read/review HTTP routes are exercised. This fixture is not a new
    # kernel execution, an enterprise identity proof, or a paid model test.
    record = AnalysisResult(
        event_id="owned-http-review-race",
        analyzer="rule",
        latency_ms=1,
        tenant_id=lab.principal.tenant_id,
        actor_id=lab.principal.subject,
        assessment=SecurityAssessment(
            risk_score=90,
            risk_level="HIGH",
            violation_type="PRIVILEGE_ESCALATION",
            rationale="통제된 HTTP 검토 동시성 시험 자료입니다.",
            recommended_action="HOLD_FOR_REVIEW",
            confidence=0.9,
            requires_human_review=True,
        ),
        policy_decision=PolicyDecision(
            action="HOLD_FOR_REVIEW",
            allowed=False,
            requires_human_review=True,
            reason="Local advisory review fixture",
        ),
    )
    audit = tmp_path / "audit.sqlite3"
    asyncio.run(SQLiteAuditStore(audit).save(record))
    key = "owned-http-review-placeholder-not-a-real-credential"
    headers = {"X-API-Key": key}
    url = "/results/" + record.event_id
    with owned_worker(lab, (config, pin), audit, tmp_path / "worker-one", key) as (
        process,
        client,
        _stats,
    ):
        observed = client.get(url, headers=headers)
        assert observed.status_code == 200
        original_tag = observed.headers["ETag"]

        def patch(index):
            return client.patch(
                url + "/review",
                headers={**headers, "If-Match": original_tag},
                json={
                    "status": "IN_REVIEW",
                    "reviewer": "spoofed-browser-name",
                    "note": "concurrent conditional review " + str(index),
                },
            )

        with ThreadPoolExecutor(max_workers=16) as pool:
            responses = list(pool.map(patch, range(16)))
        counts = Counter(response.status_code for response in responses)
        assert counts[200] == 1 and counts[412] >= 1 and set(counts) <= {200, 412, 503}
        winner = next(response for response in responses if response.status_code == 200)
        assert winner.json()["reviewer"] == lab.principal.subject
        winning_tag = winner.headers["ETag"]
        assert winning_tag != original_tag
        stored = SQLiteAuditStore.open_existing(audit)
        assert stored.integrity()["verified_lines"] == 2
        assert (
            stored.get(record.event_id, record.tenant_id).review_note
            == winner.json()["review_note"]
        )
        assert client.get("/health/live").status_code == 200
        process.kill()
        assert process.wait(timeout=10) != 0

    with owned_worker(lab, (config, pin), audit, tmp_path / "worker-two", key) as (
        process,
        client,
        _stats,
    ):
        recovered = client.get(url, headers=headers)
        assert recovered.status_code == 200 and recovered.headers["ETag"] == winning_tag
        stale = client.patch(
            url + "/review",
            headers={**headers, "If-Match": original_tag},
            json={"status": "IN_REVIEW", "note": "stale pre-restart screen"},
        )
        assert stale.status_code == 412
        assert SQLiteAuditStore.open_existing(audit).integrity()["verified_lines"] == 2
        current = client.patch(
            url + "/review",
            headers={**headers, "If-Match": winning_tag},
            json={"status": "IN_REVIEW", "note": "fresh post-restart review"},
        )
        assert current.status_code == 200 and current.headers["ETag"] != winning_tag
        stored = SQLiteAuditStore.open_existing(audit)
        assert stored.integrity()["verified_lines"] == 3
        assert stored.metrics(record.tenant_id).total_analyses == 1
        assert client.get(url, headers={"X-API-Key": "incorrect-placeholder"}).status_code == 401
        process.kill()
        assert process.wait(timeout=10) != 0
