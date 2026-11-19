"""The installed Python CLI exercises a separate owned HTTP worker."""

import asyncio
import json
import os
import subprocess
import sys

import pytest

from app.models import AnalysisResult, PolicyDecision, SecurityAssessment
from app.services.sqlite_audit import SQLiteAuditStore
from scripts.f1_lab.http_worker_controls import owned_worker
from scripts.f1_lab.shared_native_controls import configure
from scripts.run_exec_history_controls import setup_app


@pytest.mark.skipif(os.name != "posix", reason="Owned native Linux worker fixture")
@pytest.mark.parametrize("review_policy", ["optional", "caller_bound"])
def test_real_operator_cli_reads_then_reviews_once_and_refuses_replay(tmp_path, review_policy):
    lab = setup_app(tmp_path / "control", "fixture.service")
    config, pin, _ = configure(lab, tmp_path / "shared")
    record = AnalysisResult(
        event_id="operator-cli-local-control",
        tenant_id=lab.principal.tenant_id,
        actor_id=lab.principal.subject,
        analyzer="rule",
        latency_ms=1,
        assessment=SecurityAssessment(
            risk_score=90,
            risk_level="HIGH",
            violation_type="PRIVILEGE_ESCALATION",
            rationale="Owned CLI fixture",
            recommended_action="HOLD_FOR_REVIEW",
            confidence=0.9,
            requires_human_review=True,
        ),
        policy_decision=PolicyDecision(
            action="HOLD_FOR_REVIEW",
            allowed=False,
            requires_human_review=True,
            reason="Owned advisory review",
        ),
    )
    path = tmp_path / "audit.sqlite3"
    asyncio.run(SQLiteAuditStore(path).save(record))
    key = "operator-cli-placeholder-not-production"
    snapshot = tmp_path / "snapshot.json"
    with owned_worker(
        lab, (config, pin), path, tmp_path / "worker", key, review_policy=review_policy
    ) as (_, client, _):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("OPENAI_", "AWS_"))}
        env.update(AWS_EC2_METADATA_DISABLED="true", OPERATOR_FIXTURE_KEY=key)
        command = [
            sys.executable,
            "-m",
            "scripts.audit_review_client",
            "--base-url",
            str(client.base_url).rstrip("/"),
            "--credential-env",
            "OPERATOR_FIXTURE_KEY",
        ]

        def run(arguments):
            return subprocess.run(
                command + arguments,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

        observed = run(["prepare", "--event-id", record.event_id, "--snapshot", str(snapshot)])
        assert observed.returncode == 0, observed.stderr
        assert key not in snapshot.read_text() and key not in observed.stdout + observed.stderr
        request = [
            "review",
            "--snapshot",
            str(snapshot),
            "--status",
            "IN_REVIEW",
            "--note",
            "Checked the actual owned review snapshot",
        ]
        accepted = run(request)
        assert accepted.returncode == 0, accepted.stderr
        assert json.loads(accepted.stdout)["reviewer"] == lab.principal.subject
        replay = run(request)
        assert replay.returncode == 1 and "HTTP 412" in replay.stderr
        assert key not in accepted.stdout + accepted.stderr + replay.stdout + replay.stderr
        assert SQLiteAuditStore.open_existing(path).integrity()["verified_lines"] == 2
