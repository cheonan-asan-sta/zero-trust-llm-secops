"""Real JWT/JWKS, signatures and stores under load; provider transport is mocked.

This exercises admission/cancellation/isolation, never paid LLM performance.
"""

import asyncio
import base64
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from openai import AsyncOpenAI

from app import main, security
from app.analyzers.evidence_agent import EvidenceReviewAgent
from app.config import Settings
from app.models import SecurityAssessment
from app.security import Principal, Role
from app.services.audit import AuditStore
from app.services.trusted_signals import canonical_signal
from app.zero_trust_models import SignedSessionSignal
from scripts.local_oidc_authority import LocalOIDCAuthority
from scripts.local_session_analysis_lab import SCENARIOS, LocalSessionAnalysisLab
from tests.test_structured_response import envelope


def test_concurrent_tenants_backpressure_and_cancellation_recover_without_state_changes(
    tmp_path, monkeypatch
):
    async def run(authority):
        config = Settings(
            _env_file=None,
            app_environment="test",
            analyzer_mode="openai",
            auth_mode="oidc",
            oidc_issuer=authority.issuer,
            oidc_audience=authority.audience,
            oidc_jwks_url=authority.jwks_url,
            openai_prompt_mode="grounded",
            openai_evidence_agent_enabled=True,
            analysis_max_concurrency=4,
            analysis_queue_timeout_seconds=0.02,
        )
        lab = LocalSessionAnalysisLab(tmp_path / "authority")
        seed, _ = lab.create(next(s for s in SCENARIOS if s[0] == "permitted_team"))
        for index in range(2):
            source = deepcopy(lab.registry["sources"][0])
            source.update(tenant_id=f"burst-tenant-{index}", source_id=f"burst-collector-{index}")
            lab.registry["sources"].append(source)
        lab.save_registry()
        prepared = []
        for index in range(33):
            tenant = f"burst-tenant-{index % 2}"
            now = datetime.now(UTC)
            event = seed.event.model_copy(
                update={"event_id": "burst-event-" + uuid4().hex, "timestamp": now}
            )
            signal = SignedSessionSignal(
                session_id="burst-session-" + uuid4().hex,
                expected_version=0,
                event=event,
                tenant_id=tenant,
                source_id=f"burst-collector-{index % 2}",
                key_id="ephemeral-key",
                issued_at=now,
                expires_at=now + timedelta(seconds=120),
                signature="A" * 86,
            )
            signature = (
                base64.urlsafe_b64encode(lab.key.sign(canonical_signal(signal)))
                .decode()
                .rstrip("=")
            )
            signal = signal.model_copy(update={"signature": signature})
            lab.service.evaluate_signed(
                signal, Principal("local-operator", tenant, frozenset({Role.ADMIN}), "api_key")
            )
            prepared.append(
                (signal, {"Authorization": "Bearer " + authority.issue(tenant_id=tenant)})
            )
        journal = lab.service.journal_status()
        gate, saturated, entered = asyncio.Event(), asyncio.Event(), asyncio.Event()
        all_admitted = asyncio.Event()

        class ObservedCapacity(asyncio.Semaphore):
            arrivals = 0

            async def acquire(self):
                self.arrivals += 1
                if self.arrivals == 32:
                    all_admitted.set()
                return await super().acquire()

        active = peak = attempts = 0
        seen_tenants = set()

        async def provider(request):
            nonlocal active, peak, attempts
            data = json.loads(request.content)
            catalog = json.loads(data["input"][1]["content"])["evidence_catalog"]
            tenant = catalog["verified_session.tenant_id"]
            seen_tenants.add(tenant)
            active += 1
            attempts += 1
            peak = max(peak, active)
            entered.set()
            if active == 4:
                saturated.set()
            try:
                await gate.wait()
                assessment = SecurityAssessment(
                    risk_score=0,
                    risk_level="LOW",
                    violation_type="NORMAL",
                    rationale="Mock transport bound to " + tenant,
                    recommended_action="HOLD_FOR_REVIEW",
                    confidence=0.8,
                    evidence=["verified_session.tenant_id"],
                    requires_human_review=True,
                )
                return httpx.Response(200, json=envelope(assessment.model_dump_json()))
            finally:
                active -= 1

        provider_client = AsyncOpenAI(
            api_key="mock-provider-not-a-real-key",
            base_url="https://mock-provider.invalid/v1",
            max_retries=0,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(provider)),
        )
        agent = EvidenceReviewAgent(config, client=provider_client)
        audit_path = tmp_path / "audit.jsonl"
        audit = AuditStore(audit_path)
        for name, value in {
            "settings": config,
            "get_settings": lambda: config,
            "zero_trust_operations": lab.service,
            "analysis_capacity": ObservedCapacity(4),
            "get_evidence_agent": lambda: agent,
            "audit_store": audit,
        }.items():
            monkeypatch.setattr(main, name, value)
        monkeypatch.setattr(security, "get_settings", lambda: config)
        assert security.get_principal not in main.app.dependency_overrides
        bodies = []
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
            ) as client:
                warm = await client.get("/auth/me", headers=prepared[0][1])
                assert warm.status_code == 200 and attempts == 0

                async def post(pair):
                    signal, headers = pair
                    return await client.post(
                        "/analysis/evidence-review",
                        json=signal.model_dump(mode="json"),
                        headers=headers,
                    )

                tasks = [asyncio.create_task(post(pair)) for pair in prepared[:32]]
                await asyncio.wait_for(saturated.wait(), timeout=10)
                await asyncio.wait_for(all_admitted.wait(), timeout=10)
                await asyncio.sleep(0.08)  # All queued requests can reach the .02s limit.
                gate.set()
                responses = await asyncio.gather(*tasks)
                assert sum(r.status_code == 200 for r in responses) == 4
                assert sum(r.status_code == 429 for r in responses) == 28
                assert attempts == peak == 4 and active == 0
                for pair, response in zip(prepared[:32], responses, strict=True):
                    if response.status_code == 429:
                        assert response.headers["retry-after"] == "1"
                        assert audit.get(pair[0].event.event_id, pair[0].tenant_id) is None
                        response = await post(pair)
                    assert response.status_code == 200
                    body = response.json()
                    assert body["verification_context"]["tenant_id"] == pair[0].tenant_id
                    assert body["assessment"]["rationale"].endswith(pair[0].tenant_id)
                    bodies.append(body)
                assert attempts == 32 and main.analysis_capacity._value == 4

                # A disconnected client must not keep a capacity slot or create success audit.
                gate.clear()
                entered.clear()
                cancelled = asyncio.create_task(post(prepared[-1]))
                await asyncio.wait_for(entered.wait(), timeout=10)
                cancelled.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await cancelled
                assert active == 0 and main.analysis_capacity._value == 4
                signal, _ = prepared[-1]
                assert audit.get(signal.event.event_id, signal.tenant_id) is None
                gate.set()
                recovered = await post(prepared[-1])
                assert recovered.status_code == 200
                bodies.append(recovered.json())
        finally:
            gate.set()
            await agent.close()
        assert attempts == 34 and peak == 4 and active == 0
        assert seen_tenants == {"burst-tenant-0", "burst-tenant-1"}
        assert authority.fetches >= 1
        assert lab.service.journal_status() == journal
        restored = AuditStore(audit_path)
        assert restored.integrity()["ok"] and restored.integrity()["verified_lines"] == 33
        for body in bodies:
            tenant = body["tenant_id"]
            other = "burst-tenant-1" if tenant == "burst-tenant-0" else "burst-tenant-0"
            assert restored.get(body["event_id"], tenant) is not None
            assert restored.get(body["event_id"], other) is None
            assert body["llm_trace"]["provider_calls"] == 1
            assert body["assessment"]["requires_human_review"] is True
        assert "mock-provider-not-a-real-key" not in audit_path.read_text(encoding="utf-8")

    try:
        with LocalOIDCAuthority() as authority:
            asyncio.run(run(authority))
    finally:
        security._jwks_client.cache_clear()
