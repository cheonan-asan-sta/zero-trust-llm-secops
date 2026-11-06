"""Synthetic multi-store recovery fixture using the actual repository services."""

import asyncio
from datetime import UTC, datetime, timedelta

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.models import (
    AnalysisResult,
    DetectionPipelineResult,
    IncidentCaseStatus,
    IncidentCaseUpdateRequest,
    IntegrationDeliveryUpdateRequest,
)
from app.scenarios import synthetic_events
from app.services.audit import AuditStore
from app.services.cases import CaseStore, IncidentCaseService
from app.services.correlation import get_correlation_engine
from app.services.integration_outbox import IntegrationOutboxService, IntegrationOutboxStore
from app.services.ocsf import get_ocsf_normalizer
from app.services.policy import response_preview
from app.services.sigma import get_sigma_engine
from scripts.app_state_recovery import atomic, canonical, local_only
from scripts.app_storage_contract import CONTRACT, FILES, inspect


def seed_logs(directory):
    local_only()
    atomic(directory / "storage.json", canonical(CONTRACT))
    for name in FILES.values():
        atomic(directory / name, b"")
    asyncio.run(_populate(directory))
    return inspect(directory)


async def _populate(directory):
    audit = AuditStore(directory / FILES["audit"])
    cases = CaseStore(directory / FILES["cases"])
    outbox = IntegrationOutboxService(IntegrationOutboxStore(directory / FILES["outbox"]))
    service = IncidentCaseService(cases, outbox)
    for tenant in ("recovery-tenant", "unrelated-tenant"):
        event = synthetic_events()[1]
        assessment = await RuleBasedAnalyzer().analyze(event)
        await audit.save(AnalysisResult(event_id=event.event_id, tenant_id=tenant, analyzer="rule",
            assessment=assessment, policy_decision=response_preview(assessment, event), latency_ms=1))
        pipelines = []
        for event in synthetic_events():
            if not event.ground_truth.scenario_id.startswith("ZT-"):
                continue
            normalized = get_ocsf_normalizer().normalize(event)
            pipelines.append(DetectionPipelineResult(normalized=normalized,
                detection=get_sigma_engine().evaluate(normalized)))
        correlation = get_correlation_engine().correlate(pipelines, tenant)
        created, _, _ = await service.create_from_correlation(correlation, tenant, "fixture", "Recovery fixture")
        case = created[0]
        for status in (IncidentCaseStatus.TRIAGED, IncidentCaseStatus.INVESTIGATING, IncidentCaseStatus.CONTAINED):
            case = await service.transition(case.case_id, tenant, "fixture", IncidentCaseUpdateRequest(
                expected_version=case.version, status=status, note="Recovery transition"))
        rows = sorted(outbox.store.recent(100, tenant), key=lambda row: row.event.data.case_version)
        for row, outcome in zip(rows, ("delivered", "retryable_failure", "permanent_failure"), strict=False):
            await outbox.record_attempt(row.event.id, tenant, "fixture", IntegrationDeliveryUpdateRequest(
                expected_version=1, outcome=outcome, note="Synthetic delivery outcome",
                error_code="SYNTHETIC_FAILURE" if outcome != "delivered" else None),
                now=datetime.now(UTC) + timedelta(seconds=1))
