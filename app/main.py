import asyncio
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from time import perf_counter
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from mangum import Mangum
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.analyzers import HybridAnalyzer, OpenAIAnalyzer, RuleBasedAnalyzer
from app.analyzers.base import Analyzer
from app.config import get_settings
from app.middleware import RequestBodyLimitMiddleware, RequestContextMiddleware
from app.models import (
    AnalysisResult,
    AssuranceSummary,
    BatchAnalysisRequest,
    BatchAnalysisResult,
    ControlRecord,
    ControlStatus,
    DetectionPipelineResult,
    EvaluationRequest,
    EvaluationSummary,
    EventScenarioEvaluation,
    MetricsSummary,
    NormalizedSecurityEvent,
    PolicyDecision,
    ResponsePreviewRequest,
    ReviewStatus,
    ReviewUpdateRequest,
    RiskLevel,
    ScenarioSummary,
    SecurityEvent,
    SigmaRuleSummary,
    SimulationRequest,
)
from app.scenarios import SCENARIOS, generate_events, get_scenario
from app.security import Principal, Role, require_roles
from app.services.assurance import get_assurance_registry
from app.services.audit import create_audit_store
from app.services.evaluation import run_evaluation
from app.services.ocsf import get_ocsf_normalizer
from app.services.policy import enforce_assessment_safety, response_preview
from app.services.scenario_evaluator import evaluate_scenarios
from app.services.sigma import get_sigma_engine

settings = get_settings()
static_dir = Path(__file__).parent / "static"
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="합성 이벤트 기반 제로 트러스트 위험 분석 및 대응 시뮬레이션 API",
    docs_url=None if settings.app_environment == "production" else "/docs",
    redoc_url=None if settings.app_environment == "production" else "/redoc",
    openapi_url=None if settings.app_environment == "production" else "/openapi.json",
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_host_list)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=settings.api_max_body_bytes)
app.add_middleware(RequestContextMiddleware)
app.mount("/static", StaticFiles(directory=static_dir), name="static")
audit_store = create_audit_store(settings)
assurance_registry = get_assurance_registry()
ocsf_normalizer = get_ocsf_normalizer()
sigma_engine = get_sigma_engine()
analysis_capacity = asyncio.Semaphore(settings.analysis_max_concurrency)

ViewerPrincipal = Annotated[Principal, Depends(require_roles(Role.VIEWER))]
AnalystPrincipal = Annotated[Principal, Depends(require_roles(Role.ANALYST))]
ResponderPrincipal = Annotated[Principal, Depends(require_roles(Role.RESPONDER))]
AdminPrincipal = Annotated[Principal, Depends(require_roles(Role.ADMIN))]


class AnalysisCapacityExceeded(RuntimeError):
    pass


@lru_cache
def get_analyzer() -> Analyzer:
    current = get_settings()
    return build_analyzer(current.analyzer_mode)


def build_analyzer(mode: str) -> Analyzer:
    if mode == "openai":
        return OpenAIAnalyzer(get_settings())
    if mode == "hybrid":
        return HybridAnalyzer(get_settings())
    return RuleBasedAnalyzer()


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "version": settings.app_version,
        "analyzer_mode": settings.analyzer_mode,
        "audit_backend": settings.audit_backend,
        "auth_mode": settings.auth_mode,
        "environment": settings.app_environment,
    }


@app.get("/health/live")
def liveness() -> dict:
    return {"status": "ok"}


@app.get("/health/ready")
def readiness() -> Response:
    integrity = audit_store.integrity()
    assurance = assurance_registry.summary()
    ready = integrity["ok"] and assurance.valid and sigma_engine.valid
    payload = {
        "status": "ready" if ready else "degraded",
        "audit": integrity,
        "assurance": {
            "valid": assurance.valid,
            "registry_version": assurance.registry_version,
            "registry_digest_sha256": assurance.registry_digest_sha256,
            "total_controls": assurance.total_controls,
            "overdue_control_count": len(assurance.overdue_control_ids),
        },
        "normalization": {
            "valid": True,
            "schema": "OCSF",
            "schema_version": ocsf_normalizer.schema_version,
            "transformer_version": ocsf_normalizer.transformer_version,
            "mapping_digest_sha256": ocsf_normalizer.mapping_digest_sha256,
        },
        "detection": {
            "valid": sigma_engine.valid,
            "specification": "Sigma",
            "specification_version": "2.1.0",
            "loaded_rule_count": len(sigma_engine.summaries()),
            "approved_rule_count": len(sigma_engine.approved_rules),
            "ruleset_digest_sha256": sigma_engine.ruleset_digest_sha256,
            "validation_issue_count": len(sigma_engine.validation_issues),
        },
    }
    return JSONResponse(payload, status_code=200 if ready else 503)


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/scenarios", response_model=list[ScenarioSummary])
def scenarios(_: ViewerPrincipal) -> list[ScenarioSummary]:
    return SCENARIOS


@app.get("/scenarios/{scenario_id}", response_model=ScenarioSummary)
def scenario(scenario_id: str, _: ViewerPrincipal) -> ScenarioSummary:
    try:
        return get_scenario(scenario_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown scenario: {exc.args[0]}") from exc


@app.post("/events/simulate", response_model=list[SecurityEvent])
def simulate(request: SimulationRequest, _: AnalystPrincipal) -> list[SecurityEvent]:
    try:
        return generate_events(request.scenario_id, request.count)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown scenario: {exc.args[0]}") from exc


@app.post("/events/normalize", response_model=NormalizedSecurityEvent)
def normalize_event(event: SecurityEvent, _: AnalystPrincipal) -> NormalizedSecurityEvent:
    return ocsf_normalizer.normalize(event)


@app.post("/detections/evaluate", response_model=DetectionPipelineResult)
def evaluate_detections(event: SecurityEvent, _: AnalystPrincipal) -> DetectionPipelineResult:
    normalized = ocsf_normalizer.normalize(event)
    return DetectionPipelineResult(
        normalized=normalized,
        detection=sigma_engine.evaluate(normalized),
    )


@app.get("/detections/rules", response_model=list[SigmaRuleSummary])
def detection_rules(_: ViewerPrincipal) -> list[SigmaRuleSummary]:
    return sigma_engine.summaries()


@app.post("/scenarios/evaluate", response_model=EventScenarioEvaluation)
def evaluate_event_scenarios(
    event: SecurityEvent,
    _: AnalystPrincipal,
) -> EventScenarioEvaluation:
    return evaluate_scenarios(event, SCENARIOS)


@app.post("/analysis", response_model=AnalysisResult)
async def analyze(
    event: SecurityEvent,
    request: Request,
    principal: AnalystPrincipal,
) -> AnalysisResult:
    try:
        analyzer = get_analyzer()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        return await _analyze_event(event, analyzer, principal, request.state.request_id)
    except AnalysisCapacityExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail="Analysis capacity is temporarily exhausted",
            headers={"Retry-After": "1"},
        ) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Analysis provider failed") from exc


@app.post("/analysis/batch", response_model=BatchAnalysisResult)
async def analyze_batch(
    batch_request: BatchAnalysisRequest,
    request: Request,
    principal: AnalystPrincipal,
) -> BatchAnalysisResult:
    try:
        analyzer = get_analyzer()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    semaphore = asyncio.Semaphore(3)

    async def analyze_with_limit(event: SecurityEvent) -> AnalysisResult:
        async with semaphore:
            return await _analyze_event(event, analyzer, principal, request.state.request_id)

    try:
        results = await asyncio.gather(
            *(analyze_with_limit(event) for event in batch_request.events)
        )
    except AnalysisCapacityExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail="Analysis capacity is temporarily exhausted",
            headers={"Retry-After": "1"},
        ) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Batch analysis provider failed") from exc
    return BatchAnalysisResult(
        analyzer=analyzer.name,
        requested=len(batch_request.events),
        completed=len(results),
        results=results,
    )


async def _analyze_event(
    event: SecurityEvent,
    analyzer: Analyzer,
    principal: Principal,
    request_id: str,
) -> AnalysisResult:
    try:
        await asyncio.wait_for(
            analysis_capacity.acquire(),
            timeout=settings.analysis_queue_timeout_seconds,
        )
    except TimeoutError as exc:
        raise AnalysisCapacityExceeded from exc
    try:
        started = perf_counter()
        normalized = ocsf_normalizer.normalize(event)
        detection = sigma_engine.evaluate(normalized)
        assessment = await analyzer.analyze(event)
        safe_assessment = enforce_assessment_safety(assessment, event)
        decision = response_preview(safe_assessment, event)
        result = AnalysisResult(
            event_id=event.event_id,
            analyzer=analyzer.name,
            assessment=safe_assessment,
            policy_decision=decision,
            normalized_event=normalized,
            detection=detection,
            latency_ms=round((perf_counter() - started) * 1000, 2),
            tenant_id=principal.tenant_id,
            actor_id=principal.subject,
            request_id=request_id,
        )
        await audit_store.save(result)
        return result
    finally:
        analysis_capacity.release()


@app.post("/response/preview", response_model=PolicyDecision)
def preview(request: ResponsePreviewRequest, _: AnalystPrincipal) -> PolicyDecision:
    return response_preview(request.assessment, request.event)


@app.post("/evaluation/run", response_model=EvaluationSummary)
async def evaluate(request: EvaluationRequest, _: AdminPrincipal) -> EvaluationSummary:
    try:
        analyzer = build_analyzer(request.analyzer)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return await run_evaluation(analyzer, request.runs_per_scenario, request.concurrency)


@app.get("/metrics", response_model=MetricsSummary)
def metrics(principal: ViewerPrincipal) -> MetricsSummary:
    return audit_store.metrics(principal.tenant_id)


@app.get("/internal/metrics", include_in_schema=False)
def prometheus_metrics(_: AdminPrincipal) -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/assurance/summary", response_model=AssuranceSummary)
def assurance_summary(_: ViewerPrincipal) -> AssuranceSummary:
    return assurance_registry.summary()


@app.get("/assurance/controls", response_model=list[ControlRecord])
def assurance_controls(
    _: AdminPrincipal,
    status: ControlStatus | None = None,
    domain: str | None = None,
) -> list[ControlRecord]:
    controls = assurance_registry.controls
    if status is not None:
        controls = [control for control in controls if control.status == status]
    if domain is not None:
        controls = [control for control in controls if control.domain == domain]
    return controls


@app.get("/assurance/controls/{control_id}", response_model=ControlRecord)
def assurance_control(control_id: str, _: AdminPrincipal) -> ControlRecord:
    try:
        return assurance_registry.get(control_id.upper())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Control not found") from exc


@app.get("/results", response_model=list[AnalysisResult])
def recent_results(
    principal: ViewerPrincipal,
    limit: int = 20,
    review_status: ReviewStatus | None = None,
    risk_level: RiskLevel | None = None,
) -> list[AnalysisResult]:
    safe_limit = min(max(limit, 1), 100)
    records = audit_store.recent(100, principal.tenant_id)
    if review_status is not None:
        records = [record for record in records if record.review_status == review_status]
    if risk_level is not None:
        records = [record for record in records if record.assessment.risk_level == risk_level]
    return records[:safe_limit]


@app.patch("/results/{event_id}/review", response_model=AnalysisResult)
async def update_review(
    event_id: str,
    request: ReviewUpdateRequest,
    principal: ResponderPrincipal,
) -> AnalysisResult:
    record = audit_store.get(event_id, principal.tenant_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Result not found")
    if record.review_status == ReviewStatus.NOT_REQUIRED:
        raise HTTPException(status_code=409, detail="This result does not require human review")

    allowed_transitions = {
        ReviewStatus.PENDING: {
            ReviewStatus.IN_REVIEW,
            ReviewStatus.RESOLVED,
            ReviewStatus.DISMISSED,
        },
        ReviewStatus.IN_REVIEW: {
            ReviewStatus.IN_REVIEW,
            ReviewStatus.RESOLVED,
            ReviewStatus.DISMISSED,
        },
        ReviewStatus.RESOLVED: {ReviewStatus.IN_REVIEW},
        ReviewStatus.DISMISSED: {ReviewStatus.IN_REVIEW},
    }
    if request.status not in allowed_transitions.get(record.review_status, set()):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot change review from {record.review_status.value} to {request.status.value}",
        )

    payload = record.model_dump()
    reviewer = request.reviewer if principal.auth_method == "disabled" else principal.subject
    if reviewer is None:
        raise HTTPException(status_code=422, detail="reviewer is required in local mode")
    payload.update(
        review_status=request.status,
        reviewer=reviewer,
        review_note=request.note,
        review_updated_at=datetime.now(UTC),
    )
    updated = AnalysisResult.model_validate(payload)
    await audit_store.save(updated)
    return updated


@app.get("/results/{event_id}", response_model=AnalysisResult)
def result(event_id: str, principal: ViewerPrincipal) -> AnalysisResult:
    record = audit_store.get(event_id, principal.tenant_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Result not found")
    return record


handler = Mangum(app, lifespan="off")
